"""
waf_analyzer.py — WAF 로그 분석 핵심 모듈

기능:
  1) 로그 읽기   : 로컬 .log/.json/.gz (개발용) + S3 직접 읽기(운영용)
  2) IP 분석     : IP별 요청 수, BLOCK/ALLOW/COUNT 비율, 공격 유형 분류
  3) 위험도 계산 : 요청량 + 차단율 + 공격유형 + CTI → 0~100 점수, HIGH/MEDIUM/LOW
  4) JSON 출력   : 일환(AI 보고서) · 소연(Grafana) · 병옥(컴플라이언스)이 소비

JSON 출력 스키마(팀 공유 계약):
{
  "generated_at": "...",
  "summary": {
    "total_requests", "unique_ips",
    "action_counts": {"BLOCK","ALLOW","COUNT"},
    "block_rate",                # 일환 보고서 입력
    "high_risk_ips",             # 일환 보고서 입력
    "attack_type_counts": {...}  # 소연 패널4 / 일환
  },
  "rule_hits": {"AWSManagedRulesSQLiRuleSet": n, ...},   # 소연 패널4
  "time_buckets": [{"hour": "...", "count": n}],         # 소연 패널3(시간대별)
  "top_ips": [ {ip, country, request_count, action_counts, block_rate,
                attack_types, risk_score, risk_level, cti} ]  # 소연 패널1 / 일환
}
"""
import glob
import gzip
import json
import os
import re
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime, timezone

from config import Config

# 공격 유형 분류용 정규식 (uri + 디코딩된 args 대상)
ATTACK_PATTERNS = {
    "SQLi": re.compile(r"(union\s+select|'\s*or\s*'?\d|or\s+1=1|--|drop\s+table|information_schema)", re.I),
    "XSS": re.compile(r"(<script|onerror\s*=|onload\s*=|<svg|<img[^>]+src|javascript:)", re.I),
    "PathTraversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|\.\.%2f|\.\.\.\.//)", re.I),
    "CommandInjection": re.compile(r"(;\s*cat\s|\|\s*whoami|;\s*ls\s|`.*`|\$\(.*\))", re.I),
}
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|nuclei|dirbuster|gobuster|acunetix)", re.I)


# ----------------------------- 1) 로그 읽기 -----------------------------
def _open(path):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") \
        else open(path, "r", encoding="utf-8")


def iter_records(source_dir):
    """디렉터리 안의 모든 로그 파일에서 WAF 레코드를 하나씩 yield."""
    patterns = ["*.log", "*.json", "*.jsonl", "*.gz"]
    files = []
    for pat in patterns:
        files += glob.glob(os.path.join(source_dir, "**", pat), recursive=True)
    for path in sorted(set(files)):
        with _open(path) as f:
            content = f.read().strip()
            if not content:
                continue
            # WAF 로그는 보통 줄 단위 JSON. 혹시 JSON 배열이면 그것도 처리.
            if content.startswith("["):
                try:
                    for rec in json.loads(content):
                        yield rec
                    continue
                except json.JSONDecodeError:
                    pass
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def fetch_records_from_s3(bucket, region, prefix=""):
    """운영용: S3에서 직접 읽기. boto3 필요."""
    import boto3
    s3 = boto3.client("s3", region_name=region)
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            if obj["Key"].endswith(".gz"):
                body = gzip.decompress(body)
            for line in body.decode("utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue


# --------------------------- 2) 공격 유형 분류 ---------------------------
def _user_agent(req):
    for h in req.get("headers", []):
        if h.get("name", "").lower() == "user-agent":
            return h.get("value", "")
    return ""


def classify_attack(record):
    """레코드 1건 → 공격 유형 문자열. 룰 그룹 우선, 없으면 패턴 매칭."""
    req = record.get("httpRequest", {})
    rule_ids = " ".join(g.get("ruleGroupId", "") for g in record.get("ruleGroupList", []))
    term = record.get("terminatingRuleId", "") or ""

    if re.search(r"SQLi", rule_ids + term, re.I):
        return "SQLi"
    if re.search(r"CrossSiteScripting|XSS", rule_ids + term, re.I):
        return "XSS"
    if re.search(r"LFI|PathTraversal", rule_ids + term, re.I):
        return "PathTraversal"
    if re.search(r"RFI|Command", rule_ids + term, re.I):
        return "CommandInjection"

    # 룰로 안 잡히면 URI/args 패턴으로 판단
    decoded = urllib.parse.unquote((req.get("uri", "") + "?" + req.get("args", "")))
    for atype, pat in ATTACK_PATTERNS.items():
        if pat.search(decoded):
            return atype
    if SCANNER_UA.search(_user_agent(req)):
        return "Scanner"
    return "Other"


# --------------------- 3) 집계 + 위험도 계산 ---------------------
def compute_risk(stats, threshold=Config.IP_REQUEST_THRESHOLD, cti=None):
    """IP별 통계 → 0~100 위험 점수 + 등급."""
    volume = min(40.0, stats["request_count"] / threshold * 40.0)
    block = stats["block_rate"] * 30.0
    malicious = {"SQLi", "XSS", "PathTraversal", "CommandInjection", "Scanner"}
    attack = 20.0 if (set(stats["attack_types"]) & malicious) else 0.0
    cti_score = 0.0
    if cti and isinstance(cti.get("abuseConfidenceScore"), (int, float)):
        cti_score = cti["abuseConfidenceScore"] / 100.0 * 30.0

    score = round(min(100.0, volume + block + attack + cti_score), 1)
    level = "HIGH" if score >= Config.RISK_HIGH else "MEDIUM" if score >= Config.RISK_MEDIUM else "LOW"
    return score, level


def analyze(records, threshold=Config.IP_REQUEST_THRESHOLD):
    """레코드 이터러블 → 분석 결과 dict (JSON 직렬화 가능)."""
    action_counts = Counter()
    attack_type_counts = Counter()
    rule_hits = Counter()
    time_buckets = Counter()
    per_ip = defaultdict(lambda: {
        "country": "", "request_count": 0,
        "actions": Counter(), "attack_types": Counter(),
    })

    for rec in records:
        req = rec.get("httpRequest", {})
        ip = req.get("clientIp", "unknown")
        action = (rec.get("action") or "ALLOW").upper()
        atype = classify_attack(rec)

        action_counts[action] += 1
        if atype != "Other":
            attack_type_counts[atype] += 1
        for g in rec.get("ruleGroupList", []):
            rid = g.get("ruleGroupId", "").split("#")[-1]  # "AWS#X" → "X"
            if rid:
                rule_hits[rid] += 1
        ts = rec.get("timestamp")
        if isinstance(ts, (int, float)):
            hour = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:00")
            time_buckets[hour] += 1

        s = per_ip[ip]
        s["country"] = req.get("country", "") or s["country"]
        s["request_count"] += 1
        s["actions"][action] += 1
        if atype != "Other":
            s["attack_types"][atype] += 1

    # IP별 정리 + 위험도
    top_ips = []
    for ip, s in per_ip.items():
        blocked = s["actions"].get("BLOCK", 0)
        block_rate = round(blocked / s["request_count"], 3) if s["request_count"] else 0.0
        ip_stats = {
            "ip": ip,
            "country": s["country"],
            "request_count": s["request_count"],
            "action_counts": dict(s["actions"]),
            "block_rate": block_rate,
            "attack_types": sorted(s["attack_types"]),
        }
        score, level = compute_risk(ip_stats, threshold)
        ip_stats["risk_score"] = score
        ip_stats["risk_level"] = level
        ip_stats["cti"] = None  # main.py에서 선택적으로 채움
        top_ips.append(ip_stats)

    top_ips.sort(key=lambda x: x["risk_score"], reverse=True)
    total = sum(action_counts.values())

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_requests": total,
            "unique_ips": len(per_ip),
            "action_counts": dict(action_counts),
            "block_rate": round(action_counts.get("BLOCK", 0) / total, 3) if total else 0.0,
            "high_risk_ips": sum(1 for x in top_ips if x["risk_level"] == "HIGH"),
            "attack_type_counts": dict(attack_type_counts),
        },
        "rule_hits": dict(rule_hits),
        "time_buckets": [{"hour": h, "count": c} for h, c in sorted(time_buckets.items())],
        "top_ips": top_ips,
    }
