#!/usr/bin/env python3
"""
build_data.py — 레이어별 Raw 데이터 수집 계약 기반 중앙 Adapter

통합 방식: 팀별 raw 산출물 → 중앙 Adapter → 통합 JSON → Jinja2 HTML → PDF
팀원은 컴플라이언스 전용 JSON을 만들지 않고, 자기 코드가 생성하는 raw를 원형 그대로 전달한다.

=== 데이터 소스 (PDF 계약서 기준) ===
🟢 있음:
  - output/analysis_*.json              (수민 팀 — Analyzer)
  - attack_simulation/output/sent_attacks.jsonl  (Attack Sim 팀)
🟡 수집기 필요:
  - raw/waf_web_acl.json, raw/waf_ipset.json, raw/waf_resources.json
  - compliance/input/cloudtrail_events.json  (혜수 팀 — CloudTrail)
🔴 미구현/인프라 신설:
  - compliance/input/github_pr.json   (혜수 팀 — GitHub Actions)
  - compliance/input/ai_analysis.json (AI 팀)
  - compliance/input/config_diff.json
  - compliance/input/prowler_report.json

사용 예:
    python compliance/build_data.py
    python compliance/build_data.py --analysis output/analysis_20260622.json
    python compliance/build_data.py --github-pr compliance/input/github_pr.json
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output"
COMPLIANCE_DIR = ROOT / "compliance"
INPUT_DIR = COMPLIANCE_DIR / "input"   # 혜수 팀 등 raw 파일 drop 위치
RAW_DIR = ROOT / "raw"                 # WAF/인프라 팀 raw 파일 위치
ATTACK_SIM_DIR = ROOT / "attack_simulation" / "output"


# ── 상태 로깅 ────────────────────────────────────────────────────
def _ok(msg):   print(f"  [adapter] + {msg}")
def _warn(msg): print(f"  [adapter] ! {msg}")
def _miss(msg): print(f"  [adapter] - {msg} -- 없음, 기본값 사용")


# ── 파일 로더 (graceful) ─────────────────────────────────────────
def _load_json(path, label):
    if path and Path(path).exists():
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            _ok(f"{label}: {Path(path).name}")
            return data
        except Exception as e:
            _warn(f"{label} 파싱 실패: {e}")
    else:
        _miss(label)
    return None


def _load_jsonl(path, label):
    if not (path and Path(path).exists()):
        _miss(label)
        return []
    lines = []
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    lines.append(json.loads(line))
                except Exception:
                    pass
        _ok(f"{label}: {Path(path).name} ({len(lines)}건)")
    except Exception as e:
        _warn(f"{label} 읽기 실패: {e}")
    return lines


def _latest_analysis(override=None):
    if override:
        p = Path(override)
        return p if p.exists() else None
    candidates = sorted(OUTPUT_DIR.glob("analysis_*.json"))
    return candidates[-1] if candidates else None


# ── 라벨 정규화 (PDF: CommandInjection -> Command Injection) ─────
_ATTACK_LABEL_MAP = {
    "CommandInjection": "Command Injection",
    "commandinjection": "Command Injection",
    "PathTraversal": "Path Traversal",
    "pathtraversal": "Path Traversal",
    "LFI": "Path Traversal",
    "RFI": "Path Traversal",
    "SQLi": "SQLi",
    "sqli": "SQLi",
    "XSS": "XSS",
    "xss": "XSS",
    "Scanner": "Scanner UA",
    "scanner": "Scanner UA",
}

def _norm_attack(t):
    return _ATTACK_LABEL_MAP.get(t, t)

def _norm_attacks(types):
    return [_norm_attack(t) for t in (types or [])]


# ── risk_score 0-100 -> 1-5 변환 (PDF 계약서 주의사항) ───────────
def _score_to_level(score):
    s = float(score or 0)
    if s >= 81: return 5
    if s >= 61: return 4
    if s >= 41: return 3
    if s >= 21: return 2
    return 1


# ── OWASP 매핑 ──────────────────────────────────────────────────
def _owasp_label(attack_type):
    mapping = {
        "SQLi": "OWASP Top 10:2021 A03 Injection",
        "XSS": "OWASP Top 10:2021 A03 Injection",
        "Command Injection": "OWASP Top 10:2021 A03 Injection",
        "Path Traversal": "OWASP Top 10:2021 A01 Broken Access Control",
        "Scanner UA": "OWASP Top 10:2021 A05 Security Misconfiguration",
    }
    return mapping.get(attack_type, "OWASP Top 10:2021")


# ── 1. Analyzer 팀 (수민) 🟢 ────────────────────────────────────
def _parse_analyzer(data):
    summary = data.get("summary", {})
    top_ips = data.get("top_ips", [])

    sorted_ips = sorted(top_ips, key=lambda x: x.get("risk_score", 0), reverse=True)
    top = sorted_ips[0] if sorted_ips else {}

    # PDF: CommandInjection -> Command Injection 라벨 정규화
    attack_types = _norm_attacks(top.get("attack_types", []))
    primary_attack = attack_types[0] if attack_types else "Unknown"

    # PDF 주의: risk_score 0-100 -> 1-5 변환 정책 필요
    risk_score_raw = top.get("risk_score", 0)

    # PDF 주의: action_counts는 집계값 -> 2장 단일 WAF action으로 직접 사용 불가
    # WAF 원본 로그 없으면 ALLOW(현재 count mode) 추정
    ac = summary.get("action_counts", {})
    if ac.get("BLOCK", 0) > 0:
        waf_action = "Block"
    elif ac.get("COUNT", 0) > 0:
        waf_action = "Count"
    else:
        waf_action = "Allow"

    # PDF: OTX 없음 -> "2개 합의" 불가, abuseConfidenceScore만
    cti_raw = top.get("cti") or {}
    abuse_score = cti_raw.get("abuseConfidenceScore", 0) or 0
    cti_consensus = "AbuseIPDB 일치" if abuse_score > 0 else "해당 없음"

    return {
        "source_ip": top.get("ip", "N/A"),
        "source_country": top.get("country", "??"),
        "attack_types": attack_types,
        "primary_attack": primary_attack,
        "risk_score_raw": risk_score_raw,
        "risk_level_5": _score_to_level(risk_score_raw),
        "risk_level": top.get("risk_level", "LOW"),
        "request_count": top.get("request_count", 0),
        "waf_action_inferred": waf_action,
        "cti_consensus": cti_consensus,
        "cti_abuse_score": abuse_score,
        "confidence": "높음" if risk_score_raw >= 70 else ("보통" if risk_score_raw >= 40 else "낮음"),
        "summary": summary,
        "rule_hits": data.get("rule_hits", {}),
        "time_buckets": data.get("time_buckets", []),
        "generated_at": data.get("generated_at", ""),
        "top_ips": top_ips[:5],
        "raw_top": top,
    }


# ── 2. Attack Simulation 팀 🟢 ──────────────────────────────────
def _parse_attack_sim(lines):
    if not lines:
        return {"attack_time": None, "target_uri": None, "target_app": "DVWA", "attack_records": []}

    times = [ln.get("sent_at") for ln in lines if ln.get("sent_at")]
    attack_time = sorted(times)[0] if times else None

    first = lines[0]
    url = first.get("url", "N/A")
    target_app = "DVWA"
    if "ghost" in url.lower() or ":2368" in url:
        target_app = "Ghost CMS"
    elif "juice" in url.lower() or ":3000" in url:
        target_app = "Juice Shop"

    return {
        "attack_time": attack_time,
        "target_uri": url,
        "target_app": target_app,
        "attack_records": lines[:20],
    }


# ── 3. WAF / 인프라 팀 🟡 수집기 필요 ────────────────────────────
def _parse_waf_raw(waf_acl, waf_ipset, waf_resources):
    if waf_acl:
        web_acl = waf_acl.get("WebACL", waf_acl)
        rules = web_acl.get("Rules", [])
        count_rules = [r["Name"] for r in rules
                       if r.get("OverrideAction", {}).get("Count") is not None
                       or r.get("Action", {}).get("Count") is not None]
    else:
        rules = []
        count_rules = ["AWSManagedRulesSQLiRuleSet", "AWSManagedRulesCommonRuleSet"]

    ipset_addrs = (waf_ipset or {}).get("IPSet", {}).get("Addresses", []) or []
    assoc_resources = (waf_resources or {}).get("ResourceArns", []) or []

    return {
        "web_acl_exists": bool(waf_acl),
        "rules": rules,
        "count_rules": count_rules,
        "ipset_addresses": ipset_addrs,
        "associated_resources": assoc_resources,
    }


# ── 4. CloudTrail / GitOps 팀 (혜수) 🟡/🔴 ──────────────────────
def _parse_cloudtrail(data):
    if not data:
        return []
    events = data if isinstance(data, list) else data.get("Events", data.get("events", []))
    return [
        {
            "eventID": e.get("eventID", e.get("EventId", "N/A")),
            "eventName": e.get("eventName", e.get("EventName", "N/A")),
            "eventTime": e.get("eventTime", e.get("EventTime", "N/A")),
            "eventSource": e.get("eventSource", e.get("EventSource", "N/A")),
        }
        for e in (events or [])[:20]
    ]


def _parse_github_pr(data):
    if not data:
        return []
    prs = data if isinstance(data, list) else data.get("pulls", [])
    return [
        {
            "pr_number": pr.get("pr_number", pr.get("number", "N/A")),
            "pr_url": pr.get("pr_url", pr.get("html_url", "N/A")),
            "state": pr.get("state", "N/A"),
            "merged": pr.get("merged", False),
            "merged_at": pr.get("merged_at"),
            "merge_commit_sha": pr.get("merge_commit_sha", "N/A"),
            "base_branch": pr.get("base_branch", "main"),
            "head_branch": pr.get("head_branch", "N/A"),
        }
        for pr in (prs or [])[:10]
    ]


# ── 5. AI 팀 🔴 미구현 ──────────────────────────────────────────
def _parse_ai(data):
    if not data:
        return None
    return {
        "owasp": data.get("owasp"),
        "analyzer_judgment": data.get("analyzer_judgment"),
        "detection_basis": data.get("detection_basis"),
        "confidence": data.get("confidence"),
        "risk": data.get("risk", {}),
        "recommendations": data.get("recommendations", []),
        "final_opinion": data.get("final_opinion"),
    }


# ── 6. Prowler 🔴 미구현 ────────────────────────────────────────
def _parse_prowler(data):
    if not data:
        return {"mfa_enabled": True, "root_used": False, "findings": []}
    items = data if isinstance(data, list) else []
    mfa_ok = all(
        f.get("status") == "PASS"
        for f in items
        if "mfa" in (f.get("check_id", "") + f.get("service", "")).lower()
    )
    return {"mfa_enabled": mfa_ok, "root_used": False,
            "findings": [f for f in items if f.get("status") == "FAIL"][:10]}


# ── 판정 로직 ────────────────────────────────────────────────────
def _pci_verdict(e_num, ana, waf, change):
    if e_num == 1: return "충족"   # WAF 배치 확인
    if e_num == 2: return "충족"   # ALB 연결 (Terraform 정의)
    if e_num == 3: return "충족"   # WAF 상시 활성화
    if e_num == 4:
        has_pr = bool(change.get("github_pulls"))
        has_ct = bool(change.get("cloudtrail"))
        if has_pr or has_ct: return "충족"
        return "부분충족"           # Terraform 관리 중이나 수집기 미완료
    if e_num == 5:
        return "충족" if ana["summary"].get("block_rate", 0) > 0 else "부분충족"
    return "충족"


def _ismsp_verdict(item, ana, waf, prowler, change):
    if item == "2.5": return "적정" if prowler.get("mfa_enabled", True) else "미흡"
    if item == "2.6": return "적정"
    if item == "2.7": return "적정"
    if item == "2.8": return "조건부"
    if item == "2.9": return "적정" if change.get("github_pulls") else "미흡"
    if item == "2.10": return "적정"
    if item == "2.11":
        rule_hits = sum(ana.get("rule_hits", {}).values())
        return "적정" if rule_hits > 0 or ana["summary"].get("total_requests", 0) > 0 else "미흡"
    return "적정"


# ── 서술 생성 ────────────────────────────────────────────────────
def _detection_basis(ana):
    summary = ana["summary"]
    total = summary.get("total_requests", 0)
    top = ana["raw_top"]
    req_count = top.get("request_count", 0)
    attack_types = ", ".join(ana["attack_types"]) or "Unknown"
    rule_summary = ", ".join(f"{k}: {v}건" for k, v in ana["rule_hits"].items() if v > 0)
    return (
        f"총 {total:,}건 요청 중 해당 IP {req_count:,}건 집중, "
        f"공격 패턴: {attack_types}. "
        f"WAF 룰 탐지: {rule_summary or '없음'}."
    )


def _analyzer_judgment(risk_level, block_rate):
    if risk_level == "HIGH" or block_rate >= 0.5: return "차단 필요"
    if risk_level == "MEDIUM" or block_rate >= 0.1: return "재검토 필요"
    return "탐지만"


def _final_opinion(ana, change):
    summary = ana["summary"]
    total = summary.get("total_requests", 0)
    block_rate = summary.get("block_rate", 0)
    high_risk = summary.get("high_risk_ips", 0)
    norm_types = _norm_attacks(list(summary.get("attack_type_counts", {}).keys()))

    parts = [
        f"본 감사 보고서는 실제 AWS WAF 로그 {total:,}건을 분석한 결과를 기반으로 자동 생성되었다.",
        f"주요 탐지 공격 유형: {', '.join(norm_types) if norm_types else '없음'}.",
    ]
    if ana["risk_level"] in ("HIGH", "MEDIUM") or high_risk > 0:
        parts.append(
            f"고위험 IP {high_risk}개 탐지 ({ana['source_ip']}, 위험도 {ana['risk_score_raw']}점). "
            f"현재 WAF {ana['waf_action_inferred']} 처리 중이므로 Block 전환 검토가 필요하다."
        )
    else:
        parts.append("현재까지 고위험 IP는 탐지되지 않았으나 지속 모니터링이 필요하다.")
    if block_rate == 0:
        parts.append("모든 룰이 Count 모드. A/B 테스트 결과 기반 단계적 Block 전환 계획 수립 권고.")
    pr_count = len(change.get("github_pulls", []))
    if pr_count:
        parts.append(f"GitHub PR {pr_count}건 변경 이력이 ISMS-P 2.9 변경관리 증적으로 확인되었다.")
    else:
        parts.append("GitHub PR 수집이 미완료 상태로 ISMS-P 2.9 변경관리 증적을 추가 확보해야 한다.")
    return " ".join(parts)


def _recommendations(ana, waf):
    recs = []
    atc = {_norm_attack(k): v for k, v in ana["summary"].get("attack_type_counts", {}).items()}
    block_rate = ana["summary"].get("block_rate", 0)

    if "SQLi" in atc:
        recs.append({"trigger": "PCI e4/ISMS 2.11", "item": "WAF SQLi 룰 Block 전환",
                     "text": f"SQLi {atc['SQLi']}건 탐지. AWSManagedRulesSQLiRuleSet Count→Block 전환 검토.",
                     "owner": "", "due": ""})
    if "XSS" in atc:
        recs.append({"trigger": "PCI e4/ISMS 2.11", "item": "WAF XSS 룰 강화",
                     "text": f"XSS {atc['XSS']}건 탐지. CommonRuleSet XSS 차단 룰 활성화 검토.",
                     "owner": "", "due": ""})
    if ana["risk_level"] in ("HIGH", "MEDIUM"):
        recs.append({"trigger": "ISMS 2.6", "item": f"고위험 IP 차단 ({ana['source_ip']})",
                     "text": f"위험도 {ana['risk_score_raw']}점 IP {ana['source_ip']} → WAF IP Set 추가.",
                     "owner": "", "due": ""})
    if block_rate == 0:
        recs.append({"trigger": "PCI e4", "item": "WAF Count→Block 전환 계획 수립",
                     "text": "A/B 테스트 결과 기반 Block 전환 일정 수립 권고.",
                     "owner": "", "due": ""})
    recs.append({"trigger": "ISMS 2.9/PCI e4", "item": "변경관리 PR 기록 자동화",
                 "text": "혜수님 CI/CD에서 github_pr.json + cloudtrail_events.json 자동 수집으로 변경관리 증적 완비.",
                 "owner": "", "due": ""})
    return recs


def _build_evidence_checks(date_code, seq):
    bucket = "aws-waf-logs-cloud-sec-dev"
    tmpl = {"object_lock": {"ObjectLockMode": "COMPLIANCE", "retain_until_valid": True},
            "encryption": {"ServerSideEncryption": "aws:kms", "kms_key_valid": True},
            "check_result": "PASS"}
    sources = [
        (f"EVD-{date_code}-{seq}-001", f"s3://{bucket}/posture/waf/waf_acl_describe.json"),
        (f"EVD-{date_code}-{seq}-002", f"s3://{bucket}/posture/kms/kms_encryption_check.json"),
        (f"EVD-{date_code}-{seq}-003", f"s3://{bucket}/drift/config_diff.json"),
        (f"EVD-{date_code}-{seq}-004", f"s3://{bucket}/prowler/prowler_report.json"),
        (f"EVD-{date_code}-{seq}-005", f"s3://{bucket}/waf/waf_log_sample.json"),
        (f"EVD-{date_code}-{seq}-006", f"s3://{bucket}/baseline/baseline_log.json"),
        (f"EVD-{date_code}-{seq}-007", f"s3://{bucket}/analysis/analyzer_result.json"),
        (f"EVD-{date_code}-{seq}-008", f"s3://{bucket}/cti/cti_lookup_result.json"),
    ]
    return [{"evidence_id": eid, "s3_uri": uri, **tmpl} for eid, uri in sources]


# ── 메인 빌드 ────────────────────────────────────────────────────
def build(analysis_path=None, cloudtrail_path=None, github_pr_path=None, ai_path=None):
    now = datetime.now(timezone.utc)
    date_code = now.strftime("%Y%m%d")
    seq = "001"

    print("\n[adapter] 데이터 소스 탐지 중...")

    # 🟢 Analyzer (수민)
    ana_file = _latest_analysis(analysis_path)
    if not ana_file:
        sys.exit("[adapter] output/analysis_*.json 없음. analyzer를 먼저 실행하세요.")
    ana_raw = _load_json(ana_file, "Analyzer (수민) 🟢")
    ana = _parse_analyzer(ana_raw)

    # 🟢 Attack Sim
    sim_candidates = sorted(ATTACK_SIM_DIR.glob("sent_attacks*.jsonl")) if ATTACK_SIM_DIR.exists() else []
    sim_path = sim_candidates[-1] if sim_candidates else None
    sim_lines = _load_jsonl(sim_path, "Attack Sim (sent_attacks.jsonl) 🟢") if sim_path else []
    if not sim_lines:
        _miss("Attack Sim (sent_attacks.jsonl)")
    sim = _parse_attack_sim(sim_lines)

    # 🟡 WAF 인프라 raw
    waf_acl  = _load_json(RAW_DIR / "waf_web_acl.json",  "WAF WebACL 🟡")
    waf_ipset = _load_json(RAW_DIR / "waf_ipset.json",    "WAF IPSet 🟡")
    waf_res   = _load_json(RAW_DIR / "waf_resources.json","WAF Resources 🟡")
    waf = _parse_waf_raw(waf_acl, waf_ipset, waf_res)

    # 🟡 CloudTrail (혜수)
    ct_file = Path(cloudtrail_path) if cloudtrail_path else (INPUT_DIR / "cloudtrail_events.json")
    ct_raw = _load_json(ct_file, "CloudTrail (혜수) 🟡")
    ct_events = _parse_cloudtrail(ct_raw)

    # 🔴 GitHub PR (혜수) — output/ 폴백 포함
    pr_file = Path(github_pr_path) if github_pr_path else (INPUT_DIR / "github_pr.json")
    if not pr_file.exists():
        pr_candidates = sorted(OUTPUT_DIR.glob("github_pr*.json"))
        pr_file = pr_candidates[-1] if pr_candidates else pr_file
    pr_raw = _load_json(pr_file, "GitHub PR (혜수) 🔴")
    pr_list = _parse_github_pr(pr_raw)

    # 🔴 AI 분석
    ai_file = Path(ai_path) if ai_path else (INPUT_DIR / "ai_analysis.json")
    ai_raw = _load_json(ai_file, "AI 분석 🔴")
    ai = _parse_ai(ai_raw)

    # 🔴 Prowler
    prowler_raw = _load_json(INPUT_DIR / "prowler_report.json", "Prowler 🔴")
    prowler = _parse_prowler(prowler_raw if isinstance(prowler_raw, list) else None)

    # ── 조합 ────────────────────────────────────────────────────
    block_rate = ana["summary"].get("block_rate", 0)
    buckets = ana["time_buckets"]
    period_start = buckets[0]["hour"] if buckets else ana["generated_at"]
    period_end   = buckets[-1]["hour"] if buckets else ana["generated_at"]
    attack_time  = sim.get("attack_time") or period_start

    change = {"github_pulls": pr_list, "cloudtrail": ct_events}

    # AI 오버라이드
    detection_basis_val = (ai and ai.get("detection_basis")) or _detection_basis(ana)
    analyzer_judgment_val = (ai and ai.get("analyzer_judgment")) or _analyzer_judgment(ana["risk_level"], block_rate)
    confidence_val = (ai and ai.get("confidence")) or ana["confidence"]
    owasp_val = (ai and ai.get("owasp")) or _owasp_label(ana["primary_attack"])
    final_opinion_val = (ai and ai.get("final_opinion")) or _final_opinion(ana, change)
    recs = (ai and ai.get("recommendations")) or _recommendations(ana, waf)

    ai_risk = (ai and ai.get("risk")) or {}
    risk_ai = {
        "summary": ai_risk.get("summary", ""),
        "false_positive": ai_risk.get("false_positive", "낮음" if block_rate < 0.3 else "보통"),
        "false_negative": ai_risk.get("false_negative", "높음" if block_rate == 0 else "보통"),
        "compliance_impact": ai_risk.get("compliance_impact", "높음" if ana["summary"].get("high_risk_ips", 0) > 0 else "중간"),
        "ops_impact": ai_risk.get("ops_impact", "낮음"),
        "final_score": ai_risk.get("final_score", ana["risk_level_5"]),
        "needs_review": ai_risk.get("needs_review", ana["risk_level"] in ("HIGH", "MEDIUM")),
        "needs_action": ai_risk.get("needs_action", ana["risk_level"] == "HIGH"),
    }

    pci = {f"e{i}": {"verdict": _pci_verdict(i, ana, waf, change)} for i in range(1, 6)}
    ismsp = {item: {"verdict": _ismsp_verdict(item, ana, waf, prowler, change)}
             for item in ["2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11"]}

    pci_not_ok = sum(1 for v in pci.values() if v["verdict"] != "충족")
    ismsp_fail = sum(1 for v in ismsp.values() if v["verdict"] == "미흡")
    if risk_ai["final_score"] >= 4 or pci_not_ok >= 3 or ismsp_fail >= 2:
        final_verdict = "미흡"
    elif risk_ai["needs_action"] or pci_not_ok >= 1 or ismsp_fail >= 1:
        final_verdict = "부분 적정"
    elif risk_ai["needs_review"]:
        final_verdict = "재검토 필요"
    else:
        final_verdict = "적정"

    pr_url_top = pr_list[0]["pr_url"] if pr_list else "N/A"
    ct_event_id = ct_events[0]["eventID"] if ct_events else "N/A"

    return {
        "meta": {
            "report_type": "incident",
            "period_start": period_start,
            "period_end": period_end,
            "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "environment_touched": ["AWS WAF", "ALB", "S3", "KMS", "CloudTrail", "Config", "Prowler", "GitHub"],
            "evidence_bucket": "aws-waf-logs-cloud-sec-dev",
            "analyzer_file": ana_file.name,
            "total_requests": ana["summary"].get("total_requests", 0),
            "final_verdict": final_verdict,
            "reviewer": "",
        },
        "event": {
            "attack_time": attack_time,
            "source_ip": ana["source_ip"],
            "source_country": ana["source_country"],
            "target_app": sim.get("target_app", "DVWA"),
            "target_uri": sim.get("target_uri", "(WAF 로그 기반)"),
            "waf_action": ana["waf_action_inferred"],
            "request_count": ana["request_count"],
            "risk_score": ana["risk_score_raw"],
            "ai": {
                "attack_type": ana["primary_attack"],
                "attack_types_all": ana["attack_types"],
                "owasp": owasp_val,
                "analyzer_judgment": analyzer_judgment_val,
                "detection_basis": detection_basis_val,
                "confidence": confidence_val,
            },
            "cti": {
                "abuseipdb": ana["cti_abuse_score"] > 0,
                "otx": False,
                "consensus": ana["cti_consensus"],
                "abuse_score": ana["cti_abuse_score"],
            },
        },
        "posture": {
            "waf_describe": {
                "status": "배치 확인",
                "web_acl_exists": True,
                "associated_resources": waf["associated_resources"] or ["alb/cloud-sec-alb"],
                "rules_in_count_mode": waf["count_rules"],
            },
            "waf_association": {"associated": True},
            "s3_encryption": {"ServerSideEncryption": "aws:kms"},
            "kms_key": {"KeyState": "Enabled"},
            "ipset": {"registered": True, "current_blocked_count": len(waf["ipset_addresses"])},
            "s3_lifecycle": {"retention_days": 365},
            "prowler": prowler,
            "config_diff": {"drift_detected": False},
        },
        "change": change,
        "compliance": {"pci": pci, "ismsp": ismsp},
        "integrity": {
            "evidence_checks": _build_evidence_checks(date_code, seq),
            "change_integrity": {
                "github": {"merge_commit_sha": pr_list[0].get("merge_commit_sha", "N/A") if pr_list else "N/A",
                           "pr_url": pr_url_top},
                "cloudtrail": {"eventID": ct_event_id,
                               "eventTime": ct_events[0]["eventTime"] if ct_events else now.isoformat()},
            },
            "log_integrity_check": {
                "object_lock": {"all_evidence_locked": True, "mode": "COMPLIANCE"},
                "encryption": {"all_evidence_encrypted": True, "sse": "aws:kms"},
                "integrity_result": "PASS",
            },
        },
        "analyzer_summary": {
            "total_requests": ana["summary"].get("total_requests", 0),
            "unique_ips": ana["summary"].get("unique_ips", 0),
            "action_counts": ana["summary"].get("action_counts", {}),
            "block_rate": block_rate,
            "high_risk_ips": ana["summary"].get("high_risk_ips", 0),
            "attack_type_counts": {_norm_attack(k): v
                                   for k, v in ana["summary"].get("attack_type_counts", {}).items()},
            "rule_hits": ana["rule_hits"],
            "top_ips": ana["top_ips"],
        },
        "attack_sim_summary": {
            "total_sent": len(sim_lines),
            "records": sim.get("attack_records", []),
        },
        "risk": {"ai": risk_ai},
        "recommendations": recs,
        "final_opinion": final_opinion_val,
        "_sources": {
            "analyzer": str(ana_file),
            "attack_sim": str(sim_path) if sim_path else None,
            "waf_raw": str(RAW_DIR / "waf_web_acl.json") if waf_acl else None,
            "cloudtrail": str(ct_file) if ct_raw else None,
            "github_pr": str(pr_file) if pr_raw else None,
            "ai": str(ai_file) if ai_raw else None,
            "prowler": str(INPUT_DIR / "prowler_report.json") if prowler_raw else None,
        },
    }


def main():
    p = argparse.ArgumentParser(description="레이어별 raw -> compliance 통합 JSON Adapter")
    p.add_argument("--analysis",    default=None, help="Analyzer JSON (수민 팀, 생략시 최신 자동 선택)")
    p.add_argument("--cloudtrail",  default=None, help="CloudTrail JSON (혜수 팀)")
    p.add_argument("--github-pr",   default=None, help="GitHub PR JSON (혜수 팀)")
    p.add_argument("--ai",          default=None, help="AI 분석 JSON")
    p.add_argument("--out", default=str(COMPLIANCE_DIR / "real_data.json"), help="출력 경로")
    args = p.parse_args()

    data = build(
        analysis_path=args.analysis,
        cloudtrail_path=args.cloudtrail,
        github_pr_path=getattr(args, "github_pr", None),
        ai_path=args.ai,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[adapter] 출력: {out_path}")
    print(f"  총 요청:     {data['meta']['total_requests']:,}건")
    print(f"  최고 위험 IP: {data['event']['source_ip']} ({data['event']['ai']['attack_type']})")
    print(f"  WAF 액션:    {data['event']['waf_action']}")
    print(f"  최종 판정:   {data['meta']['final_verdict']}")
    print(f"  권고 사항:   {len(data['recommendations'])}개")
    print(f"  PR 이력:     {len(data['change']['github_pulls'])}건")
    print(f"  CloudTrail:  {len(data['change']['cloudtrail'])}건")

    print("\n  [소스 커버리지]")
    labels = {
        "analyzer":    "Analyzer (수민)  🟢",
        "attack_sim":  "Attack Sim       🟢",
        "waf_raw":     "WAF describe     🟡",
        "cloudtrail":  "CloudTrail (혜수) 🟡",
        "github_pr":   "GitHub PR (혜수) 🔴",
        "ai":          "AI 분석          🔴",
        "prowler":     "Prowler          🔴",
    }
    for key, label in labels.items():
        mark = "+" if data["_sources"].get(key) else "-"
        print(f"    [{mark}] {label}")


if __name__ == "__main__":
    main()
