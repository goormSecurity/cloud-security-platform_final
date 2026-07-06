"""
analyzer JSON 결과를 Grafana용 HTTP API로 노출하는 서버
"""
from flask import Flask, jsonify
from flask_cors import CORS
import json
from pathlib import Path
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)

_HERE = Path(__file__).resolve().parent
_ROOT        = _HERE.parent
_ROOT_OUTPUT = _ROOT / "output"
_LOCAL_DATA  = _HERE / "data"
_COMPLIANCE  = _HERE / "compliance"


def _find_latest(pattern: str):
    """output/ 하위 전체(s3-results 포함) + monitoring/data/ 에서 최신 파일 반환"""
    files = []
    for base in (_ROOT_OUTPUT, _LOCAL_DATA):
        files.extend(base.rglob(pattern))
    return sorted(files)[-1] if files else None


def _load(pattern: str):
    f = _find_latest(pattern)
    if not f:
        return None
    with open(f, encoding="utf-8") as fp:
        return json.load(fp)


@app.route("/")
def index():
    return ("WAF API: /summary /top-ips /rule-hits /time-buckets /action-timeline "
            "/attack-types /action-counts /risk-distribution /ab-test /pipeline-runs "
            "/zap-stats /latest-run /security-status")


# ── 핵심 요약 ─────────────────────────────────────────────────────
@app.route("/summary")
def summary():
    data = _load("analysis_*.json")
    if not data:
        return jsonify({}), 404
    s = data.get("summary", {})
    blocked = s.get("action_counts", {}).get("BLOCK", 0)
    allowed = s.get("action_counts", {}).get("ALLOW", 0)
    total   = s.get("total_requests", 0)
    return jsonify({
        "total_requests": total,
        "unique_ips":     s.get("unique_ips", 0),
        "high_risk_ips":  s.get("high_risk_ips", 0),
        "block_rate_pct": round(s.get("block_rate", 0) * 100, 1),
        "blocked":        blocked,
        "allowed":        allowed,
        "generated_at":   data.get("generated_at", ""),
    })


# ── 시간대별 추이 ─────────────────────────────────────────────────
@app.route("/time-buckets")
def time_buckets():
    from flask import request as req
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    buckets = data.get("time_buckets", [])
    # Grafana ${__from:date:seconds} / ${__to:date:seconds} 변수 수신
    try:
        from_ts = int(req.args.get("from", 0))
        to_ts   = int(req.args.get("to",   0))
    except Exception:
        from_ts = to_ts = 0

    def _with_epoch(b):
        try:
            dt = datetime.strptime(b["hour"], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            return {"hour": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "count": b["count"]}
        except Exception:
            return b

    if from_ts or to_ts:
        from_dt = datetime.fromtimestamp(from_ts, tz=timezone.utc) if from_ts else None
        to_dt   = datetime.fromtimestamp(to_ts,   tz=timezone.utc) if to_ts   else None
        filtered = []
        for b in buckets:
            try:
                dt = datetime.strptime(b["hour"], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
                if from_dt and dt < from_dt:
                    continue
                if to_dt and dt > to_dt:
                    continue
                filtered.append(_with_epoch(b))
            except Exception:
                filtered.append(_with_epoch(b))
        return jsonify(filtered if filtered else [_with_epoch(b) for b in buckets])

    return jsonify([_with_epoch(b) for b in buckets])


# ── BLOCK/ALLOW 시간대별 (wide format: time, BLOCK, ALLOW) ──────────
@app.route("/action-timeline")
def action_timeline():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    by_action = data.get("time_buckets_by_action", {})

    merged: dict = {}
    for action, buckets in by_action.items():
        for b in buckets:
            try:
                dt = datetime.strptime(b["hour"], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
                iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                if iso not in merged:
                    merged[iso] = {"time": iso, "BLOCK": 0, "ALLOW": 0}
                merged[iso][action] = b["count"]
            except Exception:
                pass
    if merged:
        return jsonify(sorted(merged.values(), key=lambda x: x["time"]))

    # 기존 분석 파일에 time_buckets_by_action 없으면 block_rate 비율로 추정
    block_rate = data.get("summary", {}).get("block_rate", 0)
    result = []
    for b in data.get("time_buckets", []):
        try:
            dt = datetime.strptime(b["hour"], "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
            iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            block_n = round(b["count"] * block_rate)
            result.append({"time": iso, "BLOCK": block_n, "ALLOW": b["count"] - block_n})
        except Exception:
            pass
    return jsonify(sorted(result, key=lambda x: x["time"]))


# ── TOP IP ───────────────────────────────────────────────────────
@app.route("/top-ips")
def top_ips():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    return jsonify([
        {
            "ip":            e.get("ip", "?"),
            "country":       e.get("country", "?"),
            "request_count": e.get("request_count", 0),
            "risk_level":    e.get("risk_level", "UNKNOWN"),
            "risk_score":    e.get("risk_score", 0),
            "block_rate_pct": round(e.get("block_rate", 0) * 100, 1),
            "blocked":       e.get("action_counts", {}).get("BLOCK", 0),
            "attack_types":  ", ".join(e.get("attack_types", [])) or "-",
        }
        for e in data.get("top_ips", [])[:10]
    ])


# ── WAF 룰 탐지 ──────────────────────────────────────────────────
@app.route("/rule-hits")
def rule_hits():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    return jsonify(sorted(
        [{"rule": k, "count": v} for k, v in data.get("rule_hits", {}).items()],
        key=lambda x: x["count"], reverse=True
    ))


# ── 공격 유형 분포 ─────────────────────────────────────────────────
@app.route("/attack-types")
def attack_types():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    types = data.get("summary", {}).get("attack_type_counts", {})
    return jsonify(sorted(
        [{"type": k, "count": v} for k, v in types.items()],
        key=lambda x: x["count"], reverse=True
    ))


# ── ALLOW/BLOCK 비율 ───────────────────────────────────────────────
@app.route("/action-counts")
def action_counts():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    actions = data.get("summary", {}).get("action_counts", {})
    return jsonify([{"action": k, "count": v} for k, v in actions.items()])


# ── IP 위험 등급 분포 ──────────────────────────────────────────────
@app.route("/risk-distribution")
def risk_distribution():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    dist: dict = {}
    for ip in data.get("top_ips", []):
        lvl = ip.get("risk_level", "UNKNOWN")
        dist[lvl] = dist.get(lvl, 0) + 1
    return jsonify([
        {"level": l, "count": dist.get(l, 0)}
        for l in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"] if l in dist
    ])


# ── A/B 테스트 (Count 룰 → Block 전환 비교) ────────────────────────
@app.route("/ab-test")
def ab_test():
    data = _load("ab_test_*.json")
    if not data:
        return jsonify({"bars": [], "rates": []}), 404

    cur  = data.get("current_mode", {})
    prop = data.get("proposed_block_mode", {})
    cur_actions  = cur.get("actions",  {"block": 0, "count": 0, "allow": 0})
    prop_actions = prop.get("actions", {"block": 0, "count": 0, "allow": 0})
    total = data.get("total_attack_patterns", 1)

    bars = [
        {"metric": "차단(Block)", "현재_Count모드": cur_actions.get("block", 0),  "제안_Block모드": prop_actions.get("block", 0)},
        {"metric": "탐지(Count)", "현재_Count모드": cur_actions.get("count", 0),  "제안_Block모드": prop_actions.get("count", 0)},
        {"metric": "통과(Allow)", "현재_Count모드": cur_actions.get("allow", 0),  "제안_Block모드": prop_actions.get("allow", 0)},
    ]
    rates = [
        {"mode": "현재 (일부 Count)", "block_rate": cur.get("block_rate", "0%"),  "detection_rate": cur.get("detection_rate", "0%")},
        {"mode": "제안 (전체 Block)", "block_rate": prop.get("block_rate", "0%"), "detection_rate": prop.get("detection_rate", "0%")},
    ]
    return jsonify({"bars": bars, "rates": rates, "total_patterns": total})


# ── 파이프라인 실행 이력 ───────────────────────────────────────────
@app.route("/pipeline-runs")
def pipeline_runs():
    from flask import request as req
    try:
        from_ts = int(req.args.get("from", 0))
        to_ts   = int(req.args.get("to",   0))
    except Exception:
        from_ts = to_ts = 0
    from_dt = datetime.fromtimestamp(from_ts, tz=timezone.utc) if from_ts else None
    to_dt   = datetime.fromtimestamp(to_ts,   tz=timezone.utc) if to_ts   else None

    files = []
    for base in (_ROOT_OUTPUT, _LOCAL_DATA):
        files.extend(base.rglob("analysis_*.json"))

    runs = []
    for f in sorted(files, reverse=True):
        if len(runs) >= 10:
            break
        try:
            with open(f, encoding="utf-8") as fp:
                d = json.load(fp)
            gen_at = d.get("generated_at", "")
            if (from_dt or to_dt) and gen_at:
                try:
                    gen_dt = datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
                    if gen_dt.tzinfo is None:
                        gen_dt = gen_dt.replace(tzinfo=timezone.utc)
                    if from_dt and gen_dt < from_dt:
                        continue
                    if to_dt and gen_dt > to_dt:
                        continue
                except Exception:
                    pass
            s = d.get("summary", {})
            runs.append({
                "filename":       f.name,
                "generated_at":   gen_at[:16].replace("T", " "),
                "total_requests": s.get("total_requests", 0),
                "high_risk_ips":  s.get("high_risk_ips", 0),
                "blocked":        s.get("action_counts", {}).get("BLOCK", 0),
                "block_rate_pct": round(s.get("block_rate", 0) * 100, 1),
            })
        except Exception:
            pass
    return jsonify(runs)


# ── ZAP 알림 통계 ─────────────────────────────────────────────────
@app.route("/zap-stats")
def zap_stats():
    data = _load("zap_report_*.json")
    if not data:
        return jsonify({"total": 0, "high": 0, "medium": 0, "low": 0, "informational": 0})
    rc = data.get("risk_counts", {})
    return jsonify({
        "total":         data.get("total_alerts", 0),
        "high":          rc.get("High", 0),
        "medium":        rc.get("Medium", 0),
        "low":           rc.get("Low", 0),
        "informational": rc.get("Informational", 0),
    })


# ── 최근 실행 상세 결과 (발표 자료용) ──────────────────────────────
@app.route("/latest-run")
def latest_run():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404

    s       = data.get("summary", {})
    total   = s.get("total_requests", 0)
    unique  = s.get("unique_ips", 0)
    blocked = s.get("action_counts", {}).get("BLOCK", 0)
    allowed = s.get("action_counts", {}).get("ALLOW", 0)

    high_ips   = [ip["ip"] for ip in data.get("top_ips", []) if ip.get("risk_level") == "HIGH"]
    high_count = s.get("high_risk_ips", len(high_ips))
    high_ip_str = high_ips[0] if high_ips else "-"

    rule_hits = data.get("rule_hits", {})
    if rule_hits:
        top_rule = max(rule_hits, key=lambda k: rule_hits[k])
        short    = top_rule.replace("AWSManagedRules", "").replace("RuleSet", "")
        top_rule_str = f"{short} {rule_hits[top_rule]:,}건"
    else:
        top_rule_str = "-"

    github_status = "미연결 (github_repo 미설정)"
    for base in (_ROOT_OUTPUT, _LOCAL_DATA):
        for f in sorted(base.rglob("github_pr*.json"), reverse=True)[:1]:
            try:
                pr = json.loads(f.read_text(encoding="utf-8"))
                url = pr.get("pr_url") or pr.get("url") or pr.get("html_url")
                github_status = f"자동 생성 완료 ({url})" if url else "자동 생성 완료"
            except Exception:
                pass

    rows = [
        {"항목": "총 요청 (1시간)",    "값": f"{total:,}건",                          "상태": "정상"},
        {"항목": "고유 IP",            "값": f"{unique:,}개",                          "상태": "정상"},
        {"항목": "HIGH 위험 IP",       "값": f"{high_count}개  ({high_ip_str})",       "상태": "경고" if high_count > 0 else "정상"},
        {"항목": "WAF 차단 (BLOCK)",   "값": f"{blocked:,}건",                         "상태": "차단"},
        {"항목": "WAF 허용 (ALLOW)",   "값": f"{allowed:,}건",                         "상태": "정상"},
        {"항목": "WAF 룰 탐지 (상위)", "값": top_rule_str,                             "상태": "탐지"},
        {"항목": "GitHub PR",          "값": github_status,                            "상태": "완료" if "완료" in github_status else "대기"},
    ]
    return jsonify(rows)


# ── Prowler 결과에서 특정 체크 상태 조회 ─────────────────────────
def _prowler_status(check_id: str) -> str:
    """prowler_report.json 에서 check_id 결과 반환 (PASS/FAIL/UNKNOWN)"""
    for base in (_COMPLIANCE, _LOCAL_DATA):
        f = base / "prowler_report.json"
        if not f.exists():
            continue
        try:
            findings = json.loads(f.read_text(encoding="utf-8"))
            for item in findings:
                if item.get("check_id") == check_id:
                    return item.get("status", "UNKNOWN")
        except Exception:
            pass
    return "UNKNOWN"


# ── 보안 상태 요약 ─────────────────────────────────────────────────
@app.route("/security-status")
def security_status():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([{"항목": "상태", "값": "데이터 없음", "상태": "경고"}])

    s          = data.get("summary", {})
    block_rate = round(s.get("block_rate", 0) * 100, 1)
    high_ips   = [ip["ip"] for ip in data.get("top_ips", []) if ip.get("risk_level") == "HIGH"]
    # WAF 모드: waf_web_acl.json의 OverrideAction:Count 여부로 판단 (block_rate만으로 오판 방지)
    waf_mode = "Block 모드"
    waf_acl_path = _ROOT / "raw" / "waf_web_acl.json"
    if waf_acl_path.exists():
        try:
            acl = json.loads(waf_acl_path.read_text(encoding="utf-8"))
            count_rules = [r.get("Name", "?") for r in acl.get("WebACL", acl).get("Rules", [])
                           if "Count" in r.get("OverrideAction", {})]
            if count_rules:
                waf_mode = f"Count 모드 ({', '.join(count_rules)})"
            elif block_rate > 0:
                waf_mode = f"Block 모드 실제 작동 중 (차단율 {block_rate}%)"
        except Exception:
            pass
    elif block_rate > 0:
        waf_mode = f"Block 모드 실제 작동 중 (차단율 {block_rate}%)"
    updated    = data.get("generated_at", "")[:16].replace("T", " ")

    # WAF 존재 여부 (Prowler)
    waf_exists = _prowler_status("wafv2_webacl_exists")
    waf_row = {
        "항목": "WAF WebACL",
        "값":   "설정됨" if waf_exists == "PASS" else ("미설정 — Terraform apply 필요" if waf_exists == "FAIL" else "확인 불가"),
        "상태": "정상" if waf_exists == "PASS" else "경고",
    }

    # 루트 MFA (Prowler)
    root_mfa = _prowler_status("iam_root_mfa_enabled")
    mfa_row = {
        "항목": "루트 MFA",
        "값":   "활성화" if root_mfa == "PASS" else ("비활성화 — 즉시 설정 필요" if root_mfa == "FAIL" else "확인 불가"),
        "상태": "정상" if root_mfa == "PASS" else "경고",
    }

    rows = [
        waf_row,
        mfa_row,
        {"항목": "WAF 모드",     "값": waf_mode,                                        "상태": "활성"},
        {"항목": "차단률",       "값": f"{block_rate}%",                                  "상태": "정상" if block_rate < 50 else "경고"},
        {"항목": "HIGH 위험 IP", "값": ", ".join(high_ips) if high_ips else "없음",       "상태": "경고" if high_ips else "정상"},
        {"항목": "최종 업데이트","값": updated,                                            "상태": "정상"},
    ]
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
