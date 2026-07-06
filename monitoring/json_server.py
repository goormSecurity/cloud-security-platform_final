"""
analyzer JSON 결과를 Grafana용 HTTP API로 노출하는 서버
"""
from flask import Flask, jsonify
from flask_cors import CORS
import json
from pathlib import Path

app = Flask(__name__)
CORS(app)

_HERE = Path(__file__).resolve().parent
_ROOT_OUTPUT = _HERE.parent / "output"
_LOCAL_DATA  = _HERE / "data"


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
    return ("WAF API: /summary /top-ips /rule-hits /time-buckets /attack-types "
            "/action-counts /risk-distribution /ab-test /pipeline-runs "
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
    data = _load("analysis_*.json")
    if not data:
        return jsonify([]), 404
    buckets = []
    for b in data.get("time_buckets", []):
        hour = b.get("hour", "")
        # "2026-06-21 15:00" → "2026-06-21T15:00:00Z" (Infinity backend parser 호환)
        if hour and "T" not in hour:
            hour = hour.replace(" ", "T") + ":00Z"
        buckets.append({"hour": hour, "count": b.get("count", 0)})
    return jsonify(buckets)


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
    files = []
    for base in (_ROOT_OUTPUT, _LOCAL_DATA):
        files.extend(base.rglob("analysis_*.json"))
    runs = []
    for f in sorted(files, reverse=True)[:10]:
        try:
            with open(f, encoding="utf-8") as fp:
                d = json.load(fp)
            s = d.get("summary", {})
            runs.append({
                "filename":       f.name,
                "generated_at":   d.get("generated_at", "")[:16].replace("T", " "),
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


# ── 보안 상태 요약 ─────────────────────────────────────────────────
@app.route("/security-status")
def security_status():
    data = _load("analysis_*.json")
    if not data:
        return jsonify([{"항목": "상태", "값": "데이터 없음"}])

    s          = data.get("summary", {})
    block_rate = round(s.get("block_rate", 0) * 100, 1)
    high_ips   = [ip["ip"] for ip in data.get("top_ips", []) if ip.get("risk_level") == "HIGH"]
    waf_mode   = "Block 모드 실제 작동 중" if block_rate > 0 else "Count 모드"
    updated    = data.get("generated_at", "")[:16].replace("T", " ")

    rows = [
        {"항목": "WAF 모드",    "값": waf_mode,                        "상태": "활성"},
        {"항목": "차단률",      "값": f"{block_rate}%",                 "상태": "정상" if block_rate < 50 else "경고"},
        {"항목": "HIGH 위험 IP","값": ", ".join(high_ips) if high_ips else "없음", "상태": "경고" if high_ips else "정상"},
        {"항목": "최종 업데이트","값": updated,                         "상태": "정상"},
    ]
    return jsonify(rows)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
