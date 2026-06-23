#!/usr/bin/env python3
"""
generate_analysis_json.py — AI 보고서 → ai_analysis.json 변환기

ai/output/report_*.md (Markdown)와 output/analysis_*.json을 읽어
build_data.py가 소비하는 compliance/input/ai_analysis.json을 생성한다.

스키마 (build_data._parse_ai 기준):
  owasp, analyzer_judgment, detection_basis, confidence
  risk.{summary, false_positive, false_negative, compliance_impact,
         ops_impact, final_score, needs_review, needs_action}
  recommendations[], final_opinion

사용 예:
  python ai/generate_analysis_json.py
  python ai/generate_analysis_json.py --analysis output/analysis_20260623.json
  python ai/generate_analysis_json.py --md ai/output/report_20260623_030816.md
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AI_OUTPUT_DIR  = ROOT / "ai" / "output"
ANALYSIS_DIR   = ROOT / "output"
OUTPUT_FILE    = ROOT / "compliance" / "input" / "ai_analysis.json"

_OWASP_MAP = {
    "SQLi":             "OWASP Top 10:2021 A03 Injection",
    "XSS":              "OWASP Top 10:2021 A03 Injection",
    "Command Injection":"OWASP Top 10:2021 A03 Injection",
    "CommandInjection": "OWASP Top 10:2021 A03 Injection",
    "Path Traversal":   "OWASP Top 10:2021 A01 Broken Access Control",
    "PathTraversal":    "OWASP Top 10:2021 A01 Broken Access Control",
    "Scanner":          "OWASP Top 10:2021 A05 Security Misconfiguration",
    "Scanner UA":       "OWASP Top 10:2021 A05 Security Misconfiguration",
}

_LABEL_MAP = {
    "CommandInjection": "Command Injection",
    "PathTraversal":    "Path Traversal",
    "SQLi": "SQLi", "XSS": "XSS",
    "Scanner": "Scanner UA",
}


def _norm(t):
    return _LABEL_MAP.get(t, t)


def _score_to_level(score):
    s = float(score or 0)
    if s >= 81: return 5
    if s >= 61: return 4
    if s >= 41: return 3
    if s >= 21: return 2
    return 1


def _extract_md_section(md, title_pattern):
    m = re.search(
        rf"##\s+\d+\.\s+{title_pattern}(.*?)(?=\n##|\Z)",
        md, re.DOTALL | re.IGNORECASE,
    )
    return m.group(1).strip() if m else ""


def _recs_from_md(md):
    """마크다운 5장에서 개선 제안 항목 추출."""
    section = _extract_md_section(md, "정책 개선 제안")
    if not section:
        return []
    recs = []
    for line in section.splitlines():
        line = re.sub(r"^[\-\*\•\d\.\s]+", "", line).strip()
        if line and len(line) > 10:
            recs.append({
                "item": line[:80],
                "text": line,
                "trigger": "",
                "owner": "",
                "due": "",
            })
    return recs[:6]


def _opinion_from_md(md):
    """마크다운 6장에서 운영자 검토 사항 추출."""
    section = _extract_md_section(md, "운영자 검토 사항")
    if not section:
        return ""
    lines = [l.strip() for l in section.splitlines()
             if l.strip() and not l.startswith("#")]
    return " ".join(lines)[:600]


def generate(analysis_path=None, md_path=None):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # ── analysis JSON 로드 ───────────────────────────────────────
    if analysis_path:
        ana_file = Path(analysis_path)
    else:
        candidates = sorted(ANALYSIS_DIR.glob("analysis_*.json"))
        if not candidates:
            sys.exit("[generate_ai_json] output/analysis_*.json 없음. analyzer 먼저 실행하세요.")
        ana_file = candidates[-1]

    ana     = json.loads(ana_file.read_text(encoding="utf-8"))
    summary = ana.get("summary", {})
    top_ips = sorted(
        ana.get("top_ips", []),
        key=lambda x: x.get("risk_score", 0), reverse=True,
    )
    top = top_ips[0] if top_ips else {}

    risk_level   = top.get("risk_level", "LOW")
    risk_score   = top.get("risk_score", 0)
    block_rate   = summary.get("block_rate", 0)
    high_risk    = summary.get("high_risk_ips", 0)
    total        = summary.get("total_requests", 0)
    source_ip    = top.get("ip", "N/A")
    attack_types = [_norm(t) for t in summary.get("attack_type_counts", {}).keys()]
    primary      = attack_types[0] if attack_types else "Unknown"
    rule_hits    = ana.get("rule_hits", {})

    print(f"[generate_ai_json] 분석 파일: {ana_file.name}")
    print(f"  최고위험 IP: {source_ip} ({risk_level}, {risk_score}점)")

    # ── Markdown 보고서 로드 (선택) ─────────────────────────────
    md_text = ""
    if md_path:
        md_text = Path(md_path).read_text(encoding="utf-8")
        print(f"[generate_ai_json] MD 보고서: {Path(md_path).name}")
    else:
        md_candidates = sorted(AI_OUTPUT_DIR.glob("report_*.md"))
        if md_candidates:
            md_text = md_candidates[-1].read_text(encoding="utf-8")
            print(f"[generate_ai_json] MD 보고서: {md_candidates[-1].name}")

    # ── 필드 계산 ────────────────────────────────────────────────
    rule_summary   = ", ".join(f"{k}: {v}건" for k, v in rule_hits.items() if v) or "없음"
    types_str      = ", ".join(attack_types) or "없음"
    detection_basis = (
        f"총 {total:,}건 요청 중 최고위험 IP {source_ip} "
        f"({top.get('request_count', 0):,}건 집중), "
        f"공격 패턴: {types_str}. WAF 룰 탐지: {rule_summary}."
    )
    analyzer_judgment = (
        "차단 필요"   if risk_level == "HIGH" or block_rate >= 0.5 else
        "재검토 필요" if risk_level == "MEDIUM" or block_rate >= 0.1 else
        "탐지만"
    )
    confidence = "높음" if risk_score >= 70 else ("보통" if risk_score >= 40 else "낮음")
    owasp      = _OWASP_MAP.get(primary, "OWASP Top 10:2021")

    # ── 권고사항: Markdown 우선 → 자동 생성 fallback ────────────
    recs = _recs_from_md(md_text) if md_text else []
    if not recs:
        atc = {_norm(k): v for k, v in summary.get("attack_type_counts", {}).items()}
        if "SQLi" in atc:
            recs.append({
                "trigger": "PCI e4/ISMS 2.11",
                "item": "WAF SQLi 룰 Block 전환",
                "text": f"SQLi {atc['SQLi']}건 탐지. AWSManagedRulesSQLiRuleSet Count→Block 전환 검토.",
                "owner": "", "due": "",
            })
        if "XSS" in atc:
            recs.append({
                "trigger": "PCI e4/ISMS 2.11",
                "item": "WAF XSS 룰 강화",
                "text": f"XSS {atc['XSS']}건 탐지. CommonRuleSet XSS 차단 룰 활성화 검토.",
                "owner": "", "due": "",
            })
        if risk_level in ("HIGH", "MEDIUM"):
            recs.append({
                "trigger": "ISMS 2.6",
                "item": f"고위험 IP 차단 ({source_ip})",
                "text": f"위험도 {risk_score}점 IP {source_ip} → WAF IP Set 추가 차단.",
                "owner": "", "due": "",
            })
        if block_rate == 0:
            recs.append({
                "trigger": "PCI e4",
                "item": "WAF Count→Block 전환 계획 수립",
                "text": "A/B 테스트 결과 기반 Block 전환 일정 수립 권고.",
                "owner": "", "due": "",
            })

    # ── 최종 의견: Markdown 우선 → 자동 생성 fallback ───────────
    final_opinion = _opinion_from_md(md_text) if md_text else ""
    if not final_opinion:
        parts = [
            f"본 감사 보고서는 실제 AWS WAF 로그 {total:,}건을 AI가 분석한 결과입니다.",
            f"주요 탐지 공격 유형: {types_str}.",
        ]
        if high_risk > 0:
            parts.append(
                f"고위험 IP {high_risk}개 탐지 (최고위험: {source_ip}, {risk_score}점). "
                f"현재 {analyzer_judgment} 판정."
            )
        if block_rate == 0:
            parts.append("모든 룰이 Count 모드. Block 전환 계획 수립 권고.")
        final_opinion = " ".join(parts)

    # ── 출력 ────────────────────────────────────────────────────
    result = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "source_analysis":   str(ana_file),
        "owasp":             owasp,
        "analyzer_judgment": analyzer_judgment,
        "detection_basis":   detection_basis,
        "confidence":        confidence,
        "risk": {
            "summary":            f"위험도 {risk_score}점 ({risk_level}), 고위험 IP {high_risk}개",
            "false_positive":     "낮음" if block_rate < 0.3 else "보통",
            "false_negative":     "높음" if block_rate == 0 else "보통",
            "compliance_impact":  "높음" if high_risk > 0 else "중간",
            "ops_impact":         "낮음",
            "final_score":        _score_to_level(risk_score),
            "needs_review":       risk_level in ("HIGH", "MEDIUM"),
            "needs_action":       risk_level == "HIGH",
        },
        "recommendations": recs,
        "final_opinion":   final_opinion,
    }

    OUTPUT_FILE.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[generate_ai_json] 저장: {OUTPUT_FILE}")
    print(f"  판정: {analyzer_judgment} / 신뢰도: {confidence} / 권고: {len(recs)}개")
    print("[generate_ai_json] 완료")
    return result


def main():
    p = argparse.ArgumentParser(
        description="AI Markdown 보고서 → compliance/input/ai_analysis.json"
    )
    p.add_argument("--analysis", default=None, help="analysis JSON 경로 (생략 시 최신 자동)")
    p.add_argument("--md",       default=None, help="AI Markdown 보고서 경로 (생략 시 최신 자동)")
    args = p.parse_args()
    generate(analysis_path=args.analysis, md_path=args.md)


if __name__ == "__main__":
    main()
