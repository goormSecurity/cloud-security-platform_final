"""
종합 보안 플랫폼 검증 스위트

검증 범위:
  1. AI 보고서 — 섹션 구조, IP 할루시네이션 탐지, 재시도 로직
  2. FACTS 빌더 — 각 데이터 소스별 숫자·키 일관성
  3. 허용 숫자 목록 — 비율→퍼센트 변환 포함
  4. 컴플라이언스 매핑 — ZAP/Prowler/Trivy/S3 → template.html 키
  5. Slack/Discord 알림 페이로드 — 위험 수준별 색상·메시지
"""
from pathlib import Path
import json
import shutil
import sys
import tempfile

import pytest

AI_DIR = Path(__file__).resolve().parents[1]
ROOT   = AI_DIR.parent
sys.path.insert(0, str(AI_DIR))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "compliance"))

import report_generator


# ── 공통 샘플 데이터 ──────────────────────────────────────────────────────────

SAMPLE_WAF = {
    "generated_at": "2026-07-06T12:00:00",
    "summary": {
        "total_requests": 25000,
        "unique_ips": 150,
        "high_risk_ips": 2,
        "block_rate": 0.105,
        "action_counts": {"BLOCK": 2625, "COUNT": 3000, "ALLOW": 19375},
        "attack_type_counts": {"SQLi": 120, "XSS": 45},
    },
    "top_ips": [
        {"ip": "203.0.113.10", "risk_level": "HIGH", "risk_score": 95,
         "request_count": 500, "country": "CN", "attack_types": ["SQLi"],
         "block_rate": 0.9, "action_counts": {"BLOCK": 450, "COUNT": 50}},
        {"ip": "198.51.100.5", "risk_level": "LOW", "risk_score": 20,
         "request_count": 10, "country": "US", "attack_types": [],
         "block_rate": 0.0},
    ],
    "rule_hits": {"AWSManagedRulesSQLiRuleSet": 120, "AWSManagedRulesCommonRuleSet": 45},
}


def _valid_report() -> str:
    """REQUIRED_SECTIONS 5개를 모두 포함하는 유효 보고서"""
    return "\n".join([
        "# WAF 보안 분석 보고서",
        "## 1. 공격 현황 요약",
        "전체 요청 25,000건. HIGH IP 2개.",
        "## 2. WAF 탐지·차단 현황",
        "BLOCK 2,625건 / COUNT 3,000건.",
        "## 3. 위험 IP 분석",
        "203.0.113.10은 HIGH 등급이다.",
        "## 4. WAF 효과성 평가",
        "차단율 10.5%.",
        "## 5. 인프라 보안 점검",
        "Prowler 데이터 없음.",
        "## 6. 웹·컨테이너 취약점 스캔",
        "ZAP 데이터 없음.",
        "## 7. 데이터 보안 및 변경 이력",
        "CloudTrail 없음.",
        "## 8. 종합 정책 개선 제안",
        "Block 모드 전환 권고.",
        "## 9. 운영자 검토 사항",
        "즉시 조치 필요: 차단 목록 업데이트.",
    ])


# ═══════════════════════════════════════════════════════════════════════════════
# 1. validate_report — 섹션·IP 검증
# ═══════════════════════════════════════════════════════════════════════════════

def test_valid_report_passes_validation():
    report_generator.validate_report(_valid_report(), [SAMPLE_WAF])


def test_unknown_ip_is_rejected():
    report = _valid_report().replace("203.0.113.10", "1.2.3.4")
    with pytest.raises(ValueError, match="없는 IP"):
        report_generator.validate_report(report, [SAMPLE_WAF])


def test_missing_required_section_is_rejected():
    report = _valid_report().replace("## 8. 종합 정책 개선 제안", "## 8. 다른 제목")
    with pytest.raises(ValueError, match="필수 섹션 누락"):
        report_generator.validate_report(report, [SAMPLE_WAF])


def test_missing_report_title_is_rejected():
    report = _valid_report().replace("# WAF 보안 분석 보고서", "# 엉뚱한 제목")
    with pytest.raises(ValueError, match="필수 섹션 누락"):
        report_generator.validate_report(report, [SAMPLE_WAF])


def test_known_ip_in_multiple_sources_passes():
    """여러 데이터 소스 중 하나에 IP가 있으면 통과해야 한다"""
    extra_source = {"events": [{"ip": "203.0.113.10"}]}
    minimal_waf = {"summary": {}, "top_ips": []}
    report_generator.validate_report(_valid_report(), [minimal_waf, extra_source])


# ═══════════════════════════════════════════════════════════════════════════════
# 2. FACTS 빌더 — 데이터 일관성
# ═══════════════════════════════════════════════════════════════════════════════

def test_build_waf_facts_key_numbers():
    facts = report_generator.build_waf_facts(SAMPLE_WAF)
    assert "total_requests=25000" in facts
    assert "high_risk_ips=2" in facts
    assert "block_rate=0.105" in facts
    assert "action_counts.BLOCK=2625" in facts
    assert "action_counts.COUNT=3000" in facts


def test_build_waf_facts_all_top_ips():
    facts = report_generator.build_waf_facts(SAMPLE_WAF)
    assert "203.0.113.10" in facts
    assert "198.51.100.5" in facts
    assert "risk_level=HIGH" in facts
    assert "risk_level=LOW" in facts


def test_build_waf_facts_rule_hits():
    facts = report_generator.build_waf_facts(SAMPLE_WAF)
    assert "AWSManagedRulesSQLiRuleSet" in facts


def test_build_fpfn_facts_no_data():
    assert "데이터없음" in report_generator.build_fpfn_facts(None)


def test_build_fpfn_facts_with_data():
    fpfn = {
        "overall_verdict": "위험",
        "summary": "FN 50%",
        "false_negative": {
            "fn_count": 5, "fn_rate": 0.5,
            "total_attack_patterns": 10,
            "improvable_by_block_mode": 4,
            "current_detection_rate": "50%",
            "block_mode_detection_rate": "90%",
            "fn_items": [
                {"category": "SQLi", "name": "union", "waf_action": "COUNT", "matched_rule": "없음"},
            ],
        },
        "false_positive_log": {"fp_suspicion_count": 1, "potential_fp_ips": []},
        "false_positive_test": {"tested": 10, "fp_count": 0, "fp_rate": 0.0},
        "recommendations": [{"action": "Block 전환", "priority": "HIGH"}],
    }
    facts = report_generator.build_fpfn_facts(fpfn)
    assert "fpfn.fn_count=5" in facts
    assert "fpfn.fn_rate=0.5" in facts
    assert "fpfn.improvable_by_block=4" in facts
    assert "fpfn.rec=Block 전환" in facts


def test_build_abtest_facts_no_data():
    assert "데이터없음" in report_generator.build_abtest_facts(None)


def test_build_abtest_facts_with_data():
    ab = {
        "total_attack_patterns": 20,
        "current_mode": {"block_rate": "5%", "detection_rate": "50%", "actions": {"COUNT": 10}},
        "proposed_block_mode": {"block_rate": "90%", "detection_rate": "90%", "actions": {"BLOCK": 18}},
    }
    facts = report_generator.build_abtest_facts(ab)
    assert "abtest.total_patterns=20" in facts
    assert "abtest.current.block_rate=5%" in facts
    assert "abtest.proposed.block_rate=90%" in facts


def test_build_prowler_facts_empty():
    assert "데이터없음" in report_generator.build_prowler_facts([])


def test_build_prowler_facts_counts():
    findings = [
        {"check_id": "iam_root_mfa_enabled", "status": "FAIL", "severity": "critical",
         "status_extended": "Root MFA 비활성화"},
        {"check_id": "wafv2_webacl_exists",  "status": "PASS", "severity": "high",
         "status_extended": "WAF 설정됨"},
    ]
    facts = report_generator.build_prowler_facts(findings)
    assert "prowler.total_checks=2" in facts
    assert "prowler.fail_count=1" in facts
    assert "prowler.pass_count=1" in facts
    assert "iam_root_mfa_enabled" in facts


def test_build_infra_facts_config_drift():
    config = {
        "recorder_status": "ACTIVE",
        "drift_detected": True,
        "resource_changes": [{"id": "sg-1"}],
        "status": "WARN",
    }
    facts = report_generator.build_infra_facts(config, None, None, None, None)
    assert "config.drift_detected=True" in facts
    assert "config.resource_changes=1" in facts


def test_build_zap_facts_no_data():
    assert "데이터없음" in report_generator.build_zap_facts(None)


def test_build_zap_facts_with_data():
    zap = {
        "total_alerts": 3,
        "risk_counts": {"High": 1, "Medium": 2, "Low": 0},
        "alerts": [
            {"name": "SQL Injection", "risk": "High", "url": "http://example.com/api"},
            {"name": "XSS", "risk": "Medium", "url": "http://example.com/page"},
        ],
    }
    facts = report_generator.build_zap_facts(zap)
    assert "zap.total_alerts=3" in facts
    assert "zap.high=1" in facts
    assert "zap.medium=2" in facts
    assert "SQL Injection" in facts
    assert "example.com" in facts


def test_build_trivy_facts_no_data():
    assert "데이터없음" in report_generator.build_trivy_facts(None)


def test_build_trivy_facts_with_data():
    trivy = {
        "summary": {"total_vulns": 10, "critical": 2, "high": 5, "medium": 3},
        "images": {
            "results": [{
                "image": "dvwa:latest",
                "by_severity": {"CRITICAL": 2, "HIGH": 5},
                "top_vulns": [{"vulnerability_id": "CVE-2023-1234", "severity": "CRITICAL", "pkg_name": "openssl"}],
            }],
        },
        "iac": {"total": 4, "by_severity": {"HIGH": 2, "MEDIUM": 2}},
    }
    facts = report_generator.build_trivy_facts(trivy)
    assert "trivy.total_vulns=10" in facts
    assert "trivy.critical=2" in facts
    assert "dvwa:latest" in facts
    assert "CVE-2023-1234" in facts
    assert "trivy.iac_misconfigs=4" in facts


def test_build_cloudtrail_list_format():
    events = [
        {"eventName": "UpdateWebACL", "eventSource": "wafv2.amazonaws.com",
         "eventTime": "2026-07-06T10:00:00Z"},
    ]
    facts = report_generator.build_cloudtrail_facts(events)
    assert "cloudtrail.total_events=1" in facts
    assert "UpdateWebACL" in facts


def test_build_cloudtrail_dict_format():
    events = {"Events": [
        {"EventName": "PutBucketPolicy", "EventSource": "s3.amazonaws.com",
         "EventTime": "2026-07-06T10:00:00Z"},
    ]}
    facts = report_generator.build_cloudtrail_facts(events)
    assert "cloudtrail.total_events=1" in facts
    assert "PutBucketPolicy" in facts


# ═══════════════════════════════════════════════════════════════════════════════
# 3. 허용 숫자 목록 — 할루시네이션 방지 기반
# ═══════════════════════════════════════════════════════════════════════════════

def test_allowed_numbers_includes_data_values():
    nums = report_generator.build_allowed_numbers(SAMPLE_WAF)
    assert "25000" in nums
    assert "2625" in nums
    assert "120" in nums


def test_allowed_numbers_converts_rate_to_pct():
    # block_rate=0.105 → "10.5" 포함되어야 함
    nums = report_generator.build_allowed_numbers(SAMPLE_WAF)
    assert "10.5" in nums


def test_allowed_numbers_always_includes_base_digits():
    nums = report_generator.build_allowed_numbers({})
    for d in ["0", "1", "10", "100"]:
        assert d in nums


# ═══════════════════════════════════════════════════════════════════════════════
# 4. 프롬프트 구조 검증
# ═══════════════════════════════════════════════════════════════════════════════

def test_prompt_forbids_low_ip_as_high_risk():
    assert 'risk_level이 LOW인 IP를 "위험한 IP"' in report_generator.SYSTEM_PROMPT


def test_prompt_forbids_number_substitution():
    assert "trivy.critical" in report_generator.SYSTEM_PROMPT
    assert "임의 대체하지 않는다" in report_generator.SYSTEM_PROMPT


def test_prompt_forbids_cross_section_data_mixing():
    assert "다른 도구의 수치를 혼용하지 않는다" in report_generator.SYSTEM_PROMPT


def test_system_prompt_has_9_sections():
    for section in [
        "1. 공격 현황 요약",
        "2. WAF 탐지",
        "3. 위험 IP 분석",
        "4. WAF 효과성",
        "5. 인프라 보안",
        "6. 웹·컨테이너",
        "7. 데이터 보안",
        "8. 종합 정책 개선 제안",
        "9. 운영자 검토",
    ]:
        assert section in report_generator.SYSTEM_PROMPT, f"섹션 누락: {section}"


def test_user_prompt_has_all_data_blocks():
    for block in ["WAF 분석 데이터", "FP/FN", "A/B 테스트", "Prowler",
                  "ZAP", "Trivy", "CloudTrail", "허용 숫자 목록"]:
        assert block in report_generator.USER_PROMPT_TEMPLATE, f"블록 누락: {block}"


def test_user_prompt_template_keys_match_generate_report():
    """USER_PROMPT_TEMPLATE의 {placeholder}가 generate_report의 facts dict 키와 일치"""
    import re
    placeholders = set(re.findall(r"\{(\w+)\}", report_generator.USER_PROMPT_TEMPLATE))
    expected_keys = {
        "waf_facts", "fpfn_facts", "abtest_facts", "prowler_facts",
        "infra_facts", "zap_facts", "trivy_facts", "cloudtrail_facts", "allowed_numbers",
    }
    assert placeholders == expected_keys, f"불일치: {placeholders ^ expected_keys}"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. 재시도 로직
# ═══════════════════════════════════════════════════════════════════════════════

def test_generation_retries_on_invalid_report():
    """첫 번째 LLM 응답이 유효하지 않으면 재시도하고 두 번째에 성공한다"""
    tmp = Path(tempfile.mkdtemp())
    try:
        input_path = tmp / "analysis.json"
        input_path.write_text(json.dumps(SAMPLE_WAF, ensure_ascii=False), encoding="utf-8")

        call_count = [0]
        orig_call_llm = report_generator.call_llm

        def fake_call_llm(facts, model, base_url):
            call_count[0] += 1
            if call_count[0] == 1:
                return "invalid: 섹션 없는 보고서"
            return _valid_report()

        report_generator.call_llm = fake_call_llm
        try:
            output_path = report_generator.generate_report(
                input_path=input_path,
                output_dir=tmp / "output",
                model="test-model",
                ollama_base_url="http://localhost:11435",
            )
        finally:
            report_generator.call_llm = orig_call_llm

        assert output_path.exists()
        assert call_count[0] == 2
        assert "WAF 보안 분석 보고서" in output_path.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_generation_saves_best_effort_on_all_failures():
    """3번 모두 실패해도 경고 헤더 붙여 저장한다"""
    tmp = Path(tempfile.mkdtemp())
    try:
        input_path = tmp / "analysis.json"
        input_path.write_text(json.dumps(SAMPLE_WAF, ensure_ascii=False), encoding="utf-8")

        orig_call_llm = report_generator.call_llm
        report_generator.call_llm = lambda *_: "# WAF 보안 분석 보고서\n섹션 일부 누락."
        try:
            output_path = report_generator.generate_report(
                input_path=input_path,
                output_dir=tmp / "output",
                model="test-model",
                ollama_base_url="http://localhost:11435",
            )
        finally:
            report_generator.call_llm = orig_call_llm

        assert "자동 검증 경고" in output_path.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. 컴플라이언스 매핑 — build_data.py → template.html 키 일치
# ═══════════════════════════════════════════════════════════════════════════════

def test_zap_mapping_full_data():
    from build_data import _parse_zap
    raw = {
        "total_alerts": 5,
        "risk_counts": {"High": 1, "Medium": 2, "Low": 2},
        "alerts": [
            {"name": "SQL Injection", "risk": "High",  "url": "http://x.com/a"},
            {"name": "XSS",           "risk": "Medium", "url": "http://x.com/b"},
        ],
        "generated_at": "2026-07-06T12:00:00",
    }
    r = _parse_zap(raw)
    assert r["total_alerts"] == 5
    assert r["high"] == 1
    assert r["medium"] == 2
    assert r["low"] == 2
    assert r["top_alerts"][0]["name"] == "SQL Injection"
    assert r["collected_at"] == "2026-07-06T12:00:00"
    assert r["_data_collected"] is True


def test_zap_mapping_no_data():
    from build_data import _parse_zap
    r = _parse_zap(None)
    assert r["total_alerts"] == 0
    assert r["_data_collected"] is False


def test_zap_mapping_only_high_medium_in_top_alerts():
    from build_data import _parse_zap
    raw = {
        "total_alerts": 3,
        "risk_counts": {"High": 0, "Medium": 1, "Low": 2},
        "alerts": [
            {"name": "Low Issue",    "risk": "Low"},
            {"name": "Medium Issue", "risk": "Medium"},
        ],
    }
    r = _parse_zap(raw)
    names = [a["name"] for a in r["top_alerts"]]
    assert "Low Issue" not in names
    assert "Medium Issue" in names


def test_prowler_mapping_fail_filter():
    from build_data import _parse_prowler
    findings = [
        {"check_id": "iam_root_mfa_enabled", "status": "FAIL", "severity": "critical"},
        {"check_id": "wafv2_webacl_exists",  "status": "PASS"},
        {"check_id": "s3_bucket_public",     "status": "FAIL", "severity": "high"},
    ]
    r = _parse_prowler(findings)
    assert r["_data_collected"] is True
    assert len(r["findings"]) == 2
    assert all(f["status"] == "FAIL" for f in r["findings"])


def test_prowler_mapping_mfa_detection():
    from build_data import _parse_prowler
    findings = [
        {"check_id": "iam_root_mfa_enabled", "service": "iam", "status": "PASS"},
        {"check_id": "iam_user_mfa_enabled",  "service": "iam", "status": "PASS"},
    ]
    r = _parse_prowler(findings)
    assert r["mfa_enabled"] is True


def test_prowler_mapping_no_data():
    from build_data import _parse_prowler
    r = _parse_prowler(None)
    assert r["_data_collected"] is False
    assert r["mfa_enabled"] is None


def test_trivy_mapping():
    from build_data import _parse_trivy
    raw = {
        "tool": "Trivy",
        "summary": {"total_vulns": 10, "critical": 2, "high": 5, "medium": 3},
        "images": {
            "scanned": ["dvwa:latest"],
            "results": [{
                "image": "dvwa:latest", "total": 7,
                "by_severity": {"CRITICAL": 2, "HIGH": 5},
                "top_vulns": [{"vulnerability_id": "CVE-2023-1234", "severity": "CRITICAL",
                               "pkg_name": "openssl"}],
            }],
        },
        "iac": {"total": 3, "by_severity": {"HIGH": 1, "MEDIUM": 2}},
        "collected_at": "2026-07-06T12:00:00",
    }
    r = _parse_trivy(raw)
    assert r["total_vulns"] == 10
    assert r["critical"] == 2
    assert r["images_scanned"] == ["dvwa:latest"]
    assert r["image_results"][0]["critical"] == 2
    assert r["iac_misconfigs"] == 3
    assert r["_data_collected"] is True


def test_trivy_mapping_no_data():
    from build_data import _parse_trivy
    r = _parse_trivy(None)
    assert r["total_vulns"] == 0
    assert r["_data_collected"] is False


def test_s3_security_mapping():
    from build_data import _parse_s3_security
    raw = {
        "overall": "WARN",
        "total_buckets": 3,
        "pass": 1, "warn": 1, "fail": 1,
        "buckets": [
            {
                "bucket": "fail-bucket", "verdict": "FAIL",
                "encryption": {"config": {"SSEAlgorithm": "AES256"}},
                "versioning": {"config": {"Status": "Enabled"}},
                "logging": {"config": {"enabled": False}},
                "public_access_block": {"config": {
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                }},
                "issues": ["logging_disabled"],
            },
        ],
    }
    r = _parse_s3_security(raw)
    assert r["overall"] == "WARN"
    assert r["total_buckets"] == 3
    assert "fail-bucket" in r["fail_buckets"]
    assert "logging_disabled" in r["top_issues"]


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Slack / Discord 알림 페이로드
# ═══════════════════════════════════════════════════════════════════════════════

import notify_slack


def _make_analysis(high_risk: int, attack_types: dict) -> dict:
    ips = []
    if high_risk > 0:
        ips.append({"ip": "10.0.0.1", "risk_level": "HIGH", "risk_score": 90,
                    "country": "CN", "attack_types": list(attack_types)})
    return {
        "summary": {"total_requests": 1000, "high_risk_ips": high_risk,
                    "block_rate": 0.1 if high_risk else 0.0,
                    "attack_type_counts": attack_types},
        "top_ips": ips,
    }


def test_slack_payload_high_risk_red():
    data = _make_analysis(1, {"SQLi": 5})
    p = notify_slack._build_payload(data, "test.json", "https://hooks.slack.com/x")
    assert p["attachments"][0]["color"] == "#FF0000"
    assert "HIGH" in p["attachments"][0]["title"]


def test_slack_payload_attack_no_high_orange():
    data = _make_analysis(0, {"XSS": 3})
    p = notify_slack._build_payload(data, "test.json", "https://hooks.slack.com/x")
    assert p["attachments"][0]["color"] == "#FFA500"


def test_slack_payload_clean_green():
    data = _make_analysis(0, {})
    p = notify_slack._build_payload(data, "test.json", "https://hooks.slack.com/x")
    assert p["attachments"][0]["color"] == "#36A64F"


def test_discord_payload_has_embed_structure():
    data = _make_analysis(1, {"SQLi": 5})
    p = notify_slack._build_payload(data, "test.json", "https://discord.com/api/webhooks/123/abc")
    assert "embeds" in p
    assert isinstance(p["embeds"][0]["color"], int)
    assert p["embeds"][0]["color"] == int("FF0000", 16)


def test_slack_payload_count_mode_warning():
    """block_rate=0이고 공격이 있으면 Count 모드 경고 필드가 포함되어야 한다"""
    data = _make_analysis(0, {"SQLi": 10})
    data["summary"]["block_rate"] = 0.0
    p = notify_slack._build_payload(data, "test.json", "https://hooks.slack.com/x")
    field_titles = [f["title"] for f in p["attachments"][0]["fields"]]
    assert any("주의" in t for t in field_titles)


def test_slack_payload_required_fields():
    data = _make_analysis(0, {})
    p = notify_slack._build_payload(data, "test.json", "https://hooks.slack.com/x")
    titles = [f["title"] for f in p["attachments"][0]["fields"]]
    assert any("요청 수" in t for t in titles)
    assert any("차단율" in t or "WAF" in t for t in titles)


def test_discord_is_detected_correctly():
    assert notify_slack._is_discord("https://discord.com/api/webhooks/123/abc") is True
    assert notify_slack._is_discord("https://hooks.slack.com/services/T00/B00/xxx") is False
    assert notify_slack._is_discord("https://discordapp.com/api/webhooks/99/zz") is True
