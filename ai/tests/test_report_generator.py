from pathlib import Path
import json
import sys

import pytest


AI_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AI_DIR))

import report_generator


SAMPLE_DATA = {
    "summary": {"total_requests": 25},
    "top_ips": [{"ip": "203.0.113.10", "risk_level": "HIGH"}],
}


def _valid_report() -> str:
    return "\n".join(
        [
            "# WAF 보안 분석 보고서",
            "## 1. 공격 현황 요약",
            "전체 요청 수는 25건이다.",
            "## 2. 주요 공격 유형",
            "제공된 분석 결과에서 확인되지 않음",
            "## 3. 위험 IP 분석",
            "203.0.113.10은 HIGH 등급이다.",
            "## 4. WAF 탐지 결과",
            "제공된 분석 결과에서 확인되지 않음",
            "## 5. 정책 개선 제안",
            "제공된 분석 결과에서 확인되지 않음",
            "## 6. 운영자 검토 사항",
            "제공된 분석 결과에서 확인되지 않음",
        ]
    )


def test_valid_report_passes_validation():
    report_generator.validate_report(_valid_report(), SAMPLE_DATA)


def test_unknown_ip_is_rejected():
    report = _valid_report().replace("203.0.113.10", "198.51.100.20")

    with pytest.raises(ValueError, match="없는 IP"):
        report_generator.validate_report(report, SAMPLE_DATA)


def test_unknown_number_is_rejected():
    report = _valid_report().replace("25건", "99건")

    with pytest.raises(ValueError, match="없는 숫자"):
        report_generator.validate_report(report, SAMPLE_DATA)


def test_prompt_does_not_treat_every_top_ip_as_high_risk():
    assert 'risk_level이 LOW인 IP를 "위험한 IP"' in report_generator.SYSTEM_PROMPT


def test_prompt_separates_analyzer_classification_from_waf_detection():
    assert "attack_type_counts는 Analyzer 분류 결과이며 WAF 탐지 결과가 아니다" in report_generator.SYSTEM_PROMPT


def test_generation_retries_after_invalid_report(monkeypatch, tmp_path):
    input_path = tmp_path / "analysis.json"
    input_path.write_text(
        json.dumps(SAMPLE_DATA, ensure_ascii=False),
        encoding="utf-8",
    )
    responses = iter(["invalid report", _valid_report()])

    monkeypatch.setattr(
        report_generator,
        "call_ollama_with_langchain",
        lambda **_: next(responses),
    )

    output_path = report_generator.generate_report(
        input_path=input_path,
        output_dir=tmp_path / "output",
        model="test-model",
        ollama_base_url="http://localhost:11435",
    )

    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8") == _valid_report()
