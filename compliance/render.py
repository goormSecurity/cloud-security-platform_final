from __future__ import annotations

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import ChainableUndefined, Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import sync_playwright


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"
TEMPLATE_NAME = "template.html"
DEFAULT_DATA_FILE = BASE_DIR / "real_data.json"
HTML_FILE = OUTPUT_DIR / "report.html"
PDF_FILE = OUTPUT_DIR / "report.pdf"
PLACEHOLDER = "[ ]"


def _resolve_data_file(override: str | None) -> Path:
    if override:
        p = Path(override)
        if p.exists():
            return p
        raise FileNotFoundError(f"[render] 지정한 데이터 파일 없음: {override}")
    if DEFAULT_DATA_FILE.exists():
        return DEFAULT_DATA_FILE
    raise FileNotFoundError(
        "[render] 데이터 파일 없음. "
        "run_pipeline.py 또는 'python compliance/build_data.py' 를 먼저 실행하세요."
    )


def _compute_final_verdict(data: dict) -> str:
    """분석 데이터 기반 최종 판정 자동 결정."""
    risk = data.get("risk", {}).get("ai", {})
    if risk.get("needs_action"):
        score = risk.get("final_score", 1)
        if score >= 4:
            return "미흡"
        return "부분 적정"
    if risk.get("needs_review"):
        return "재검토 필요"
    return "적정"


def get_path(data: dict[str, Any], path: str, default: Any = PLACEHOLDER) -> Any:
    current: Any = data
    parts = path.split(".")
    index = 0

    while index < len(parts):
        part = parts[index]
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            elif index + 1 < len(parts) and f"{part}.{parts[index + 1]}" in current:
                current = current[f"{part}.{parts[index + 1]}"]
                index += 1
            else:
                return default
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return default
        else:
            return default
        index += 1

    if current in ("", None):
        return default
    return current


def build_code_fields() -> dict[str, str]:
    yyyymmdd = datetime.now().strftime("%Y%m%d")
    sequence = "001"
    return {
        "yyyymmdd": yyyymmdd,
        "sequence": sequence,
        "document_id": f"AUD-WAF-{yyyymmdd}-{sequence}",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event_id": f"EVT-{yyyymmdd}-{sequence}",
        "primary_evidence_id": f"EVD-{yyyymmdd}-{sequence}-001",
    }


def build_evidence_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    specs = [
        ("WAF 설정 상태", "AWS WAF describe", "A"),
        ("암호화 설정", "KMS / S3 SSE-KMS", "A"),
        ("drift 점검", "AWS Config snapshot diff", "A"),
        ("posture 점검", "Prowler report", "A"),
        ("WAF 탐지 로그", "AWS WAF Logs", "B"),
        ("정상 트래픽 기준선", "Ghost CMS 요청 로그", "B"),
        ("Analyzer 결정값", "Python Analyzer output", "B"),
        ("CTI 조회 결과", "AbuseIPDB / OTX", "B"),
    ]
    checks = get_path(data, "integrity.evidence_checks", [])
    rows: list[dict[str, Any]] = []

    for index, (name, source, plane) in enumerate(specs):
        check = checks[index] if isinstance(checks, list) and index < len(checks) else {}
        rows.append(
            {
                "name": name,
                "source": source,
                "plane": plane,
                "evidence_id": check.get("evidence_id", PLACEHOLDER),
                "s3_uri": check.get("s3_uri", PLACEHOLDER),
                "check_result": check.get("check_result", ""),
            }
        )
    return rows


def build_attachment_rows(data: dict[str, Any]) -> list[dict[str, str]]:
    checks = get_path(data, "integrity.evidence_checks", [])
    check_ids = [item.get("evidence_id", PLACEHOLDER) for item in checks] if isinstance(checks, list) else []
    bucket = get_path(data, "meta.evidence_bucket")
    return [
        {
            "evidence_id": check_ids[4] if len(check_ids) > 4 else PLACEHOLDER,
            "file_name": "waf_log_sample.json",
            "description": "WAF 탐지 원본 로그",
            "location": f"s3://{bucket}/waf/",
        },
        {
            "evidence_id": "EVD-CODE-ATHENA-001",
            "file_name": "athena_result.json",
            "description": "Athena 집계 결과",
            "location": f"s3://{bucket}/analysis/",
        },
        {
            "evidence_id": check_ids[6] if len(check_ids) > 6 else PLACEHOLDER,
            "file_name": "analyzer_result.json",
            "description": "Analyzer 결정값",
            "location": f"s3://{bucket}/analysis/",
        },
        {
            "evidence_id": check_ids[7] if len(check_ids) > 7 else PLACEHOLDER,
            "file_name": "cti_lookup_result.json",
            "description": "CTI 조회 결과",
            "location": f"s3://{bucket}/cti/",
        },
        {
            "evidence_id": check_ids[3] if len(check_ids) > 3 else PLACEHOLDER,
            "file_name": "prowler_report.json",
            "description": "posture 점검",
            "location": f"s3://{bucket}/prowler/",
        },
        {
            "evidence_id": check_ids[2] if len(check_ids) > 2 else PLACEHOLDER,
            "file_name": "config_diff.json",
            "description": "drift 점검",
            "location": f"s3://{bucket}/drift/",
        },
        {
            "evidence_id": "EVD-CODE-CLOUDTRAIL-001",
            "file_name": "cloudtrail_events.json",
            "description": "변경·키사용 이력",
            "location": f"s3://{bucket}/cloudtrail/",
        },
        {
            "evidence_id": "EVD-CODE-GITHUB-001",
            "file_name": "github_pr_link.txt",
            "description": "정책 변경 PR 링크",
            "location": get_path(data, "integrity.change_integrity.github.pr_url"),
        },
    ]


def render(data_file: str | None = None) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    resolved = _resolve_data_file(data_file)
    data = json.loads(resolved.read_text(encoding="utf-8"))
    print(f"[render] 데이터 소스: {resolved.name}")

    # meta에 final_verdict 자동 주입 (없으면 계산)
    if "meta" not in data:
        data["meta"] = {}
    if "final_verdict" not in data["meta"]:
        data["meta"]["final_verdict"] = _compute_final_verdict(data)
    # analyzer_summary 호환 (구 포맷은 없을 수 있음)
    if "analyzer_summary" not in data:
        data["analyzer_summary"] = {
            "total_requests": data.get("meta", {}).get("total_requests", 0),
            "high_risk_ips": 0,
            "attack_type_counts": {},
        }

    env = Environment(
        loader=FileSystemLoader(BASE_DIR),
        autoescape=select_autoescape(["html", "xml"]),
        undefined=ChainableUndefined,
    )
    template = env.get_template(TEMPLATE_NAME)

    context = {
        **data,
        "code": build_code_fields(),
        "get": lambda path, default=PLACEHOLDER: get_path(data, path, default),
        "environment_labels": [
            "AWS WAF",
            "ALB",
            "CloudFront",
            "S3",
            "KMS",
            "CloudTrail",
            "Config",
            "Prowler",
            "GitHub",
        ],
        "attack_type_labels": [
            "SQLi",
            "XSS",
            "Command Injection",
            "LFI/RFI",
            "File Upload",
            "Brute Force",
            "API Abuse",
            "JWT 조작",
            "CSRF",
            "정상 트래픽",
        ],
        "waf_action_labels": ["Allow", "Count", "Block", "CAPTCHA", "Challenge"],
        "analyzer_labels": ["정상", "탐지만", "차단 필요", "재검토 필요"],
        "cti_labels": ["해당 없음", "AbuseIPDB 일치", "OTX 일치", "2개 소스 합의", "불일치"],
        "cti_value": get_path(data, "event.cti.consensus"),
        "confidence_labels": ["낮음", "보통", "높음", "매우 높음"],
        "pci_verdict_labels": ["충족", "부분충족", "미충족"],
        "ismsp_verdict_labels": ["적정", "미흡"],
        "likelihood_labels": ["낮음", "보통", "높음", "판단 불가"],
        "impact_labels": ["낮음", "중간", "높음", "중대"],
        "ops_impact_labels": ["낮음", "중간", "높음"],
        "score_labels": [1, 2, 3, 4, 5],
        "evidence_rows": build_evidence_rows(data),
        "attachment_rows": build_attachment_rows(data),
    }

    HTML_FILE.write_text(template.render(context), encoding="utf-8")
    print("HTML OK")
    print(HTML_FILE)

    os.chdir(BASE_DIR)
    html_path = os.path.abspath("output/report.html")
    pdf_path = os.path.abspath("output/report.pdf")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"file://{html_path}", wait_until="networkidle")
        page.pdf(
            path=pdf_path,
            format="A4",
            print_background=True,
            prefer_css_page_size=True,
            margin={"top": "0", "right": "0", "bottom": "0", "left": "0"},
        )
        browser.close()
    print("PDF OK")
    print(PDF_FILE)


def main() -> None:
    p = argparse.ArgumentParser(description="컴플라이언스 감사 보고서 생성")
    p.add_argument("--data", default=None,
                   help="데이터 JSON 경로 (생략 시 compliance/real_data.json 자동 탐색)")
    args = p.parse_args()
    try:
        render(data_file=args.data)
    except FileNotFoundError as e:
        print(e)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
