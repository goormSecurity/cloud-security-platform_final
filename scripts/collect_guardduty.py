#!/usr/bin/env python3
"""
collect_guardduty.py — AWS GuardDuty 위협 탐지 결과 수집

IAM 권한 오용, 비정상 API 호출, 네트워크 위협, 암호화폐 채굴 등
웹 레이어 너머 클라우드 전체 위협을 탐지한 GuardDuty 결과를 수집한다.

출력: compliance/input/guardduty_findings.json

사용 예:
    python scripts/collect_guardduty.py
    python scripts/collect_guardduty.py --severity-min 7   # HIGH만
    python scripts/collect_guardduty.py --days 7
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg, now_kst
except Exception:
    def cfg(p, d=None): return d
    def now_kst(fmt=None):
        t = datetime.now(timezone(timedelta(hours=9)))
        return t.strftime(fmt) if fmt else t.isoformat(timespec="seconds")

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[guardduty] boto3 없음: pip install boto3", file=sys.stderr)
    sys.exit(1)

DEFAULT_REGION = cfg("aws.region", "ap-northeast-2")
OUT_FILE = ROOT / "compliance" / "input" / "guardduty_findings.json"


def _get_detector_id(client) -> str:
    try:
        ids = client.list_detectors().get("DetectorIds", [])
        return ids[0] if ids else ""
    except Exception:
        return ""


def _severity_label(score: float) -> str:
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def collect(region: str = DEFAULT_REGION, severity_min: float = 4.0, days: int = 30) -> dict:
    """GuardDuty finding 수집 후 정제된 dict 반환."""
    client = boto3.client("guardduty", region_name=region)

    detector_id = _get_detector_id(client)
    if not detector_id:
        print("[guardduty] GuardDuty 비활성화 상태 — Terraform apply 후 재실행")
        return {
            "enabled": False,
            "detector_id": "",
            "findings": [],
            "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "by_type": {}},
            "collected_at": now_kst(),
        }

    print(f"[guardduty] Detector ID: {detector_id}")

    cutoff_ms = int(
        (datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000
    )

    # Finding ID 목록 조회 (심각도 필터 + 최근 N일)
    criteria = {
        "Criterion": {
            "severity": {"Gte": int(severity_min * 10)},
            "updatedAt": {"Gte": cutoff_ms},
        }
    }

    finding_ids = []
    paginator = client.get_paginator("list_findings")
    for page in paginator.paginate(
        DetectorId=detector_id,
        FindingCriteria=criteria,
        SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
        PaginationConfig={"MaxItems": 50, "PageSize": 50},
    ):
        finding_ids.extend(page.get("FindingIds", []))

    print(f"[guardduty] 탐지 건수: {len(finding_ids)}건 (최근 {days}일, 심각도 {severity_min}+)")

    findings = []
    by_type: dict[str, int] = {}
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if finding_ids:
        resp = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:50])
        for f in resp.get("Findings", []):
            sev = f.get("Severity", 0)
            label = _severity_label(sev)
            counts[label] = counts.get(label, 0) + 1

            ftype = f.get("Type", "Unknown")
            category = ftype.split(":")[0] if ":" in ftype else ftype
            by_type[category] = by_type.get(category, 0) + 1

            resource = f.get("Resource", {})
            findings.append(
                {
                    "id":            f.get("Id", ""),
                    "type":          ftype,
                    "severity":      sev,
                    "severity_label": label,
                    "title":         f.get("Title", ""),
                    "description":   (f.get("Description") or "")[:300],
                    "region":        f.get("Region", region),
                    "resource_type": resource.get("ResourceType", ""),
                    "account_id":    f.get("AccountId", ""),
                    "created_at":    str(f.get("CreatedAt", "")),
                    "updated_at":    str(f.get("UpdatedAt", "")),
                }
            )

    return {
        "enabled": True,
        "detector_id": detector_id,
        "findings": findings,
        "summary": {
            "total":   len(findings),
            "high":    counts["HIGH"],
            "medium":  counts["MEDIUM"],
            "low":     counts["LOW"],
            "by_type": by_type,
        },
        "collected_at": now_kst(),
    }


def main():
    p = argparse.ArgumentParser(description="GuardDuty 위협 탐지 결과 수집")
    p.add_argument("--region",       default=DEFAULT_REGION)
    p.add_argument("--severity-min", type=float, default=4.0,
                   help="최소 심각도 (4.0=Medium, 7.0=High, 기본 4.0)")
    p.add_argument("--days",         type=int, default=30,
                   help="수집 기간 (일, 기본 30)")
    p.add_argument("--out",          default=str(OUT_FILE),
                   help="출력 파일 경로")
    args = p.parse_args()

    try:
        result = collect(args.region, args.severity_min, args.days)
    except NoCredentialsError:
        print("[guardduty] AWS 자격증명 없음 (~/.aws/credentials 또는 환경변수 확인)", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        print(f"[guardduty] AWS API 오류: {e}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    s = result["summary"]
    print(f"[guardduty] 저장: {out_path}")
    print(f"[guardduty] HIGH={s['high']}  MEDIUM={s['medium']}  LOW={s['low']}")
    if s["by_type"]:
        for k, v in s["by_type"].items():
            print(f"  {k}: {v}건")


if __name__ == "__main__":
    main()
