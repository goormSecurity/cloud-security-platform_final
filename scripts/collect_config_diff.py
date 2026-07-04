#!/usr/bin/env python3
"""
collect_config_diff.py — AWS Config 드리프트 감지 수집기 (ISMS-P 2.10)

AWS Config 리소스 변경 이력을 조회하여 WAF/보안 설정 드리프트를 감지한다.
Config Recorder가 비활성화된 경우 WARN 상태로 기록한다.

출력: compliance/input/config_diff.json

사용 예:
  python scripts/collect_config_diff.py
  python scripts/collect_config_diff.py --days 14
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg
except Exception:
    def cfg(p, d=None): return d

OUTPUT_FILE = ROOT / "compliance" / "input" / "config_diff.json"

DEFAULT_REGION = cfg("aws.region", "ap-northeast-2")
DEFAULT_DAYS   = 7

WAF_RESOURCE_TYPES = [
    "AWS::WAFv2::WebACL",
    "AWS::WAFv2::IPSet",
    "AWS::WAFv2::RuleGroup",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::S3::Bucket",
]


def _client(service, region):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_config] boto3가 필요합니다: pip install boto3")


def collect(region=DEFAULT_REGION, days=DEFAULT_DAYS):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    now   = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    result = {
        "checked_at": now.isoformat(),
        "region": region,
        "period_days": days,
        "recorder_status": None,
        "drift_detected": False,
        "resource_changes": [],
        "compliance_rules": [],
        "status": "UNKNOWN",
    }

    cfg = _client("config", region)

    # ── 1. Config Recorder 상태 ─────────────────────────────────
    try:
        recorders = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
        if not recorders:
            result["recorder_status"] = "NOT_CONFIGURED"
            result["status"] = "WARN"
            result["note"] = (
                "AWS Config Recorder가 설정되지 않음. "
                "ISMS-P 2.10 드리프트 감지를 위해 활성화 필요."
            )
            print("[collect_config] Config Recorder 미설정 — WARN 상태 기록")
        else:
            rec = recorders[0]
            recording = rec.get("recording", False)
            result["recorder_status"] = {
                "name": rec.get("name"),
                "recording": recording,
                "lastStatus": rec.get("lastStatus", "UNKNOWN"),
                "lastStartTime": (
                    rec.get("lastStartTime").isoformat()
                    if rec.get("lastStartTime") else None
                ),
            }
            result["status"] = "PASS" if recording else "WARN"
            print(f"[collect_config] Config Recorder: {'활성' if recording else '비활성'}")
    except Exception as e:
        result["recorder_status"] = "ERROR"
        result["status"] = "ERROR"
        result["error"] = str(e)
        print(f"[collect_config] Config Recorder 조회 실패: {e}")

    # ── 2. WAF 리소스 변경 이력 ──────────────────────────────────
    for rtype in WAF_RESOURCE_TYPES:
        try:
            paginator = cfg.get_paginator("list_discovered_resources")
            for page in paginator.paginate(resourceType=rtype):
                for res in page.get("resourceIdentifiers", []):
                    rid = res.get("resourceId")
                    try:
                        history = cfg.get_resource_config_history(
                            resourceType=rtype,
                            resourceId=rid,
                            startTime=since,
                            endTime=now,
                            limit=5,
                        )
                        items = history.get("configurationItems", [])
                        if len(items) > 1:
                            result["drift_detected"] = True
                        for item in items:
                            result["resource_changes"].append({
                                "resourceType": rtype,
                                "resourceId": rid,
                                "resourceName": item.get("resourceName"),
                                "configurationItemCaptureTime": (
                                    item["configurationItemCaptureTime"].isoformat()
                                    if item.get("configurationItemCaptureTime") else None
                                ),
                                "configurationItemStatus": item.get("configurationItemStatus"),
                                "configurationItemDiff": item.get("configurationItemDiff"),
                            })
                    except Exception:
                        pass
        except Exception as e:
            print(f"[collect_config] {rtype} 조회 실패: {e}")

    # ── 3. Config 컴플라이언스 룰 결과 ──────────────────────────
    try:
        rules = cfg.describe_compliance_by_config_rule().get(
            "ComplianceByConfigRules", []
        )
        for rule in rules:
            comp = rule.get("Compliance", {})
            cnt  = comp.get("ComplianceContributorCount", {})
            result["compliance_rules"].append({
                "ConfigRuleName": rule.get("ConfigRuleName"),
                "ComplianceType": comp.get("ComplianceType"),
                "CompliantResourceCount": cnt.get("CompliantResourceCount"),
                "NonCompliantResourceCount": cnt.get("NonCompliantResourceCount"),
            })
        print(f"[collect_config] Config 룰: {len(result['compliance_rules'])}개")
    except Exception as e:
        print(f"[collect_config] Config 룰 조회 실패: {e}")

    print(
        f"[collect_config] 리소스 변경: {len(result['resource_changes'])}건 "
        f"/ 드리프트: {result['drift_detected']}"
    )
    OUTPUT_FILE.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"[collect_config] 저장: {OUTPUT_FILE}")
    print("[collect_config] 완료")


def main():
    p = argparse.ArgumentParser(
        description="AWS Config 드리프트 감지 → compliance/input/config_diff.json"
    )
    p.add_argument("--region", default=DEFAULT_REGION)
    p.add_argument("--days",   default=DEFAULT_DAYS, type=int, help="수집 기간 (일)")
    args = p.parse_args()
    collect(region=args.region, days=args.days)


if __name__ == "__main__":
    main()
