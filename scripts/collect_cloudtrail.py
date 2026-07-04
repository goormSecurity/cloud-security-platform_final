#!/usr/bin/env python3
"""
collect_cloudtrail.py — AWS CloudTrail 변경 이력 수집기

boto3로 CloudTrail에서 WAF 관련 변경 이벤트를 조회하고
compliance/input/cloudtrail_events.json 으로 저장한다.

대상 이벤트:
  - UpdateWebACL, CreateWebACL, DeleteWebACL (WAF 변경)
  - UpdateIPSet, CreateIPSet, DeleteIPSet
  - PutBucketEncryption, PutObjectLockConfiguration (증적 버킷)
  - ConsoleLogin (루트 로그인 감시)

사용 예:
  python scripts/collect_cloudtrail.py
  python scripts/collect_cloudtrail.py --days 30
  python scripts/collect_cloudtrail.py --region ap-northeast-2
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

OUTPUT_FILE = ROOT / "compliance" / "input" / "cloudtrail_events.json"

DEFAULT_REGION = cfg("aws.region", "ap-northeast-2")
DEFAULT_DAYS   = 14

TARGET_EVENTS = [
    # WAF 변경 관리 (PCI e4 / ISMS 2.9)
    "UpdateWebACL", "CreateWebACL", "DeleteWebACL",
    "UpdateIPSet", "CreateIPSet", "DeleteIPSet",
    "UpdateRuleGroup", "CreateRuleGroup", "DeleteRuleGroup",
    # S3 증적 버킷 설정 변경 (ISMS 2.7 / 4장 무결성)
    "PutBucketEncryption", "PutObjectLockConfiguration",
    "PutBucketLifecycleConfiguration",
    # IAM / 루트 접근 (ISMS 2.5)
    "ConsoleLogin",
    "CreateAccessKey", "DeleteAccessKey",
    # KMS (ISMS 2.7)
    "CreateKey", "ScheduleKeyDeletion", "DisableKey",
]


def _boto3_client(service, region):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_cloudtrail] boto3가 설치되지 않았습니다: pip install boto3")


def collect(region=DEFAULT_REGION, days=DEFAULT_DAYS):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    ct = _boto3_client("cloudtrail", region)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    print(f"[collect_cloudtrail] 기간: {start_time.date()} ~ {end_time.date()} ({days}일)")
    print(f"[collect_cloudtrail] 대상 이벤트: {len(TARGET_EVENTS)}종")

    all_events = []
    for event_name in TARGET_EVENTS:
        try:
            paginator = ct.get_paginator("lookup_events")
            pages = paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start_time,
                EndTime=end_time,
            )
            for page in pages:
                for evt in page.get("Events", []):
                    # CloudTrail Event 객체를 직렬화 가능하게 변환
                    parsed = {
                        "eventID": evt.get("EventId"),
                        "eventName": evt.get("EventName"),
                        "eventTime": evt.get("EventTime").isoformat() if evt.get("EventTime") else None,
                        "eventSource": evt.get("EventSource"),
                        "username": evt.get("Username"),
                        "resources": [
                            {"resourceType": r.get("ResourceType"), "resourceName": r.get("ResourceName")}
                            for r in evt.get("Resources", [])
                        ],
                    }
                    # CloudTrailEvent 필드 파싱 (JSON 문자열)
                    raw_str = evt.get("CloudTrailEvent", "{}")
                    try:
                        raw = json.loads(raw_str)
                        parsed["userIdentity"] = raw.get("userIdentity", {})
                        parsed["requestParameters"] = raw.get("requestParameters", {})
                        parsed["sourceIPAddress"] = raw.get("sourceIPAddress")
                        parsed["errorCode"] = raw.get("errorCode")
                        parsed["errorMessage"] = raw.get("errorMessage")
                    except Exception:
                        pass
                    all_events.append(parsed)
        except Exception as e:
            print(f"[collect_cloudtrail] {event_name} 조회 실패: {e}")

    # 시간 역순 정렬
    all_events.sort(key=lambda e: e.get("eventTime") or "", reverse=True)

    OUTPUT_FILE.write_text(
        json.dumps(all_events, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[collect_cloudtrail] 저장: {OUTPUT_FILE} ({len(all_events)}건)")
    print("[collect_cloudtrail] 완료")


def main():
    p = argparse.ArgumentParser(description="CloudTrail WAF 변경 이력 수집 → compliance/input/")
    p.add_argument("--region", default=DEFAULT_REGION)
    p.add_argument("--days",   default=DEFAULT_DAYS, type=int, help="수집 기간 (일)")
    args = p.parse_args()
    collect(region=args.region, days=args.days)


if __name__ == "__main__":
    main()
