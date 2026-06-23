#!/usr/bin/env python3
"""
collect_waf.py — AWS WAF v2 실데이터 수집기

boto3로 실제 WAF WebACL·IPSet·연결 리소스를 조회하고
raw/ 디렉토리에 저장한다.

출력:
  raw/waf_web_acl.json
  raw/waf_ipset.json
  raw/waf_resources.json

사용 예:
  python scripts/collect_waf.py
  python scripts/collect_waf.py --region ap-northeast-2 --acl-name cloud-sec-web-acl
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = ROOT / "raw"

# Terraform에 정의된 기본값
DEFAULT_REGION  = "ap-northeast-2"
DEFAULT_SCOPE   = "REGIONAL"
DEFAULT_ACL_NAME = "cloud-sec-web-acl"


def _boto3_client(service, region):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_waf] boto3가 설치되지 않았습니다: pip install boto3")


def collect(region=DEFAULT_REGION, scope=DEFAULT_SCOPE, acl_name=DEFAULT_ACL_NAME):
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    wafv2 = _boto3_client("wafv2", region)

    # ── 1. WebACL 목록에서 대상 찾기 ───────────────────────────
    print(f"[collect_waf] WAF WebACL 목록 조회 중... (region={region})")
    try:
        acls = wafv2.list_web_acls(Scope=scope).get("WebACLs", [])
    except Exception as e:
        sys.exit(f"[collect_waf] list_web_acls 실패: {e}")

    target = next((a for a in acls if a["Name"] == acl_name), None)
    if not target:
        names = [a["Name"] for a in acls]
        sys.exit(f"[collect_waf] '{acl_name}' WebACL을 찾을 수 없습니다. 발견된 ACL: {names}")

    acl_id = target["Id"]
    acl_arn = target["ARN"]
    print(f"[collect_waf] 대상 ACL: {acl_name} (Id={acl_id})")

    # ── 2. WebACL 상세 조회 ─────────────────────────────────────
    try:
        acl_detail = wafv2.get_web_acl(Name=acl_name, Scope=scope, Id=acl_id)
        acl_detail.pop("ResponseMetadata", None)
        out = RAW_DIR / "waf_web_acl.json"
        out.write_text(json.dumps(acl_detail, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(f"[collect_waf] 저장: {out}")
    except Exception as e:
        print(f"[collect_waf] get_web_acl 실패: {e}")

    # ── 3. IPSet 조회 (WebACL 룰에서 IPSet ARN 추출) ────────────
    try:
        rules = acl_detail.get("WebACL", {}).get("Rules", [])
        ipset_arn = None
        for rule in rules:
            stmt = rule.get("Statement", {})
            if "IPSetReferenceStatement" in stmt:
                ipset_arn = stmt["IPSetReferenceStatement"]["ARN"]
                break

        if ipset_arn:
            # ARN에서 name/id 파싱: .../ipset/name/id
            parts = ipset_arn.split("/")
            ipset_name = parts[-2]
            ipset_id   = parts[-1]
            ipset_detail = wafv2.get_ip_set(Name=ipset_name, Scope=scope, Id=ipset_id)
            ipset_detail.pop("ResponseMetadata", None)
        else:
            # IPSet이 룰에 없으면 list_ip_sets로 탐색
            ipsets = wafv2.list_ip_sets(Scope=scope).get("IPSets", [])
            if ipsets:
                first = ipsets[0]
                ipset_detail = wafv2.get_ip_set(Name=first["Name"], Scope=scope, Id=first["Id"])
                ipset_detail.pop("ResponseMetadata", None)
            else:
                ipset_detail = {"IPSet": {"Addresses": []}, "_note": "IPSet 없음"}

        out = RAW_DIR / "waf_ipset.json"
        out.write_text(json.dumps(ipset_detail, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        addrs = ipset_detail.get("IPSet", {}).get("Addresses", [])
        print(f"[collect_waf] 저장: {out} (차단 IP {len(addrs)}개)")
    except Exception as e:
        print(f"[collect_waf] IPSet 조회 실패: {e}")

    # ── 4. 연결 리소스 (ALB 등) ─────────────────────────────────
    try:
        resources = wafv2.list_resources_for_web_acl(WebACLArn=acl_arn)
        resources.pop("ResponseMetadata", None)
        out = RAW_DIR / "waf_resources.json"
        out.write_text(json.dumps(resources, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        arns = resources.get("ResourceArns", [])
        print(f"[collect_waf] 저장: {out} (연결 리소스 {len(arns)}개)")
    except Exception as e:
        print(f"[collect_waf] list_resources_for_web_acl 실패: {e}")

    print("[collect_waf] 완료")


def main():
    p = argparse.ArgumentParser(description="AWS WAF 실데이터 수집 → raw/")
    p.add_argument("--region",   default=DEFAULT_REGION)
    p.add_argument("--scope",    default=DEFAULT_SCOPE, choices=["REGIONAL", "CLOUDFRONT"])
    p.add_argument("--acl-name", default=DEFAULT_ACL_NAME)
    args = p.parse_args()
    collect(region=args.region, scope=args.scope, acl_name=args.acl_name)


if __name__ == "__main__":
    main()
