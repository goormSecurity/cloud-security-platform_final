#!/usr/bin/env python3
import json

d = json.load(open("compliance/real_data.json", encoding="utf-8"))

print("=== 최종 판정 ===")
print("판정:", d["meta"]["final_verdict"])
print("총 요청:", d["meta"]["total_requests"], "건")
print("최고위험 IP:", d["event"]["source_ip"], "/", d["event"]["ai"]["attack_type"])
print("WAF 액션:", d["event"]["waf_action"])

print("\n=== PCI DSS (e1~e5) ===")
for k, v in d["compliance"]["pci"].items():
    print(f"  {k}: {v['verdict']}")

print("\n=== ISMS-P (2.5~2.11) ===")
for k, v in d["compliance"]["ismsp"].items():
    print(f"  {k}: {v['verdict']}")

print("\n=== 인프라 보안 현황 ===")
ol = d["posture"]["s3_lifecycle"]
kms = d["posture"]["kms_key"]
cfg = d["posture"]["config_diff"]
enc = d["posture"]["s3_encryption"]

print(f"  S3 암호화: {enc['ServerSideEncryption']} ({enc['status']})")
print(f"  KMS CMK : {kms['status']}")
print(f"  Object Lock: {ol['object_lock_enabled']} / {ol['mode']} / {ol.get('retention_days')}일 ({ol['status']})")
print(f"  Config 드리프트: recorder={cfg['recorder_status']} / drift={cfg['drift_detected']}")

print("\n=== 권고사항 ===")
for r in d["recommendations"]:
    if isinstance(r, dict):
        print(f"  [{r.get('trigger','')}] {r.get('item','')}")
    else:
        print(f"  {str(r)[:80]}")

print("\n=== 소스 커버리지 ===")
for k, v in d["_sources"].items():
    mark = "+" if v else "-"
    print(f"  [{mark}] {k}: {v.split(chr(92))[-1] if v else '없음'}")
