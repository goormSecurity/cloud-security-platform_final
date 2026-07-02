#!/usr/bin/env python3
"""
collect_cmk.py — CMK + Object Lock 증적 수집기 (ISMS-P 2.7)

WAF 로그 버킷의 암호화 현황, KMS 키 상태, Object Lock 설정을 수집하여
ISMS-P 2.7 무결성 증적 파일을 생성한다.

출력 (compliance/input/):
  bucket_encryption.json   — SSE 알고리즘, KMS 키 ID
  kms_key.json             — 키 ARN, 상태, 관리자
  kms_rotation.json        — 자동 회전 여부
  kms_key_policy.json      — 키 정책
  object_lock_config.json  — Object Lock COMPLIANCE 설정
  object_head.json         — 최신 오브젝트 헤더 (무결성 샘플)

사용 예:
  python scripts/collect_cmk.py
  python scripts/collect_cmk.py --bucket aws-waf-logs-cloud-sec-dev
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg, waf_log_prefix
except Exception:
    def cfg(p, d=None): return d
    def waf_log_prefix(): return ""

OUTPUT_DIR = ROOT / "compliance" / "input"

DEFAULT_BUCKET        = cfg("buckets.waf_logs",       "aws-waf-logs-cloud-sec-dev")
AUDIT_EVIDENCE_BUCKET = cfg("buckets.audit_evidence", "cloud-sec-audit-evidence-dev")
DEFAULT_REGION        = cfg("aws.region",              "ap-northeast-2")
DEFAULT_PREFIX        = (waf_log_prefix() or "AWSLogs//WAFLogs//") + "/"


def _client(service, region):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_cmk] boto3가 필요합니다: pip install boto3")


def _save(name, data):
    path = OUTPUT_DIR / name
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"  [+] 저장: {path.name}")
    return data


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── 1. S3 버킷 암호화 ────────────────────────────────────────────
def collect_bucket_encryption(s3, bucket):
    try:
        resp = s3.get_bucket_encryption(Bucket=bucket)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        sse   = rules[0].get("ApplyServerSideEncryptionByDefault", {}) if rules else {}
        result = {
            "bucket": bucket,
            "checked_at": _now(),
            "SSEAlgorithm": sse.get("SSEAlgorithm", "none"),
            "KMSMasterKeyID": sse.get("KMSMasterKeyID"),
            "BucketKeyEnabled": rules[0].get("BucketKeyEnabled", False) if rules else False,
            "status": "PASS" if sse.get("SSEAlgorithm") else "FAIL",
            "note": "SSE-KMS 미적용 — audit-evidence 버킷에 CMK 적용 권고"
                    if sse.get("SSEAlgorithm") != "aws:kms" else "",
        }
    except Exception as e:
        result = {
            "bucket": bucket,
            "checked_at": _now(),
            "SSEAlgorithm": "none",
            "KMSMasterKeyID": None,
            "error": str(e),
            "status": "FAIL",
        }
    return _save("bucket_encryption.json", result)


# ── 2. KMS 키 상세 ───────────────────────────────────────────────
def collect_kms_key(kms, kms_key_id=None):
    if not kms_key_id:
        try:
            aliases = kms.list_aliases().get("Aliases", [])
            waf_alias = next(
                (a for a in aliases
                 if "waf" in a.get("AliasName", "").lower()
                 or "cloud-sec" in a.get("AliasName", "").lower()),
                None,
            )
            if waf_alias:
                kms_key_id = waf_alias.get("TargetKeyId")
        except Exception:
            pass

    if not kms_key_id:
        result = {
            "checked_at": _now(),
            "status": "NOT_FOUND",
            "note": "WAF 관련 CMK 없음 — audit-evidence 버킷 생성 시 CMK 구성 필요 (ISMS-P 2.7.2)",
            "KeyId": None, "KeyArn": None, "KeyState": None, "KeyManager": None,
        }
        return _save("kms_key.json", result)

    try:
        meta = kms.describe_key(KeyId=kms_key_id).get("KeyMetadata", {})
        result = {
            "checked_at": _now(),
            "status": "PASS" if meta.get("Enabled") else "FAIL",
            "KeyId": meta.get("KeyId"),
            "KeyArn": meta.get("Arn"),
            "KeyState": meta.get("KeyState"),
            "Enabled": meta.get("Enabled"),
            "KeyManager": meta.get("KeyManager"),
            "MultiRegion": meta.get("MultiRegion", False),
            "Description": meta.get("Description", ""),
        }
    except Exception as e:
        result = {"checked_at": _now(), "status": "ERROR", "error": str(e), "KeyId": kms_key_id}
    return _save("kms_key.json", result)


# ── 3. KMS 자동 회전 ─────────────────────────────────────────────
def collect_kms_rotation(kms, key_id):
    if not key_id:
        return _save("kms_rotation.json", {
            "checked_at": _now(), "KeyRotationEnabled": None, "status": "NOT_FOUND",
        })
    try:
        enabled = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)
        result = {
            "checked_at": _now(),
            "KeyId": key_id,
            "KeyRotationEnabled": enabled,
            "status": "PASS" if enabled else "WARN",
            "note": "" if enabled else "연간 자동 회전 비활성 — ISMS-P 2.7.2 접근통제 증적 필요",
        }
    except Exception as e:
        result = {"checked_at": _now(), "error": str(e), "status": "ERROR"}
    return _save("kms_rotation.json", result)


# ── 4. KMS 키 정책 ───────────────────────────────────────────────
def collect_kms_policy(kms, key_id):
    if not key_id:
        return _save("kms_key_policy.json", {
            "checked_at": _now(), "Policy": None, "status": "NOT_FOUND",
        })
    try:
        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "{}")
        result = {
            "checked_at": _now(),
            "KeyId": key_id,
            "PolicyName": "default",
            "Policy": json.loads(policy_str),
            "status": "PASS",
        }
    except Exception as e:
        result = {"checked_at": _now(), "error": str(e), "status": "ERROR"}
    return _save("kms_key_policy.json", result)


# ── 5. Object Lock 설정 ──────────────────────────────────────────
def collect_object_lock(s3, bucket):
    try:
        lock = s3.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration", {})
        rule = lock.get("Rule", {}).get("DefaultRetention", {})
        result = {
            "checked_at": _now(),
            "bucket": bucket,
            "ObjectLockEnabled": lock.get("ObjectLockEnabled", "Disabled"),
            "Mode": rule.get("Mode"),
            "Days": rule.get("Days"),
            "Years": rule.get("Years"),
            "status": "PASS" if lock.get("ObjectLockEnabled") == "Enabled" else "WARN",
            "note": "" if lock.get("ObjectLockEnabled") == "Enabled"
                    else "Object Lock 미적용 — audit-evidence 버킷 신규 생성 시 COMPLIANCE 모드 설정 필요 (1장 무결성)",
        }
    except Exception as e:
        err = str(e)
        if "ObjectLockConfigurationNotFoundError" in err or "does not have Object Lock" in err:
            result = {
                "checked_at": _now(),
                "bucket": bucket,
                "ObjectLockEnabled": "Disabled",
                "status": "WARN",
                "note": "Object Lock 미적용. COMPLIANCE 모드 신규 버킷 생성 필요.",
            }
        else:
            result = {"checked_at": _now(), "bucket": bucket, "error": err, "status": "ERROR"}
    return _save("object_lock_config.json", result)


# ── 6. Object Retention 설정 (개별 오브젝트 보존 기간) ──────────
def collect_object_retention(s3, bucket, prefix):
    """최신 오브젝트의 Object Retention 설정 수집 (4장 evidence_checks)."""
    now = _now()
    try:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=10)
        objects = sorted(
            resp.get("Contents", []),
            key=lambda x: x.get("LastModified", ""),
            reverse=True,
        )
        if not objects:
            return _save("object_retention.json", {
                "checked_at": now, "bucket": bucket, "status": "NO_OBJECTS",
            })
        obj = objects[0]
        try:
            ret = s3.get_object_retention(Bucket=bucket, Key=obj["Key"])
            retention = ret.get("Retention", {})
            result = {
                "checked_at": now,
                "bucket": bucket,
                "Key": obj["Key"],
                "Mode": retention.get("Mode"),
                "RetainUntilDate": (
                    retention.get("RetainUntilDate").isoformat()
                    if retention.get("RetainUntilDate") else None
                ),
                "status": "PASS" if retention.get("Mode") == "COMPLIANCE" else "WARN",
                "note": "" if retention.get("Mode") == "COMPLIANCE"
                        else "COMPLIANCE 모드 권고 (ISMS-P 2.7 무결성 보장)",
            }
        except Exception as e:
            err = str(e)
            if "NoSuchObjectLockConfiguration" in err or "InvalidRequest" in err:
                result = {
                    "checked_at": now,
                    "bucket": bucket,
                    "Key": obj["Key"],
                    "Mode": None,
                    "RetainUntilDate": None,
                    "status": "WARN",
                    "note": "Object Lock 미적용 — audit-evidence 버킷 신규 생성 시 COMPLIANCE 모드 설정 필요",
                }
            else:
                result = {"checked_at": now, "bucket": bucket, "error": err, "status": "ERROR"}
    except Exception as e:
        result = {"checked_at": now, "bucket": bucket, "error": str(e), "status": "ERROR"}
    return _save("object_retention.json", result)


# ── 7. 오브젝트 헤더 (무결성 샘플) ──────────────────────────────
def collect_object_head(s3, bucket, prefix):
    try:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=10)
        objects = sorted(
            resp.get("Contents", []),
            key=lambda x: x.get("LastModified", ""),
            reverse=True,
        )
        if not objects:
            return _save("object_head.json", {
                "checked_at": _now(), "bucket": bucket, "status": "NO_OBJECTS",
            })
        obj = objects[0]
        head = s3.head_object(Bucket=bucket, Key=obj["Key"])
        result = {
            "checked_at": _now(),
            "bucket": bucket,
            "Key": obj["Key"],
            "ServerSideEncryption": head.get("ServerSideEncryption"),
            "SSEKMSKeyId": head.get("SSEKMSKeyId"),
            "VersionId": head.get("VersionId"),
            "ContentLength": head.get("ContentLength"),
            "LastModified": head.get("LastModified").isoformat() if head.get("LastModified") else None,
            "status": "PASS" if head.get("ServerSideEncryption") else "WARN",
        }
    except Exception as e:
        result = {"checked_at": _now(), "bucket": bucket, "error": str(e), "status": "ERROR"}
    return _save("object_head.json", result)


# ── 메인 ─────────────────────────────────────────────────────────
def collect(bucket=DEFAULT_BUCKET, region=DEFAULT_REGION, prefix=DEFAULT_PREFIX):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[collect_cmk] WAF 로그 버킷: {bucket}")
    print(f"[collect_cmk] 증적 버킷   : {AUDIT_EVIDENCE_BUCKET}")

    s3  = _client("s3",  region)
    kms = _client("kms", region)

    # WAF 로그 버킷: 암호화 + KMS 키 증적
    enc        = collect_bucket_encryption(s3, bucket)
    kms_key_id = enc.get("KMSMasterKeyID")

    key_info = collect_kms_key(kms, kms_key_id)
    key_id   = key_info.get("KeyId") or kms_key_id

    collect_kms_rotation(kms, key_id)
    collect_kms_policy(kms, key_id)

    # audit-evidence 버킷: Object Lock COMPLIANCE 증적 (Terraform으로 별도 생성)
    collect_object_lock(s3, AUDIT_EVIDENCE_BUCKET)
    collect_object_retention(s3, AUDIT_EVIDENCE_BUCKET, "")
    collect_object_head(s3, AUDIT_EVIDENCE_BUCKET, "")

    print("[collect_cmk] 완료")


def main():
    p = argparse.ArgumentParser(description="CMK + Object Lock 증적 수집 → compliance/input/")
    p.add_argument("--bucket", default=DEFAULT_BUCKET)
    p.add_argument("--region", default=DEFAULT_REGION)
    args = p.parse_args()
    collect(bucket=args.bucket, region=args.region)


if __name__ == "__main__":
    main()
