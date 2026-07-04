#!/usr/bin/env python3
"""
collect_s3_security.py — S3 버킷 전체 보안 감사 (ISMS-P 2.6/2.7/2.8/2.9)

계정 내 모든 S3 버킷에 대해 다음 항목을 점검한다:
  - Public Access Block (퍼블릭 차단 4개 항목)
  - 서버사이드 암호화 (SSE-KMS / SSE-S3 / 없음)
  - 버전 관리 활성화 여부
  - 액세스 로깅 설정 여부
  - CORS 설정 여부
  - 생명주기 정책 규칙 수

ISMS-P 매핑:
  2.6  접근통제 — 퍼블릭 액세스 차단
  2.7  암호화    — SSE-KMS 적용 여부
  2.8  가용성   — 버전 관리 / 생명주기
  2.9  변경관리  — 액세스 로깅

출력: compliance/input/s3_security.json

사용 예:
  python scripts/collect_s3_security.py
  python scripts/collect_s3_security.py --region ap-northeast-2
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg
except Exception:
    def cfg(p, d=None): return d

OUTPUT_DIR = ROOT / "compliance" / "input"

DEFAULT_REGION = cfg("aws.region", "ap-northeast-2")


def _client(service, region):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_s3] boto3가 필요합니다: pip install boto3")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _save(data):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUTPUT_DIR / "s3_security.json"
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return out


def _check_public_access_block(s3, bucket):
    try:
        resp = s3.get_public_access_block(Bucket=bucket)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        block = {
            "BlockPublicAcls":      cfg.get("BlockPublicAcls", False),
            "IgnorePublicAcls":     cfg.get("IgnorePublicAcls", False),
            "BlockPublicPolicy":    cfg.get("BlockPublicPolicy", False),
            "RestrictPublicBuckets": cfg.get("RestrictPublicBuckets", False),
        }
        fully_blocked = all(block.values())
        return block, "PASS" if fully_blocked else "FAIL", (
            [] if fully_blocked else ["퍼블릭 액세스 차단 미완료 항목 있음 (ISMS-P 2.6)"]
        )
    except Exception as e:
        if "NoSuchPublicAccessBlockConfiguration" in str(e):
            block = {k: False for k in
                     ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]}
            return block, "FAIL", ["퍼블릭 액세스 차단 전혀 미설정 (ISMS-P 2.6)"]
        return {"error": str(e)}, "ERROR", []


def _check_encryption(s3, bucket):
    try:
        resp = s3.get_bucket_encryption(Bucket=bucket)
        rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        sse = rules[0].get("ApplyServerSideEncryptionByDefault", {}) if rules else {}
        algo = sse.get("SSEAlgorithm", "")
        enc = {"SSEAlgorithm": algo or "none", "KMSMasterKeyID": sse.get("KMSMasterKeyID")}
        if algo == "aws:kms":
            return enc, "PASS", []
        elif algo:
            return enc, "WARN", ["SSE-S3(AES256) 적용 중 — CMK(SSE-KMS) 전환 권고 (ISMS-P 2.7)"]
        else:
            return enc, "FAIL", ["버킷 암호화 미설정 (ISMS-P 2.7)"]
    except Exception as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            return {"SSEAlgorithm": "none"}, "FAIL", ["버킷 암호화 미설정 (ISMS-P 2.7)"]
        return {"error": str(e)}, "ERROR", []


def _check_versioning(s3, bucket):
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket)
        status = resp.get("Status", "Disabled")
        ver = {"Status": status}
        if status == "Enabled":
            return ver, "PASS", []
        return ver, "WARN", ["버전 관리 비활성 — 삭제/덮어쓰기 복구 불가 (ISMS-P 2.8)"]
    except Exception as e:
        return {"error": str(e)}, "ERROR", []


def _check_logging(s3, bucket):
    try:
        resp = s3.get_bucket_logging(Bucket=bucket)
        cfg = resp.get("LoggingEnabled", {})
        log = {
            "enabled": bool(cfg),
            "target_bucket": cfg.get("TargetBucket"),
            "target_prefix": cfg.get("TargetPrefix"),
        }
        if cfg:
            return log, "PASS", []
        return log, "WARN", ["액세스 로깅 미설정 — 접근 기록 없음 (ISMS-P 2.9)"]
    except Exception as e:
        return {"error": str(e)}, "ERROR", []


def _check_cors(s3, bucket):
    try:
        resp = s3.get_bucket_cors(Bucket=bucket)
        rules = resp.get("CORSRules", [])
        origins = [o for r in rules for o in r.get("AllowedOrigins", [])]
        wildcard = any(o == "*" for o in origins)
        return {
            "enabled": True,
            "rules_count": len(rules),
            "wildcard_origin": wildcard,
        }, ("WARN" if wildcard else "INFO"), (
            ["CORS 와일드카드(*) origin 허용 — 크로스오리진 노출 위험 (ISMS-P 2.6)"] if wildcard else []
        )
    except Exception as e:
        if "NoSuchCORSConfiguration" in str(e):
            return {"enabled": False}, "PASS", []
        return {"error": str(e)}, "ERROR", []


def _check_lifecycle(s3, bucket):
    try:
        resp = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        rules = resp.get("Rules", [])
        return {"rules_count": len(rules)}, "PASS", []
    except Exception as e:
        if "NoSuchLifecycleConfiguration" in str(e):
            return {"rules_count": 0}, "WARN", ["생명주기 정책 없음 — 오래된 데이터 자동 정리 불가 (ISMS-P 2.8)"]
        return {"error": str(e)}, "ERROR", []


def _check_bucket(s3, bucket_name):
    issues = []
    verdict_priority = {"PASS": 0, "INFO": 1, "WARN": 2, "FAIL": 3, "ERROR": 4}
    worst = "PASS"

    def _merge(v):
        nonlocal worst
        if verdict_priority.get(v, 0) > verdict_priority.get(worst, 0):
            worst = v

    pub, v1, i1 = _check_public_access_block(s3, bucket_name)
    enc, v2, i2 = _check_encryption(s3, bucket_name)
    ver, v3, i3 = _check_versioning(s3, bucket_name)
    log, v4, i4 = _check_logging(s3, bucket_name)
    cors, v5, i5 = _check_cors(s3, bucket_name)
    lc, v6, i6 = _check_lifecycle(s3, bucket_name)

    for v, i in [(v1, i1), (v2, i2), (v3, i3), (v4, i4), (v5, i5), (v6, i6)]:
        _merge(v)
        issues.extend(i)

    return {
        "bucket": bucket_name,
        "checked_at": _now(),
        "verdict": worst,
        "issues": issues,
        "public_access_block": {"config": pub, "status": v1},
        "encryption": {"config": enc, "status": v2},
        "versioning": {"config": ver, "status": v3},
        "logging": {"config": log, "status": v4},
        "cors": {"config": cors, "status": v5},
        "lifecycle": {"config": lc, "status": v6},
    }


def collect(region=DEFAULT_REGION):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    s3 = _client("s3", region)

    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except Exception as e:
        print(f"[collect_s3] 버킷 목록 조회 실패: {e}")
        result = {
            "checked_at": _now(), "total_buckets": 0,
            "overall": "ERROR", "error": str(e), "buckets": [],
        }
        _save(result)
        return result

    print(f"[collect_s3] 총 {len(buckets)}개 버킷 감사 중...")
    results = []
    for bucket in buckets:
        r = _check_bucket(s3, bucket)
        verdict_icon = {"PASS": "✔", "WARN": "!", "FAIL": "✘", "ERROR": "?", "INFO": "i"}.get(r["verdict"], "?")
        print(f"  [{verdict_icon}] {bucket} → {r['verdict']}")
        for issue in r["issues"]:
            print(f"      - {issue}")
        results.append(r)

    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in ["PASS", "WARN", "FAIL", "ERROR"]}
    overall = "FAIL" if counts["FAIL"] > 0 else ("WARN" if counts["WARN"] > 0 else "PASS")

    summary = {
        "checked_at": _now(),
        "region": region,
        "total_buckets": len(results),
        "pass": counts["PASS"],
        "warn": counts["WARN"],
        "fail": counts["FAIL"],
        "overall": overall,
        "isms_p_mapping": {
            "2.6": "접근통제 — 퍼블릭 액세스 차단, CORS 와일드카드",
            "2.7": "암호화    — SSE-KMS 적용 여부",
            "2.8": "가용성   — 버전 관리, 생명주기 정책",
            "2.9": "변경관리  — 액세스 로깅",
        },
        "buckets": results,
    }

    out = _save(summary)
    print(f"[collect_s3] 저장: {out.name}")
    print(f"  결과: PASS={counts['PASS']} WARN={counts['WARN']} FAIL={counts['FAIL']}")
    print(f"  전체 판정: {overall}")
    print("[collect_s3] 완료")
    return summary


def main():
    p = argparse.ArgumentParser(description="S3 버킷 전체 보안 감사 → compliance/input/s3_security.json")
    p.add_argument("--region", default=DEFAULT_REGION, help="AWS 리전 (기본: ap-northeast-2)")
    args = p.parse_args()
    collect(region=args.region)


if __name__ == "__main__":
    main()
