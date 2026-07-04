#!/usr/bin/env python3
"""
collect_prowler.py — Prowler AWS 보안 점검 수집기

Prowler CLI를 실행해서 ISMS-P 2.5(MFA/root), 2.10(drift) 관련
점검 결과를 compliance/input/prowler_report.json으로 저장한다.

Prowler 없을 때는 boto3로 직접 주요 항목을 점검한다 (경량 fallback).

사용 예:
  python scripts/collect_prowler.py              # fallback 모드 (boto3 직접)
  python scripts/collect_prowler.py --use-cli    # Prowler CLI 실행
  python scripts/collect_prowler.py --region ap-northeast-2
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg
except Exception:
    def cfg(p, d=None): return d

OUTPUT_FILE    = ROOT / "compliance" / "input" / "prowler_report.json"
DEFAULT_REGION = cfg("aws.region", "ap-northeast-2")


def _boto3_client(service, region):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_prowler] boto3가 설치되지 않았습니다: pip install boto3")


def _check_via_boto3(region):
    """Prowler 없을 때 boto3로 핵심 항목만 직접 점검."""
    print("[collect_prowler] boto3 경량 점검 모드")
    findings = []
    now = datetime.now(timezone.utc).isoformat()

    # ── IAM: 루트 MFA 확인 (ISMS 2.5) ─────────────────────────
    try:
        iam = _boto3_client("iam", region)
        summary = iam.get_account_summary()["SummaryMap"]
        root_mfa = summary.get("AccountMFAEnabled", 0)
        findings.append({
            "check_id": "iam_root_mfa_enabled",
            "service": "iam",
            "status": "PASS" if root_mfa else "FAIL",
            "severity": "critical",
            "resource_arn": "arn:aws:iam::root",
            "region": "global",
            "status_extended": f"루트 계정 MFA {'활성화' if root_mfa else '비활성화'} 상태",
            "checked_at": now,
        })
        print(f"  [+] iam_root_mfa_enabled: {'PASS' if root_mfa else 'FAIL'}")
    except Exception as e:
        print(f"  [!] iam_root_mfa_enabled 점검 실패: {e}")

    # ── IAM: 루트 최근 사용 여부 (ISMS 2.5) ────────────────────
    try:
        iam = _boto3_client("iam", region)
        cred_report = None
        try:
            iam.generate_credential_report()
        except Exception:
            pass
        import time; time.sleep(2)
        try:
            resp = iam.get_credential_report()
            content = resp["Content"].decode("utf-8")
            root_line = next((l for l in content.splitlines() if l.startswith("<root-account>")), None)
            if root_line:
                cols = root_line.split(",")
                # 컬럼: user,arn,user_creation_time,password_enabled,password_last_used,...
                password_last_used = cols[4] if len(cols) > 4 else "N/A"
                root_used_recently = password_last_used not in ("N/A", "no_information", "not_supported", "")
                findings.append({
                    "check_id": "iam_root_last_used",
                    "service": "iam",
                    "status": "FAIL" if root_used_recently else "PASS",
                    "severity": "high",
                    "resource_arn": "arn:aws:iam::root",
                    "region": "global",
                    "status_extended": f"루트 계정 마지막 사용: {password_last_used}",
                    "checked_at": now,
                })
                print(f"  [+] iam_root_last_used: {'FAIL' if root_used_recently else 'PASS'}")
        except Exception:
            pass
    except Exception as e:
        print(f"  [!] iam_root_last_used 점검 실패: {e}")

    # ── WAF: WebACL 존재 확인 (ISMS 2.11 / PCI e1) ─────────────
    try:
        wafv2 = _boto3_client("wafv2", region)
        acls = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        has_acl = len(acls) > 0
        findings.append({
            "check_id": "wafv2_webacl_exists",
            "service": "wafv2",
            "status": "PASS" if has_acl else "FAIL",
            "severity": "high",
            "resource_arn": acls[0].get("ARN", "N/A") if acls else "N/A",
            "region": region,
            "status_extended": f"WebACL {len(acls)}개 탐지",
            "checked_at": now,
        })
        print(f"  [+] wafv2_webacl_exists: {'PASS' if has_acl else 'FAIL'} ({len(acls)}개)")
    except Exception as e:
        print(f"  [!] wafv2_webacl_exists 점검 실패: {e}")

    # ── S3: WAF 로그 버킷 암호화 확인 (ISMS 2.7) ────────────────
    try:
        s3 = _boto3_client("s3", region)
        buckets = s3.list_buckets().get("Buckets", [])
        waf_buckets = [b["Name"] for b in buckets if "waf" in b["Name"].lower() or "cloud-sec" in b["Name"].lower()]
        for bucket_name in waf_buckets[:3]:
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                sse = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "none") if rules else "none"
                is_kms = sse in ("aws:kms", "aws:kms:dsse")
                findings.append({
                    "check_id": "s3_bucket_encryption",
                    "service": "s3",
                    "status": "PASS" if is_kms else "WARN",
                    "severity": "medium",
                    "resource_arn": f"arn:aws:s3:::{bucket_name}",
                    "region": region,
                    "status_extended": f"{bucket_name}: SSE={sse}",
                    "checked_at": now,
                })
                print(f"  [+] s3_bucket_encryption ({bucket_name}): {sse}")
            except Exception:
                pass
    except Exception as e:
        print(f"  [!] s3_bucket_encryption 점검 실패: {e}")

    # ── CloudTrail: log file validation (ISMS 2.9) ──────────────
    try:
        ct = _boto3_client("cloudtrail", region)
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        for trail in trails:
            validation = trail.get("LogFileValidationEnabled", False)
            findings.append({
                "check_id": "cloudtrail_log_validation",
                "service": "cloudtrail",
                "status": "PASS" if validation else "FAIL",
                "severity": "medium",
                "resource_arn": trail.get("TrailARN", "N/A"),
                "region": region,
                "status_extended": f"{trail.get('Name')}: log validation {'ON' if validation else 'OFF'}",
                "checked_at": now,
            })
            print(f"  [+] cloudtrail_log_validation ({trail.get('Name')}): {'PASS' if validation else 'FAIL'}")
    except Exception as e:
        print(f"  [!] cloudtrail_log_validation 점검 실패: {e}")

    return findings


def _check_via_prowler_cli(region):
    """Prowler CLI가 설치된 경우 실행."""
    print("[collect_prowler] Prowler CLI 실행 중...")
    checks = [
        "iam_root_mfa_enabled",
        "iam_root_credentials_usage",
        "wafv2_webacl_rule_attached",
        "s3_bucket_default_encryption",
        "cloudtrail_log_file_validation_enabled",
        "kms_cmk_rotation_enabled",
    ]
    cmd = [
        "prowler", "aws",
        "--region", region,
        "--checks", ",".join(checks),
        "--output-formats", "json",
        "--output-directory", str(ROOT / "compliance" / "input"),
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[collect_prowler] Prowler CLI 실패: {result.stderr[:300]}")
        return None

    # Prowler JSON 출력 파일 탐색
    candidates = sorted((ROOT / "compliance" / "input").glob("prowler-output*.json"))
    if candidates:
        data = json.loads(candidates[-1].read_text(encoding="utf-8"))
        findings = data if isinstance(data, list) else data.get("findings", [])
        return findings
    return None


def collect(region=DEFAULT_REGION, use_cli=False):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if use_cli:
        findings = _check_via_prowler_cli(region)
        if findings is None:
            print("[collect_prowler] CLI 실패, boto3 fallback으로 전환")
            findings = _check_via_boto3(region)
    else:
        findings = _check_via_boto3(region)

    OUTPUT_FILE.write_text(
        json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n[collect_prowler] 저장: {OUTPUT_FILE} ({len(findings)}건)")
    pass_count = sum(1 for f in findings if f.get("status") == "PASS")
    fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
    print(f"  PASS: {pass_count}  FAIL: {fail_count}  WARN: {len(findings)-pass_count-fail_count}")
    print("[collect_prowler] 완료")


def main():
    p = argparse.ArgumentParser(description="Prowler 보안 점검 수집 → compliance/input/")
    p.add_argument("--region",  default=DEFAULT_REGION)
    p.add_argument("--use-cli", action="store_true", help="Prowler CLI 사용 (미설치 시 boto3 fallback)")
    args = p.parse_args()
    collect(region=args.region, use_cli=args.use_cli)


if __name__ == "__main__":
    main()
