#!/usr/bin/env python3
"""
generate_config.py — Terraform output → platform.yaml 자동 생성

terraform apply 후 한 번 실행하면 platform.yaml 이 자동으로 만들어진다.
이후 모든 Python 스크립트가 platform.yaml 에서 설정을 읽는다.

사용 예:
    python scripts/generate_config.py
    python scripts/generate_config.py --tf-dir terraform/
    python scripts/generate_config.py --dry-run   # 출력만 확인
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ROOT     = Path(__file__).resolve().parent.parent
TF_DIR   = ROOT / "terraform"
OUT_FILE = ROOT / "platform.yaml"
EXAMPLE  = ROOT / "platform.yaml.example"


def _tf_output(tf_dir: Path) -> dict:
    """terraform output -json 실행 후 파싱."""
    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=tf_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
        if result.returncode != 0:
            print(f"[generate_config] terraform output 실패:\n{result.stderr}", file=sys.stderr)
            return {}
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("[generate_config] terraform CLI 없음 — PATH 확인", file=sys.stderr)
        return {}
    except json.JSONDecodeError as e:
        print(f"[generate_config] JSON 파싱 오류: {e}", file=sys.stderr)
        return {}


def _aws_account_id() -> str:
    """boto3 또는 CLI로 현재 계정 ID 조회."""
    try:
        import boto3
        return boto3.client("sts").get_caller_identity()["Account"]
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def _aws_waf_acl_name(region: str, project_name: str) -> str:
    """WAF WebACL 이름 조회 (project_name-web-acl 패턴 우선)."""
    try:
        import boto3
        waf = boto3.client("wafv2", region_name=region)
        acls = waf.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
        # project_name 포함된 ACL 우선
        for acl in acls:
            if project_name in acl["Name"]:
                return acl["Name"]
        if acls:
            return acls[0]["Name"]
    except Exception:
        pass
    return f"{project_name}-web-acl"


def _build_config(tf_out: dict, region: str, account_id: str, project_name: str, env: str) -> str:
    """tf output dict로 platform.yaml 내용 생성."""
    def _val(key: str, fallback: str = "") -> str:
        v = tf_out.get(key, {}).get("value", fallback)
        return str(v) if v else fallback

    alb_dns      = _val("alb_dns_name")
    analysis_ip  = _val("analysis_public_ip")
    waf_bucket   = _val("waf_logs_bucket",      f"aws-waf-logs-{project_name}-{env}")
    audit_bkt    = _val("audit_evidence_bucket", f"{project_name}-audit-evidence-{env}")
    alb_bkt      = f"{project_name}-alb-logs-{env}"
    ct_bkt       = f"{project_name}-cloudtrail-{env}"
    trail_name   = f"{project_name}-trail"
    waf_acl      = _aws_waf_acl_name(region, project_name)

    # 선택 항목은 기존 platform.yaml에서 보존
    slack = discord = github = abuseipdb = ""
    ssh_key = "~/.ssh/cloud-sec-key2"
    if OUT_FILE.exists():
        try:
            import yaml
            existing = yaml.safe_load(OUT_FILE.read_text(encoding="utf-8")) or {}
            intg = existing.get("integrations", {})
            slack     = intg.get("slack_webhook", "")
            discord   = intg.get("discord_webhook", "")
            github    = intg.get("github_repo", "")
            abuseipdb = intg.get("abuseipdb_key", "")
            srvs = existing.get("servers", {})
            ssh_key     = srvs.get("ssh_key", ssh_key)
            analysis_ip = analysis_ip or srvs.get("analysis_ip", "")
        except Exception:
            pass

    # 환경변수 우선
    slack       = os.getenv("SLACK_WEBHOOK_URL",   slack)
    discord     = os.getenv("DISCORD_WEBHOOK_URL", discord)
    github      = os.getenv("GITHUB_REPOSITORY",   github)
    abuseipdb   = os.getenv("ABUSEIPDB_API_KEY",   abuseipdb)
    analysis_ip = os.getenv("ANALYSIS_SERVER_IP",  analysis_ip)

    return f"""\
# Cloud Security Platform — 자동 생성된 환경 설정
# generate_config.py 로 생성됨 — 직접 수정 가능
# 이 파일은 .gitignore 에 포함됨 (계정 정보 보호)

aws:
  region: {region}
  account_id: "{account_id}"

project:
  name: {project_name}
  environment: {env}

buckets:
  waf_logs: {waf_bucket}
  audit_evidence: {audit_bkt}
  alb_logs: {alb_bkt}
  cloudtrail: {ct_bkt}

waf:
  acl_name: {waf_acl}

alb:
  dns_name: {alb_dns}

cloudtrail:
  trail_name: {trail_name}

servers:
  analysis_ip: {analysis_ip}
  ssh_user: ec2-user
  ssh_key: {ssh_key}

integrations:
  slack_webhook: "{slack}"
  discord_webhook: "{discord}"
  github_repo: "{github}"
  abuseipdb_key: "{abuseipdb}"
"""


def main():
    p = argparse.ArgumentParser(description="Terraform output → platform.yaml 자동 생성")
    p.add_argument("--tf-dir",      default=str(TF_DIR), help="terraform 디렉토리")
    p.add_argument("--region",      default="ap-northeast-2")
    p.add_argument("--project",     default="cloud-sec",  help="project_name (tfvars와 동일)")
    p.add_argument("--env",         default="dev",        help="environment (dev/staging/prod)")
    p.add_argument("--dry-run",     action="store_true",  help="파일 저장 없이 출력만")
    args = p.parse_args()

    print("[generate_config] terraform output 조회 중...")
    tf_out = _tf_output(Path(args.tf_dir))
    if not tf_out:
        print("[generate_config] terraform output 없음 - 기본값으로 진행")

    print("[generate_config] 계정 ID 조회 중...")
    account_id = _aws_account_id()
    if account_id:
        print(f"[generate_config] 계정 ID: {account_id}")
    else:
        print("[generate_config] 계정 ID 조회 실패 — platform.yaml에서 직접 수정 필요")

    content = _build_config(tf_out, args.region, account_id, args.project, args.env)

    if args.dry_run:
        print("\n" + "=" * 60)
        print(content)
        return

    OUT_FILE.write_text(content, encoding="utf-8")
    print(f"[generate_config] 저장 완료: {OUT_FILE}")
    print("[generate_config] 다음 단계: python scripts/run_pipeline.py")


if __name__ == "__main__":
    main()
