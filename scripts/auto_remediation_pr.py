#!/usr/bin/env python3
"""
auto_remediation_pr.py — 보안 취약점 수정 코드 자동 PR 생성

파이프라인 분석 결과(Prowler FAIL, Trivy CRITICAL, WAF Count 모드)를 읽어
구체적인 수정 코드(AWS CLI + Terraform 스니펫)를 포함한 GitHub PR을 자동으로 생성한다.

관리자가 PR 코드를 검토하고 승인(Merge)하면 수정 사항이 적용된다.

사용 예:
    python scripts/auto_remediation_pr.py
    python scripts/auto_remediation_pr.py --dry-run
    python scripts/auto_remediation_pr.py --min-severity high

환경 변수:
    GITHUB_TOKEN  GitHub Personal Access Token (scope: repo)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).parent.parent
BASE_BRANCH = "main"
API = "https://api.github.com"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _load_repo() -> str:
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    try:
        import yaml
        cfg = yaml.safe_load((ROOT / "platform.yaml").read_text(encoding="utf-8"))
        return cfg["integrations"]["github_repo"]
    except Exception:
        return "goormSecurity/cloud-security-platform_final"


REPO = _load_repo()


# ── GitHub API ────────────────────────────────────────────────────

def _gh(method: str, path: str, token: str, body: dict = None):
    url = f"{API}{path}"
    data = json.dumps(body).encode() if body else None
    req = Request(url, data=data, method=method)
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except HTTPError as e:
        body_bytes = e.read()
        try:
            msg = json.loads(body_bytes).get("message", "")
        except Exception:
            msg = body_bytes.decode()[:200]
        raise RuntimeError(f"GitHub {method} {path} → {e.code}: {msg}") from e


def _get_main_sha(token: str) -> str:
    ref = _gh("GET", f"/repos/{REPO}/git/ref/heads/{BASE_BRANCH}", token)
    return ref["object"]["sha"]


def _create_branch(branch: str, sha: str, token: str) -> bool:
    try:
        _gh("POST", f"/repos/{REPO}/git/refs", token, {"ref": f"refs/heads/{branch}", "sha": sha})
        return True
    except RuntimeError as e:
        if "already exists" in str(e):
            return True
        raise


def _push_file(branch: str, path: str, content: str, msg: str, token: str):
    encoded = base64.b64encode(content.encode()).decode()
    try:
        existing = _gh("GET", f"/repos/{REPO}/contents/{path}?ref={branch}", token)
        sha = existing.get("sha")
    except Exception:
        sha = None
    body = {"message": msg, "content": encoded, "branch": branch}
    if sha:
        body["sha"] = sha
    _gh("PUT", f"/repos/{REPO}/contents/{path}", token, body)


def _create_pr(branch: str, title: str, body: str, token: str) -> str:
    pr = _gh("POST", f"/repos/{REPO}/pulls", token, {
        "title": title, "body": body,
        "head": branch, "base": BASE_BRANCH,
    })
    return pr["html_url"]


def _open_remediation_prs(token: str) -> set:
    try:
        prs = _gh("GET", f"/repos/{REPO}/pulls?state=open&per_page=50", token)
        return {pr["head"]["ref"] for pr in prs
                if pr.get("head", {}).get("ref", "").startswith("auto/remediation-")}
    except Exception:
        return set()


# ── 데이터 로더 ────────────────────────────────────────────────────

def _load(p: Path):
    if p and p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _find_latest(pattern: str) -> Path | None:
    candidates = sorted((ROOT / "output").glob(pattern))
    return candidates[-1] if candidates else None


# ── Prowler 수정 코드 생성 ─────────────────────────────────────────

PROWLER_REMEDIATION = {
    "s3_bucket_encryption": {
        "title": "S3 버킷 KMS 암호화 전환",
        "severity": "medium",
        "why": "현재 SSE-S3(AES256) 암호화 적용 중. KMS CMK로 전환하면 키 로테이션·감사 추적이 가능.",
        "cli": lambda bucket, region: (
            f"# 1) KMS 키 생성 (이미 있으면 기존 Key ARN 사용)\n"
            f"KEY_ARN=$(aws kms create-key --description 's3-{bucket}' \\\n"
            f"  --region {region} --query KeyMetadata.Arn --output text)\n\n"
            f"# 2) 버킷 암호화 정책 KMS로 교체\n"
            f"aws s3api put-bucket-encryption \\\n"
            f"  --bucket {bucket} \\\n"
            f"  --server-side-encryption-configuration '{{\n"
            f'    "Rules": [{{"ApplyServerSideEncryptionByDefault": {{\n'
            f'      "SSEAlgorithm": "aws:kms",\n'
            f'      "KMSMasterKeyID": "\'$KEY_ARN\'"\n'
            f"    }}}}]\n"
            f"  }}' \\\n"
            f"  --region {region}"
        ),
        "tf": lambda bucket: (
            f'# terraform/s3_kms_encryption.tf\n'
            f'resource "aws_s3_bucket_server_side_encryption_configuration" "{bucket.replace("-","_")}_enc" {{\n'
            f'  bucket = "{bucket}"\n'
            f'  rule {{\n'
            f'    apply_server_side_encryption_by_default {{\n'
            f'      sse_algorithm     = "aws:kms"\n'
            f'      kms_master_key_id = aws_kms_key.s3_{bucket.replace("-","_")}.arn\n'
            f'    }}\n'
            f'    bucket_key_enabled = true\n'
            f'  }}\n'
            f'}}\n\n'
            f'resource "aws_kms_key" "s3_{bucket.replace("-","_")}" {{\n'
            f'  description             = "KMS key for S3 bucket {bucket}"\n'
            f'  deletion_window_in_days = 30\n'
            f'  enable_key_rotation     = true\n'
            f'}}'
        ),
    },
    "s3_bucket_versioning_enabled": {
        "title": "S3 버킷 버전 관리 활성화",
        "severity": "medium",
        "why": "버전 관리 미적용 버킷은 실수 삭제·랜섬웨어로 인한 데이터 손실에 취약.",
        "cli": lambda bucket, region: (
            f"aws s3api put-bucket-versioning \\\n"
            f"  --bucket {bucket} \\\n"
            f"  --versioning-configuration Status=Enabled \\\n"
            f"  --region {region}"
        ),
        "tf": lambda bucket: (
            f'resource "aws_s3_bucket_versioning" "{bucket.replace("-","_")}_ver" {{\n'
            f'  bucket = "{bucket}"\n'
            f'  versioning_configuration {{ status = "Enabled" }}\n'
            f'}}'
        ),
    },
    "cloudwatch_changes_to_vpcs_alarm_configured": {
        "title": "VPC 변경 감지 CloudWatch 알람 생성",
        "severity": "medium",
        "why": "VPC 구성 변경(보안 그룹·라우팅 테이블·인터넷 게이트웨이)을 실시간 감지하지 못하면 무단 네트워크 변경 탐지가 어려움.",
        "cli": lambda bucket, region: (
            f"# CloudTrail → CloudWatch Logs 연동이 선행되어야 합니다\n"
            f"aws cloudwatch put-metric-alarm \\\n"
            f"  --alarm-name 'vpc-changes-alarm' \\\n"
            f"  --alarm-description 'VPC 구성 변경 감지' \\\n"
            f"  --metric-name 'VPCChangeCount' \\\n"
            f"  --namespace 'CloudTrailMetrics' \\\n"
            f"  --statistic Sum \\\n"
            f"  --period 300 \\\n"
            f"  --threshold 1 \\\n"
            f"  --comparison-operator GreaterThanOrEqualToThreshold \\\n"
            f"  --evaluation-periods 1 \\\n"
            f"  --alarm-actions <SNS_TOPIC_ARN> \\\n"
            f"  --region {region}"
        ),
        "tf": lambda bucket: (
            f'resource "aws_cloudwatch_metric_alarm" "vpc_changes" {{\n'
            f'  alarm_name          = "vpc-changes-alarm"\n'
            f'  alarm_description   = "VPC 구성 변경 감지 (Prowler: cloudwatch_changes_to_vpcs_alarm_configured)"\n'
            f'  namespace           = "CloudTrailMetrics"\n'
            f'  metric_name         = "VPCChangeCount"\n'
            f'  statistic           = "Sum"\n'
            f'  period              = 300\n'
            f'  threshold           = 1\n'
            f'  comparison_operator = "GreaterThanOrEqualToThreshold"\n'
            f'  evaluation_periods  = 1\n'
            f'  alarm_actions       = [aws_sns_topic.security_alerts.arn]\n'
            f'}}'
        ),
    },
    "cloudtrail_log_file_validation_enabled": {
        "title": "CloudTrail 로그 파일 무결성 검증 활성화",
        "severity": "high",
        "why": "로그 파일 무결성 검증이 없으면 로그 변조·삭제를 사후에 탐지하기 어려움.",
        "cli": lambda bucket, region: (
            f"aws cloudtrail update-trail \\\n"
            f"  --name cloud-sec-trail \\\n"
            f"  --enable-log-file-validation \\\n"
            f"  --region {region}"
        ),
        "tf": lambda bucket: (
            f'# 기존 aws_cloudtrail 리소스에 아래 속성 추가\n'
            f'# enable_log_file_validation = true'
        ),
    },
    "vpc_flow_logs_enabled": {
        "title": "VPC Flow Logs 활성화",
        "severity": "medium",
        "why": "Flow Logs 없이는 비정상 트래픽·데이터 유출 경로를 사후 분석할 수 없음.",
        "cli": lambda bucket, region: (
            f"# VPC ID는 환경에 맞게 수정\n"
            f"VPC_ID=$(aws ec2 describe-vpcs --region {region} \\\n"
            f"  --filters Name=isDefault,Values=false \\\n"
            f"  --query 'Vpcs[0].VpcId' --output text)\n\n"
            f"aws ec2 create-flow-logs \\\n"
            f"  --resource-type VPC \\\n"
            f"  --resource-ids $VPC_ID \\\n"
            f"  --traffic-type ALL \\\n"
            f"  --log-destination-type cloud-watch-logs \\\n"
            f"  --log-group-name /aws/vpc/flow-logs \\\n"
            f"  --deliver-logs-permission-arn <FLOW_LOGS_ROLE_ARN> \\\n"
            f"  --region {region}"
        ),
        "tf": lambda bucket: (
            f'resource "aws_flow_log" "vpc_flow" {{\n'
            f'  vpc_id          = aws_vpc.main.id\n'
            f'  traffic_type    = "ALL"\n'
            f'  iam_role_arn    = aws_iam_role.flow_log.arn\n'
            f'  log_destination = aws_cloudwatch_log_group.vpc_flow.arn\n'
            f'}}'
        ),
    },
}


def build_prowler_remediations(prowler_data: list, region: str) -> list:
    remediations = []
    seen = set()
    for finding in prowler_data:
        if finding.get("status") not in ("FAIL", "WARN"):
            continue
        cid = finding.get("check_id", "")
        if cid not in PROWLER_REMEDIATION:
            continue
        arn = finding.get("resource_arn", "")
        resource = arn.split(":")[-1].split("/")[-1] or "unknown"
        key = (cid, resource)
        if key in seen:
            continue
        seen.add(key)
        tpl = PROWLER_REMEDIATION[cid]
        remediations.append({
            "type": "prowler",
            "check_id": cid,
            "severity": finding.get("severity", tpl["severity"]),
            "title": tpl["title"],
            "why": tpl["why"],
            "resource": resource,
            "detail": finding.get("status_extended", ""),
            "cli_code": tpl["cli"](resource, region),
            "tf_code": tpl["tf"](resource),
        })
    return remediations


# ── Trivy 수정 코드 생성 ──────────────────────────────────────────

def build_trivy_remediations(trivy_data: dict, min_severity: str) -> list:
    if not trivy_data:
        return []
    sev_threshold = SEVERITY_ORDER.get(min_severity.lower(), 1)
    remediations = []
    for r in (trivy_data.get("images", {}).get("results") or []):
        image = r.get("image", "?")
        for v in (r.get("top_vulns") or []):
            sev = (v.get("severity") or "").lower()
            if SEVERITY_ORDER.get(sev, 99) > sev_threshold:
                continue
            cve_id  = v.get("id") or v.get("vulnerability_id", "")
            pkg_nm  = v.get("pkg") or v.get("pkg_name", "")
            fixed   = v.get("fixed") or v.get("fixed_version", "")
            installed = v.get("installed", "")
            title   = v.get("title", "")[:80]
            score   = v.get("cvss_score", "")
            if not cve_id:
                continue
            cli_code = (
                f"# {cve_id} — {title}\n"
                f"# Image: {image}\n"
                f"# 패키지: {pkg_nm} {installed} → {fixed or '최신 버전'}\n"
                f"# 방법 1: 베이스 이미지 업그레이드 후 재빌드\n"
                f"docker pull {image.split(':')[0]}:latest\n"
                f"docker build --no-cache -t {image.split(':')[0]}:patched .\n\n"
                f"# 방법 2: 컨테이너 내 패키지만 업데이트 (임시 조치)\n"
                f"# apt-get update && apt-get install -y --only-upgrade {pkg_nm}"
            )
            tf_code = (
                f"# docker-compose.yml 또는 ECS Task Definition에서 이미지 버전 고정\n"
                f"# 현재: {image}\n"
                f"# 권장: {image.split(':')[0]}:latest (또는 {fixed or 'patched'} 포함 버전)\n\n"
                f"# ECS Task Definition 업데이트 예시\n"
                f"aws ecs describe-task-definition --task-definition <TASK_FAMILY> \\\n"
                f"  --query taskDefinition > task_def.json\n"
                f"# task_def.json 내 image 필드를 수정 후\n"
                f"aws ecs register-task-definition --cli-input-json file://task_def.json"
            )
            remediations.append({
                "type": "trivy",
                "check_id": cve_id,
                "severity": sev,
                "title": f"[{cve_id}] {title}",
                "why": (
                    f"패키지 {pkg_nm} {installed}에 CVSS {score} {sev.upper()} 취약점 존재. "
                    f"수정 버전: {fixed or '미정'}"
                ),
                "resource": image,
                "detail": f"image={image} pkg={pkg_nm} installed={installed} fixed={fixed}",
                "cli_code": cli_code,
                "tf_code": tf_code,
            })
    return remediations


# ── WAF 누락 룰 탐지 (attack_runner PASS + fp_fn 미탐) ──────────

# 공격 유형 → 권고 AWS 관리형 룰 매핑
_ATTACK_RULE_MAP = {
    "CommandInjection": {
        "rule_group": "AWSManagedRulesKnownBadInputsRuleSet",
        "vendor":     "AWS",
        "priority":   5,
        "desc":       "OS 명령어 주입(Command Injection) 패턴을 차단하는 AWS 관리형 룰 그룹",
        "tf_name":    "AWSManagedRulesKnownBadInputsRuleSet",
    },
    "SQLi": {
        "rule_group": "AWSManagedRulesSQLiRuleSet",
        "vendor":     "AWS",
        "priority":   2,
        "desc":       "SQL 인젝션 패턴 차단 (이미 존재하면 스킵)",
        "tf_name":    "AWSManagedRulesSQLiRuleSet",
    },
    "XSS": {
        "rule_group": "AWSManagedRulesCommonRuleSet",
        "vendor":     "AWS",
        "priority":   1,
        "desc":       "XSS를 포함한 일반 웹 공격 차단 (이미 존재하면 스킵)",
        "tf_name":    "AWSManagedRulesCommonRuleSet",
    },
    "PathTraversal": {
        "rule_group": "AWSManagedRulesCommonRuleSet",
        "vendor":     "AWS",
        "priority":   1,
        "desc":       "경로 순회(LFI) 공격 차단 (이미 존재하면 스킵)",
        "tf_name":    "AWSManagedRulesCommonRuleSet",
    },
}


def _get_uncovered_attack_types(analysis_data: dict, acl_data: dict) -> list[str]:
    """attack_runner PASS 공격 유형 중 WAF 룰이 없는 항목 반환."""
    # 현재 WAF에 있는 룰 그룹 이름 수집
    existing_rules: set[str] = set()
    if acl_data:
        acl = acl_data.get("WebACL") or acl_data
        for rule in (acl.get("Rules") or []):
            existing_rules.add(rule.get("Name", ""))
            stmt = rule.get("Statement") or {}
            mrg = stmt.get("ManagedRuleGroupStatement") or {}
            if mrg.get("Name"):
                existing_rules.add(mrg["Name"])

    # fp_fn 파일에서 미탐 유형 읽기
    fp_fn_paths = [
        ROOT / "output" / "fp_fn_latest.json",
    ]
    fp_fn_latest = _find_latest("fp_fn_*.json")
    if fp_fn_latest:
        fp_fn_paths.insert(0, fp_fn_latest)

    missed_types: set[str] = set()
    for p in fp_fn_paths:
        data = _load(p)
        if not data:
            continue
        for item in (data.get("false_negatives") or []):
            atype = item.get("attack_type") or item.get("type") or ""
            if atype:
                missed_types.add(atype)
        break

    # attack_runner sent_attacks.jsonl에서 PASS(미차단) 유형 추가
    sim_path = ROOT / "attack_simulation" / "output" / "sent_attacks.jsonl"
    if sim_path.exists():
        try:
            import json as _json
            with open(sim_path, encoding="utf-8") as f:
                for line in f:
                    rec = _json.loads(line.strip())
                    # blocked=False 또는 status!=403 인 것
                    if not rec.get("blocked", True) or rec.get("status_code", 403) not in (403, 400):
                        atype = rec.get("attack_type") or rec.get("type") or ""
                        if atype:
                            missed_types.add(atype)
        except Exception:
            pass

    # 맵에 있는 유형 중 실제로 커버되지 않는 것만
    uncovered = []
    for atype, info in _ATTACK_RULE_MAP.items():
        if atype not in missed_types:
            continue
        if info["rule_group"] not in existing_rules and info["tf_name"] not in existing_rules:
            uncovered.append(atype)
    return uncovered


def build_missing_waf_rule_remediations(analysis_data: dict, acl_data: dict) -> list:
    """attack_runner에서 PASS된 공격 유형 중 WAF 룰이 없는 항목에 대한 추가 권고."""
    remediations = []
    acl_name = (acl_data or {}).get("WebACL", {}).get("Name") or "cloud-sec-web-acl"
    acl_id   = (acl_data or {}).get("WebACL", {}).get("Id") or "<WEB_ACL_ID>"
    region   = "ap-northeast-2"

    for atype in _get_uncovered_attack_types(analysis_data, acl_data):
        info = _ATTACK_RULE_MAP[atype]
        rg   = info["rule_group"]
        pri  = info["priority"]

        cli_code = (
            f"# {atype} 차단 WAF 룰 그룹 추가: {rg}\n\n"
            f"LOCK_TOKEN=$(aws wafv2 get-web-acl \\\n"
            f"  --name {acl_name} --scope REGIONAL --id {acl_id} \\\n"
            f"  --region {region} --query LockToken --output text)\n\n"
            f"# waf_acl_current.json 에 아래 Rule 블록을 추가 후:\n"
            f"aws wafv2 update-web-acl \\\n"
            f"  --name {acl_name} --scope REGIONAL --id {acl_id} \\\n"
            f"  --lock-token $LOCK_TOKEN \\\n"
            f"  --cli-input-json file://waf_acl_updated.json \\\n"
            f"  --region {region}"
        )
        tf_code = (
            f'# terraform/waf.tf 에 추가\n'
            f'resource "aws_wafv2_web_acl_rule" "{rg.lower()}" {{\n'
            f'  name     = "{rg}"\n'
            f'  priority = {pri}\n'
            f'  override_action {{ none {{}} }}\n'
            f'  statement {{\n'
            f'    managed_rule_group_statement {{\n'
            f'      name        = "{rg}"\n'
            f'      vendor_name = "{info["vendor"]}"\n'
            f'    }}\n'
            f'  }}\n'
            f'  visibility_config {{\n'
            f'    sampled_requests_enabled   = true\n'
            f'    cloudwatch_metrics_enabled = true\n'
            f'    metric_name                = "{rg}"\n'
            f'  }}\n'
            f'}}'
        )
        remediations.append({
            "type":      "waf",
            "check_id":  f"waf_missing_rule_{atype.lower()}",
            "severity":  "high",
            "title":     f"WAF {atype} 차단 룰 미설치 — {rg} 추가 필요",
            "why":       (
                f"공격 시뮬레이션에서 {atype} 공격이 WAF에 차단되지 않고 통과됨. "
                f"AWS 관리형 룰 '{rg}' 추가로 즉시 차단 가능."
            ),
            "resource":  acl_name,
            "detail":    f"attack_type={atype} missing_rule_group={rg}",
            "cli_code":  cli_code,
            "tf_code":   tf_code,
        })

    return remediations


# ── WAF Count 모드 수정 코드 생성 ────────────────────────────────

def build_waf_remediations(analysis_data: dict) -> list:
    remediations = []
    rule_hits = analysis_data.get("rule_hits") or {}

    # WAF ACL 파일 확인
    acl_paths = [
        ROOT / "raw" / "waf_web_acl.json",
        ROOT / "analyzer" / "live_logs" / "raw" / "waf_web_acl.json",
        ROOT / "output" / "waf_web_acl.json",
    ]
    acl_data = None
    for p in acl_paths:
        if p.exists():
            acl_data = _load(p)
            break

    count_rules = []
    if acl_data:
        acl = acl_data.get("WebACL") or acl_data
        for rule in (acl.get("Rules") or []):
            oa = rule.get("OverrideAction") or {}
            if "Count" in oa:
                count_rules.append(rule.get("Name", ""))

    # Count 모드 규칙이 있고 탐지 건수가 있으면 PR 생성
    for rule_name in count_rules:
        hits = rule_hits.get(rule_name, 0)
        if hits == 0:
            continue
        acl_name = (acl_data or {}).get("WebACL", {}).get("Name") or "cloud-sec-web-acl"
        acl_id   = (acl_data or {}).get("WebACL", {}).get("Id") or ""
        scope    = "REGIONAL"

        cli_code = (
            f"# WAF Rule '{rule_name}'을 Count → Block 모드로 전환\n"
            f"# 주의: 적용 전 FP(오탐) 여부를 반드시 확인하세요\n\n"
            f"# 1) 현재 WebACL 설정 조회\n"
            f"aws wafv2 get-web-acl \\\n"
            f"  --name {acl_name} \\\n"
            f"  --scope {scope} \\\n"
            f"  --id {acl_id or '<WEB_ACL_ID>'} \\\n"
            f"  --region ap-northeast-2 > waf_acl_current.json\n\n"
            f"# 2) waf_acl_current.json 편집:\n"
            f"#    Rule '{rule_name}'의 OverrideAction: Count → OverrideAction: None (= Block)\n\n"
            f"# 3) 변경 적용\n"
            f"LOCK_TOKEN=$(aws wafv2 get-web-acl --name {acl_name} \\\n"
            f"  --scope {scope} --id {acl_id or '<WEB_ACL_ID>'} \\\n"
            f"  --region ap-northeast-2 --query LockToken --output text)\n\n"
            f"aws wafv2 update-web-acl \\\n"
            f"  --name {acl_name} \\\n"
            f"  --scope {scope} \\\n"
            f"  --id {acl_id or '<WEB_ACL_ID>'} \\\n"
            f"  --lock-token $LOCK_TOKEN \\\n"
            f"  --cli-input-json file://waf_acl_updated.json \\\n"
            f"  --region ap-northeast-2"
        )
        tf_code = (
            f'# terraform/waf.tf 내 {rule_name} 규칙 수정\n'
            f'# OverrideAction을 count에서 none(Block)으로 변경\n\n'
            f'rule {{\n'
            f'  name     = "{rule_name}"\n'
            f'  priority = <기존값 유지>\n'
            f'  # override_action {{ count {{}} }}  ← 이 줄을 아래로 교체\n'
            f'  override_action {{ none {{}} }}\n'
            f'  statement {{\n'
            f'    managed_rule_group_statement {{\n'
            f'      name        = "{rule_name}"\n'
            f'      vendor_name = "AWS"\n'
            f'    }}\n'
            f'  }}\n'
            f'  visibility_config {{\n'
            f'    sampled_requests_enabled   = true\n'
            f'    cloudwatch_metrics_enabled = true\n'
            f'    metric_name                = "{rule_name}"\n'
            f'  }}\n'
            f'}}'
        )
        remediations.append({
            "type": "waf",
            "check_id": f"waf_count_mode_{rule_name}",
            "severity": "high",
            "title": f"WAF '{rule_name}' Count→Block 모드 전환",
            "why": (
                f"{hits:,}건 탐지됐지만 Count 모드라 실제 차단되지 않음. "
                f"Block 전환 시 해당 트래픽을 즉시 차단 가능."
            ),
            "resource": acl_name,
            "detail": f"rule={rule_name} hits={hits} mode=Count",
            "cli_code": cli_code,
            "tf_code": tf_code,
        })

    return remediations


# ── PR 본문 생성 ──────────────────────────────────────────────────

def _severity_badge(sev: str) -> str:
    return {"critical": "🔴 CRITICAL", "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM", "low": "⚪ LOW"}.get(sev.lower(), sev.upper())


def build_pr_body(remediations: list, date_str: str) -> str:
    lines = [
        f"## 보안 취약점 자동 수정 코드 제안 — {date_str}",
        "",
        "> 이 PR은 파이프라인이 탐지한 보안 취약점에 대한 **수정 코드를 제안**합니다.  ",
        "> 관리자가 코드를 검토하고 **승인(Merge)하면** 해당 스크립트를 적용하세요.  ",
        "> 자동 적용되지 않으며, 각 수정 사항은 독립적으로 검토·실행할 수 있습니다.",
        "",
        f"| # | 유형 | 심각도 | 대상 리소스 | 제목 |",
        f"|---|------|--------|-------------|------|",
    ]
    for i, r in enumerate(remediations, 1):
        lines.append(
            f"| {i} | {r['type'].upper()} | {_severity_badge(r['severity'])} "
            f"| `{r['resource']}` | {r['title']} |"
        )
    lines.append("")

    for i, r in enumerate(remediations, 1):
        lines += [
            f"---",
            f"",
            f"### {i}. [{_severity_badge(r['severity'])}] {r['title']}",
            f"",
            f"**탐지 도구**: {r['type'].upper()}  ",
            f"**식별자**: `{r['check_id']}`  ",
            f"**대상 리소스**: `{r['resource']}`  ",
            f"**탐지 내용**: {r['detail']}",
            f"",
            f"**수정 이유**  ",
            f"{r['why']}",
            f"",
            f"**AWS CLI 수정 명령어**",
            f"```bash",
            r["cli_code"],
            f"```",
            f"",
            f"**Terraform 코드 스니펫** (IaC 반영 시)",
            f"```hcl",
            r["tf_code"],
            f"```",
            f"",
        ]

    lines += [
        "---",
        "",
        "### 검토 체크리스트",
        "- [ ] 각 수정 사항의 영향 범위 확인",
        "- [ ] 스테이징 환경에서 먼저 적용 테스트",
        "- [ ] WAF Block 전환 시 오탐(FP) 여부 확인",
        "- [ ] Terraform apply 전 plan 결과 검토",
        "",
        "---",
        "*자동 생성 by cloud-security-platform pipeline*",
    ]
    return "\n".join(lines)


def build_script_file(remediations: list, date_str: str) -> str:
    lines = [
        f"#!/bin/bash",
        f"# ============================================================",
        f"# 보안 취약점 수정 스크립트 — {date_str}",
        f"# 이 스크립트는 자동 생성됩니다. 실행 전 반드시 검토하세요.",
        f"# ============================================================",
        f"set -e",
        f"REGION=${{1:-ap-northeast-2}}",
        f"",
    ]
    for i, r in enumerate(remediations, 1):
        lines += [
            f"# ── [{i}] {r['title']} ({r['severity'].upper()}) ──",
            f"# 식별자: {r['check_id']}",
            f"# 리소스: {r['resource']}",
            f"",
            r["cli_code"],
            f"",
        ]
    return "\n".join(lines)


# ── 메인 ──────────────────────────────────────────────────────────

def run(dry_run: bool = False, min_severity: str = "medium") -> bool:
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("[auto_remediation_pr] GITHUB_TOKEN 미설정 — 스킵")
        return False

    region = "ap-northeast-2"
    try:
        import yaml
        cfg = yaml.safe_load((ROOT / "platform.yaml").read_text(encoding="utf-8"))
        region = cfg.get("aws", {}).get("region", region)
    except Exception:
        pass

    # 데이터 로드
    prowler_path = ROOT / "compliance" / "input" / "prowler_report.json"
    trivy_path   = ROOT / "compliance" / "input" / "trivy_report.json"
    analysis_path = _find_latest("analysis_*.json")

    prowler_raw = _load(prowler_path) or []
    trivy_data  = _load(trivy_path)
    analysis    = _load(analysis_path) or {}

    prowler_list = prowler_raw if isinstance(prowler_raw, list) else []

    # WAF ACL 데이터 (waf 관련 함수들이 공유)
    _acl_paths = [
        ROOT / "raw" / "waf_web_acl.json",
        ROOT / "analyzer" / "live_logs" / "raw" / "waf_web_acl.json",
        ROOT / "output" / "waf_web_acl.json",
    ]
    _acl_data = None
    for _p in _acl_paths:
        if _p.exists():
            _acl_data = _load(_p)
            break

    # 수정 코드 생성
    remediations = (
        build_prowler_remediations(prowler_list, region) +
        build_waf_remediations(analysis) +
        build_missing_waf_rule_remediations(analysis, _acl_data) +
        build_trivy_remediations(trivy_data, min_severity)
    )

    # 심각도 필터 + 정렬
    sev_threshold = SEVERITY_ORDER.get(min_severity.lower(), 2)
    remediations = [r for r in remediations
                    if SEVERITY_ORDER.get(r["severity"].lower(), 99) <= sev_threshold]
    remediations.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"].lower(), 99))

    if not remediations:
        print(f"[auto_remediation_pr] 수정 대상 없음 (min_severity={min_severity})")
        return True

    print(f"[auto_remediation_pr] 수정 항목 {len(remediations)}건:")
    for r in remediations:
        print(f"  [{r['severity'].upper()}] {r['type']} {r['check_id']} — {r['resource']}")

    now = datetime.now(timezone(timedelta(hours=9)))
    date_str = now.strftime("%Y-%m-%d %H:%M KST")
    ts_str   = now.strftime("%Y%m%d-%H%M%S")
    branch   = f"auto/remediation-{ts_str}"
    script_path = f"remediation/fix_{ts_str}.sh"
    pr_title = f"[보안 자동화] {len(remediations)}건 취약점 수정 코드 제안 — {now.strftime('%Y-%m-%d')}"

    pr_body     = build_pr_body(remediations, date_str)
    script_body = build_script_file(remediations, date_str)

    if dry_run:
        print(f"\n[dry-run] branch: {branch}")
        print(f"[dry-run] PR 제목: {pr_title}")
        print(f"\n{'─'*60}\n{pr_body[:1500]}\n{'─'*60}")
        return True

    # 중복 방지: 오늘 이미 생성된 remediation PR 있으면 스킵
    open_branches = _open_remediation_prs(token)
    today_prefix = f"auto/remediation-{now.strftime('%Y%m%d')}"
    if any(b.startswith(today_prefix) for b in open_branches):
        print(f"[auto_remediation_pr] 오늘 날짜 OPEN PR 이미 존재 — 중복 생성 생략")
        return True

    sha = _get_main_sha(token)
    _create_branch(branch, sha, token)
    _push_file(branch, script_path, script_body,
               f"auto: remediation script {ts_str}", token)

    url = _create_pr(branch, pr_title, pr_body, token)
    print(f"[auto_remediation_pr] PR 생성 완료: {url}")
    return True


def main():
    p = argparse.ArgumentParser(description="보안 취약점 수정 코드 자동 PR 생성")
    p.add_argument("--dry-run", action="store_true", help="PR 생성 없이 내용만 출력")
    p.add_argument("--min-severity", default="medium",
                   choices=["critical", "high", "medium", "low"],
                   help="포함할 최소 심각도 (기본: medium)")
    args = p.parse_args()
    ok = run(dry_run=args.dry_run, min_severity=args.min_severity)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
