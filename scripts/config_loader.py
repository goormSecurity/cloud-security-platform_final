"""
config_loader.py — platform.yaml 기반 중앙 설정 로더

우선순위: 환경변수 > platform.yaml > 기본값
platform.yaml 없으면 generate_config.py 실행 안내 후 종료.

사용 예:
    from scripts.config_loader import cfg
    bucket = cfg("buckets.waf_logs")
    region = cfg("aws.region")
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from functools import reduce
from pathlib import Path
from typing import Any

# 한국 표준시 (UTC+9)
KST = timezone(timedelta(hours=9))


def now_kst(fmt: str | None = None) -> str:
    """현재 KST 시각. fmt 지정 시 strftime 결과, 없으면 ISO 8601 반환."""
    t = datetime.now(KST)
    return t.strftime(fmt) if fmt else t.isoformat(timespec="seconds")

ROOT = Path(__file__).resolve().parent.parent
_PLATFORM_YAML = ROOT / "platform.yaml"

# 환경변수 오버라이드 맵 (env key → yaml dotted path)
_ENV_OVERRIDES: dict[str, str] = {
    "AWS_REGION":           "aws.region",
    "AWS_ACCOUNT_ID":       "aws.account_id",
    "WAF_LOGS_BUCKET":      "buckets.waf_logs",
    "AUDIT_EVIDENCE_BUCKET":"buckets.audit_evidence",
    "WAF_ACL_NAME":         "waf.acl_name",
    "ALB_DNS_NAME":         "alb.dns_name",
    "SLACK_WEBHOOK_URL":    "integrations.slack_webhook",
    "DISCORD_WEBHOOK_URL":  "integrations.discord_webhook",
    "GITHUB_REPOSITORY":    "integrations.github_repo",
    "ABUSEIPDB_API_KEY":    "integrations.abuseipdb_key",
}


def _load_yaml() -> dict:
    if not _PLATFORM_YAML.exists():
        print(
            "[config] platform.yaml 없음.\n"
            "  방법 1: python scripts/generate_config.py  (terraform output에서 자동 생성)\n"
            "  방법 2: cp platform.yaml.example platform.yaml  후 직접 수정",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        import yaml
    except ImportError:
        # PyYAML 없으면 간단한 파서로 대체
        return _parse_yaml_simple(_PLATFORM_YAML.read_text(encoding="utf-8"))

    with open(_PLATFORM_YAML, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _parse_yaml_simple(text: str) -> dict:
    """PyYAML 없을 때 쓰는 단순 파서 (중첩 dict, 문자열 값만 지원)."""
    result: dict = {}
    current_section: dict = result
    section_key: str | None = None

    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith(" ") and stripped.endswith(":"):
            section_key = stripped[:-1]
            current_section = {}
            result[section_key] = current_section
        elif stripped.startswith("  ") and ":" in stripped:
            k, _, v = stripped.strip().partition(":")
            v = v.strip().strip('"').split("#")[0].strip()
            current_section[k.strip()] = v if v else ""
    return result


def _apply_env_overrides(data: dict) -> dict:
    for env_key, yaml_path in _ENV_OVERRIDES.items():
        val = os.getenv(env_key)
        if not val:
            continue
        keys = yaml_path.split(".")
        node = data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = val
    return data


_data: dict | None = None


def _get_data() -> dict:
    global _data
    if _data is None:
        _data = _apply_env_overrides(_load_yaml())
    return _data


def cfg(path: str, default: Any = None) -> Any:
    """점(.) 구분 경로로 설정값 조회.

    예: cfg("buckets.waf_logs")  →  "aws-waf-logs-cloud-sec-dev"
        cfg("aws.region")        →  "ap-northeast-2"
    """
    try:
        return reduce(lambda d, k: d[k], path.split("."), _get_data())
    except (KeyError, TypeError):
        return default


def waf_log_prefix() -> str:
    """WAF 로그 S3 prefix (계정ID·리전·ACL명 조합)."""
    account = cfg("aws.account_id", "")
    region  = cfg("aws.region", "ap-northeast-2")
    acl     = cfg("waf.acl_name", "")
    return f"AWSLogs/{account}/WAFLogs/{region}/{acl}"


def alb_target_url() -> str:
    """ALB HTTP URL."""
    dns = cfg("alb.dns_name", "")
    return f"http://{dns}" if dns else ""


def require(path: str) -> str:
    """값이 비어있으면 오류로 종료."""
    val = cfg(path)
    if not val:
        print(f"[config] 필수 설정 누락: {path}  (platform.yaml 확인)", file=sys.stderr)
        sys.exit(1)
    return val
