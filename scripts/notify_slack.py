#!/usr/bin/env python3
"""
notify_slack.py — WAF 분석 완료 후 Slack Webhook 알림

HIGH 위험 IP 탐지 시 즉시 알림. SLACK_WEBHOOK_URL 없으면 자동 스킵.
파이프라인 완료 후 run_pipeline.py에서 자동 호출됨.

환경변수:
  SLACK_WEBHOOK_URL  — Slack Incoming Webhook URL (필수)

사용 예:
  python scripts/notify_slack.py
  python scripts/notify_slack.py --analysis output/analysis_20260629.json
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _latest_analysis():
    candidates = sorted((ROOT / "output").glob("analysis_*.json"))
    return candidates[-1] if candidates else None


def _send_webhook(url: str, payload: dict) -> bool:
    try:
        import urllib.request
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "CloudSecurityPlatform/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        print(f"[notify_slack] 전송 실패: {e}")
        return False


def _is_discord(url: str) -> bool:
    return "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url


def _build_slack_payload(data: dict, filename: str, level: str, color: str,
                         fields_data: list) -> dict:
    fields = [
        {"title": k, "value": v, "short": s} for k, v, s in fields_data
    ]
    return {
        "attachments": [{
            "color": color,
            "title": f"[Cloud Security Platform] WAF 분석 완료 — {level}",
            "text": f"분석 파일: `{filename}`",
            "fields": fields,
            "footer": "Cloud Security Platform | AWS WAF 자동 분석",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }


def _build_discord_payload(data: dict, filename: str, level: str, color_hex: str,
                           fields_data: list) -> dict:
    color_int = int(color_hex.lstrip("#"), 16)
    summary = data.get("summary", {})
    high_risk = summary.get("high_risk_ips", 0)

    if high_risk > 0:
        status_bar = "🔴🔴🔴 **즉각 조치 필요**"
        desc_prefix = "⚠️ **HIGH 위험 IP가 탐지되었습니다.** WAF 차단 목록 업데이트를 위한 GitHub PR이 자동 생성되었습니다."
    else:
        status_bar = "🟢🟢🟢 **정상 범위**"
        desc_prefix = "✅ 탐지된 고위험 IP가 없습니다. 인프라 보안 상태가 양호합니다."

    embed_fields = [{"name": k, "value": v, "inline": s} for k, v, s in fields_data]

    return {
        "username": "구름방범대 보안봇",
        "avatar_url": "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/2601.png",
        "embeds": [{
            "title": f"🛡️ WAF 자동 분석 리포트 — {level}",
            "description": f"{status_bar}\n\n{desc_prefix}",
            "color": color_int,
            "fields": embed_fields,
            "thumbnail": {"url": "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/2601.png"},
            "footer": {
                "text": "구름방범대 · AI 적용 클라우드 보안 자동화 플랫폼",
                "icon_url": "https://cdn.jsdelivr.net/gh/twitter/twemoji@14.0.2/assets/72x72/2601.png",
            },
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }]
    }


def _build_payload(data: dict, filename: str, url: str) -> dict:
    summary = data.get("summary", {})
    total = summary.get("total_requests", 0)
    high_risk = summary.get("high_risk_ips", 0)
    block_rate = summary.get("block_rate", 0)
    attack_counts = summary.get("attack_type_counts", {})
    top_ips = data.get("top_ips", [])

    high_ips = [ip for ip in top_ips if ip.get("risk_level") == "HIGH"]

    if high_risk > 0:
        color = "FF0000"
        level = "🔴 HIGH 위험 IP 탐지"
    elif attack_counts:
        color = "FFA500"
        level = "🟡 공격 패턴 탐지"
    else:
        color = "36A64F"
        level = "🟢 이상 없음"

    # (이름, 값, inline/short) 공통 필드
    fields_data = [
        ("📊 총 요청 수",  f"`{total:,}건`",                           True),
        ("🚨 고위험 IP",   f"`{high_risk}개`",                         True),
        ("🛡️ WAF 차단율",  f"`{block_rate * 100:.1f}%`",              True),
        ("⚔️ 공격 유형",   ", ".join(attack_counts) or "탐지 없음",   True),
    ]

    if high_ips:
        top = high_ips[0]
        fields_data.append((
            f"🔍 최고위험 IP [{top.get('country', '??')}]",
            f"```{top.get('ip')}```\n"
            f"위험도 **{top.get('risk_score', 0):.0f}점** · "
            f"공격: {', '.join(top.get('attack_types', [])) or '없음'}",
            False,
        ))

    # WAF 실제 설정 기반 Count 모드 판단 (block_rate만으로 판단하면 sample_logs 오판 가능)
    waf_acl_path = ROOT / "raw" / "waf_web_acl.json"
    count_mode_rules = []
    if waf_acl_path.exists():
        try:
            acl_data = json.loads(waf_acl_path.read_text(encoding="utf-8"))
            rules = acl_data.get("WebACL", acl_data).get("Rules", [])
            for r in rules:
                if "Count" in r.get("OverrideAction", {}):
                    count_mode_rules.append(r.get("Name", "?"))
        except Exception:
            pass

    if count_mode_rules:
        fields_data.append((
            "⚠️ 주의",
            f"WAF 규칙이 Count 모드: {', '.join(count_mode_rules)}. 공격이 차단되지 않습니다. Block 전환을 검토하세요.",
            False,
        ))

    # WAF WebACL 존재 여부 — Prowler 결과 참조
    prowler_path = ROOT / "compliance" / "input" / "prowler_report.json"
    if prowler_path.exists():
        try:
            findings = json.loads(prowler_path.read_text(encoding="utf-8"))
            for item in findings:
                if item.get("check_id") == "wafv2_webacl_exists" and item.get("status") == "FAIL":
                    fields_data.append((
                        "🚨 WAF 미설정",
                        "WebACL이 존재하지 않습니다. `terraform apply`로 WAF를 배포하세요.",
                        False,
                    ))
                    break
                if item.get("check_id") == "iam_root_mfa_enabled" and item.get("status") == "FAIL":
                    fields_data.append((
                        "⚠️ 루트 MFA 비활성화",
                        "AWS 루트 계정 MFA가 설정되지 않았습니다. 즉시 활성화하세요.",
                        False,
                    ))
        except Exception:
            pass

    if _is_discord(url):
        return _build_discord_payload(data, filename, level, color, fields_data)
    return _build_slack_payload(data, filename, level, f"#{color}", fields_data)


def notify(analysis_path=None) -> bool:
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("[notify_slack] SLACK_WEBHOOK_URL 없음 — 스킵 (.env에 추가하면 활성화)")
        return False

    path = Path(analysis_path) if analysis_path else _latest_analysis()
    if not path or not path.exists():
        print("[notify_slack] 분석 파일 없음 — 스킵")
        return False

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[notify_slack] 파일 읽기 실패: {e}")
        return False

    payload = _build_payload(data, path.name, webhook_url)
    ok = _send_webhook(webhook_url, payload)
    if ok:
        high = data.get("summary", {}).get("high_risk_ips", 0)
        level = "HIGH 위험" if high > 0 else "완료"
        print(f"[notify_slack] Slack 알림 전송 완료 ({level})")
    return ok


def main():
    p = argparse.ArgumentParser(description="WAF 분석 결과 Slack Webhook 알림")
    p.add_argument("--analysis", default=None, help="분석 JSON 경로 (생략 시 최신 자동 선택)")
    args = p.parse_args()

    # .env 로딩
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    ok = notify(args.analysis)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
