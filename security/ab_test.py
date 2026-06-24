#!/usr/bin/env python3
"""
ab_test.py — WAF Count Mode vs Block Mode A/B 테스트

attack_runner.py의 공격 페이로드를 waf_analyzer의 탐지 패턴에 적용하여
현재 Count 모드와 가상 Block 모드의 차단율을 비교·분석한다.

실제 AWS WAF가 없어도 로컬에서 시뮬레이션 가능.

사용 예:
    python security/ab_test.py --target http://localhost:5000
    python security/ab_test.py --dry-run           # 실제 요청 없이 패턴만 분석
    python security/ab_test.py --log-dir analyzer/sample_logs
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "analyzer"))
sys.path.insert(0, str(ROOT / "attack_simulation"))

import waf_analyzer

# WAF 규칙 우선순위 매핑 (기획서 4.5 검증 계층 기반)
WAF_RULES = [
    {
        "name": "BlockMaliciousIPs",
        "priority": 0,
        "mode": "block",          # 항상 BLOCK
        "matches": lambda r: r.get("_is_known_malicious", False),
    },
    {
        "name": "AWSManagedRulesSQLiRuleSet",
        "priority": 1,
        "mode": "count",          # 현재 Count 모드
        "mode_block": "block",    # 제안: Block 모드
        "patterns": waf_analyzer.ATTACK_PATTERNS.get("SQLi"),
        "matches": lambda r, p=waf_analyzer.ATTACK_PATTERNS.get("SQLi"):
            p and bool(p.search(r.get("_uri", ""))),
    },
    {
        "name": "AWSManagedRulesCommonRuleSet",
        "priority": 2,
        "mode": "count",
        "mode_block": "block",
        "patterns": None,
        "matches": lambda r: any(
            pat.search(r.get("_uri", ""))
            for pat in waf_analyzer.ATTACK_PATTERNS.values()
        ),
    },
]


def _parse_attack_payloads() -> list[dict]:
    """attack_runner.py 소스에서 공격 페이로드 목록 추출 (import 없이 파싱)."""
    runner_path = ROOT / "attack_simulation" / "attack_runner.py"
    source = runner_path.read_text(encoding="utf-8")

    # ATTACKS 딕셔너리 블록 추출
    match = re.search(r"ATTACKS\s*=\s*\{(.+?)\n\}", source, re.DOTALL)
    if not match:
        return []

    payloads = []
    category_re = re.compile(r'"(\w+)"\s*:\s*\[(.*?)\]', re.DOTALL)
    # attack_runner.py는 튜플 포맷: ("name", "GET|POST|...", "/path", {})
    entry_re = re.compile(
        r'\(\s*"([^"]+)"\s*,\s*"(?:GET|POST|PUT|DELETE)"\s*,\s*"([^"]+)"'
    )
    for cat_match in category_re.finditer(match.group(1)):
        category = cat_match.group(1)
        for entry in entry_re.finditer(cat_match.group(2)):
            payloads.append(
                {"category": category, "name": entry.group(1), "path": entry.group(2)}
            )
    return payloads


def _simulate_waf(payloads: list[dict], mode: str = "count") -> dict:
    """
    mode: "current"  → Count 룰은 COUNT, Block 룰은 BLOCK
          "proposed" → Count 룰도 BLOCK으로 적용
    """
    results = []
    for p in payloads:
        uri = p["path"]
        record = {"_uri": uri, "_is_known_malicious": False}
        action = "allow"
        matched_rule = None

        for rule in sorted(WAF_RULES, key=lambda r: r["priority"]):
            if rule["matches"](record):
                matched_rule = rule["name"]
                if rule["mode"] == "block":
                    action = "block"
                    break
                elif mode == "current":
                    action = "count"
                    break
                else:  # proposed block mode
                    action = "block"
                    break

        results.append(
            {
                "category": p["category"],
                "name": p["name"],
                "uri": uri,
                "action": action,
                "matched_rule": matched_rule,
            }
        )
    return results


def _send_attacks(target: str, dry_run: bool) -> str:
    """attack_runner.py 실행. stdout 반환."""
    cmd = [sys.executable, str(ROOT / "attack_simulation" / "attack_runner.py")]
    if dry_run:
        cmd.append("--dry-run")
    else:
        cmd += ["--target", target, "--count", "1"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=60
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "[A/B] 공격 전송 타임아웃 (60s)\n"
    except Exception as e:
        return f"[A/B] 공격 전송 실패: {e}\n"


def run_ab_test(
    target: str = "http://localhost:5000",
    dry_run: bool = False,
    log_dir: str = None,
    output_dir: str = "output",
) -> dict:
    print("[A/B] 공격 페이로드 로딩...")
    payloads = _parse_attack_payloads()
    if not payloads:
        print("[A/B] 페이로드를 찾을 수 없습니다. attack_runner.py를 확인하세요.")
        return {}

    print(f"[A/B] 총 {len(payloads)}개 공격 패턴 분석")

    if not dry_run and target:
        print(f"[A/B] 공격 전송 중: {target}")
        out = _send_attacks(target, dry_run=False)
        print(out[:500])
    else:
        print("[A/B] dry-run 모드: 실제 요청 없이 시뮬레이션")

    # Count 모드 시뮬레이션 (현재 상태)
    current = _simulate_waf(payloads, mode="current")
    # Block 모드 시뮬레이션 (제안 상태)
    proposed = _simulate_waf(payloads, mode="proposed")

    def count_actions(results):
        counts = {"block": 0, "count": 0, "allow": 0}
        for r in results:
            counts[r["action"]] += 1
        return counts

    cur_counts = count_actions(current)
    prop_counts = count_actions(proposed)
    total = len(payloads)

    # 실제 로그 분석 (선택)
    real_analysis = None
    if log_dir and os.path.exists(log_dir):
        print(f"[A/B] 실 로그 분석: {log_dir}")
        records = list(waf_analyzer.iter_records(log_dir))
        if records:
            real_analysis = waf_analyzer.analyze(records)

    result = {
        "generated_at": datetime.now().isoformat(),
        "target_url": target,
        "total_attack_patterns": total,
        "current_mode": {
            "description": "현재 상태: SQLi·CommonRuleSet → COUNT, BlockMaliciousIPs → BLOCK",
            "actions": cur_counts,
            "block_rate": f"{cur_counts['block'] / total * 100:.1f}%",
            "detection_rate": f"{(cur_counts['block'] + cur_counts['count']) / total * 100:.1f}%",
            "detail": current,
        },
        "proposed_block_mode": {
            "description": "제안 상태: 모든 룰 → BLOCK 전환",
            "actions": prop_counts,
            "block_rate": f"{prop_counts['block'] / total * 100:.1f}%",
            "detection_rate": f"{prop_counts['block'] / total * 100:.1f}%",
            "detail": proposed,
        },
        "improvement": {
            "additional_blocks": prop_counts["block"] - cur_counts["block"],
            "recommendation": (
                "Block 모드 전환 권장 (오탐 재검토 후)"
                if prop_counts["block"] > cur_counts["block"]
                else "현재 Count 모드 유지"
            ),
        },
        "real_log_analysis": real_analysis,
    }

    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"ab_test_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n[A/B] 결과:")
    print(f"  현재(Count): BLOCK {cur_counts['block']} / COUNT {cur_counts['count']} / ALLOW {cur_counts['allow']}")
    print(f"  제안(Block): BLOCK {prop_counts['block']} / ALLOW {prop_counts['allow']}")
    print(f"  추가 차단 가능: {result['improvement']['additional_blocks']}건")
    print(f"  권고: {result['improvement']['recommendation']}")
    print(f"[A/B] 보고서 저장: {out_path}")
    return result


def main():
    p = argparse.ArgumentParser(description="WAF Count/Block A/B 테스트")
    p.add_argument("--target", default="http://localhost:5000", help="공격 대상 URL")
    p.add_argument("--dry-run", action="store_true", help="실제 요청 없이 시뮬레이션만")
    p.add_argument("--log-dir", default=None, help="실제 WAF 로그 디렉토리 (선택)")
    p.add_argument("--out", default="output", help="결과 저장 디렉토리")
    args = p.parse_args()

    run_ab_test(
        target=args.target,
        dry_run=args.dry_run,
        log_dir=args.log_dir,
        output_dir=args.out,
    )


if __name__ == "__main__":
    main()
