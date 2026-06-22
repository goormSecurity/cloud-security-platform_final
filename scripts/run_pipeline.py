#!/usr/bin/env python3
"""
run_pipeline.py — 전체 보안 파이프라인 로컬 실행기

기획서 14단계 파이프라인을 로컬에서 순서대로 실행한다.
각 단계는 독립적으로 실패해도 다음 단계를 계속 진행하며,
최종 요약 보고서를 출력한다.

사용 예:
    python scripts/run_pipeline.py
    python scripts/run_pipeline.py --skip-zap --skip-ai
    python scripts/run_pipeline.py --target http://localhost:5000
    python scripts/run_pipeline.py --log-dir analyzer/sample_logs
"""
import argparse
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent.parent

# ── 색상 출력 ────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"

def _ok(msg):   print(f"{C.GREEN}  ✔ {msg}{C.RESET}")
def _skip(msg): print(f"{C.YELLOW}  ⊘ {msg}{C.RESET}")
def _fail(msg): print(f"{C.RED}  ✘ {msg}{C.RESET}")
def _info(msg): print(f"{C.CYAN}  → {msg}{C.RESET}")
def _step(n, title):
    print(f"\n{C.BOLD}{C.CYAN}[{n}] {title}{C.RESET}")
    print(f"{C.GRAY}{'─' * 50}{C.RESET}")


def _run(cmd: list, cwd=None, env=None) -> tuple[int, str, str]:
    env_full = {**os.environ, **(env or {})}
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env_full)
    return r.returncode, r.stdout, r.stderr


def _check_docker() -> bool:
    code, _, _ = _run(["docker", "info"])
    return code == 0


def _check_ollama() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434/api/version", timeout=3)
        return True
    except Exception:
        return False


def _latest_file(pattern: str) -> str | None:
    files = sorted(ROOT.glob(pattern))
    return str(files[-1]) if files else None


# ── 단계별 실행 ──────────────────────────────────────────────────

def step_attack_sim(target: str, dry_run: bool) -> bool:
    _step(1, "공격 시뮬레이션 (attack_runner.py)")
    cmd = [sys.executable, str(ROOT / "attack_simulation" / "attack_runner.py")]
    if dry_run or not target:
        cmd.append("--dry-run")
        _info("dry-run 모드")
    else:
        cmd += ["--target", target]
        _info(f"대상: {target}")

    code, out, err = _run(cmd)
    if code == 0:
        _ok("공격 시뮬레이션 완료")
        return True
    else:
        _fail(f"실패: {err[:300]}")
        return False


def step_analyzer(log_dir: str) -> str | None:
    _step(2, "WAF 로그 분석 + CTI 위험도 산정 (analyzer/main.py)")
    _info(f"로그 소스: {log_dir}")
    cmd = [sys.executable, str(ROOT / "analyzer" / "main.py"), "--source", log_dir]
    code, out, err = _run(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("분석 완료")
        latest = _latest_file("output/analysis_*.json")
        if latest:
            _info(f"결과 파일: {Path(latest).name}")
        return latest
    else:
        _fail(f"실패: {(err or out)[:300]}")
        return None


def step_ab_test(target: str, log_dir: str, dry_run: bool) -> bool:
    _step(3, "WAF Count/Block A/B 테스트 (security/ab_test.py)")
    cmd = [sys.executable, str(ROOT / "security" / "ab_test.py"),
           "--log-dir", log_dir, "--out", str(ROOT / "output")]
    if dry_run or not target:
        cmd.append("--dry-run")
    else:
        cmd += ["--target", target]

    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines():
        if "[A/B]" in line:
            print(f"  {line.strip()}")
    if code == 0:
        _ok("A/B 테스트 완료")
        return True
    else:
        _fail(f"실패: {err[:200]}")
        return False


def step_zap(target: str) -> bool:
    _step(4, "OWASP ZAP 자동 스캔 (security/zap_scanner.py)")
    if not _check_docker():
        _skip("Docker 미실행 — ZAP 스킵 (Docker Desktop을 시작하면 사용 가능)")
        return False
    if not target:
        _skip("--target 미지정 — ZAP 스킵")
        return False

    _info(f"대상: {target}")
    cmd = [sys.executable, str(ROOT / "security" / "zap_scanner.py"),
           "--target", target, "--baseline-only", "--out", str(ROOT / "output")]
    code, out, err = _run(cmd)
    for line in (out + err).splitlines():
        if "[ZAP]" in line:
            print(f"  {line.strip()}")
    if code == 0:
        _ok("ZAP 스캔 완료")
        return True
    else:
        _fail(f"실패 (ZAP 종료 코드: {code})")
        return False


def step_ai_report(analysis_json: str | None) -> bool:
    _step(5, "AI 보안 보고서 생성 (ai/report_generator.py)")
    if not _check_ollama():
        _skip("Ollama 미실행 — AI 보고서 스킵\n"
              "     (Ollama 설치: https://ollama.ai  모델: ollama pull llama3.1:8b)")
        return False

    if not analysis_json:
        _skip("분석 JSON 없음 — AI 보고서 스킵")
        return False

    _info(f"입력: {Path(analysis_json).name}")
    cmd = [sys.executable, str(ROOT / "ai" / "report_generator.py"), analysis_json]
    code, out, err = _run(cmd, cwd=str(ROOT / "ai"))
    if code == 0:
        _ok("AI 보고서 생성 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:300]}")
        return False


def step_compliance_report() -> bool:
    _step(6, "컴플라이언스 감사 보고서 생성 (compliance/render.py)")
    cmd = [sys.executable, str(ROOT / "compliance" / "render.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    output_lines = [l for l in (out + err).splitlines() if l.strip()]
    for line in output_lines[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("컴플라이언스 보고서 생성 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:300]}")
        return False


def step_pr_collector() -> bool:
    _step(7, "PR 이력 수집 — ISMS-P 변경관리 증적 (compliance/pr_collector.py)")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        _skip("GITHUB_TOKEN 없음 — PR 수집 스킵 (.env에 GITHUB_TOKEN 설정)")
        return False

    cmd = [sys.executable, str(ROOT / "compliance" / "pr_collector.py"), "--merged-only"]
    code, out, err = _run(cmd, cwd=str(ROOT), env={"GITHUB_TOKEN": token})
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("PR 이력 수집 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:300]}")
        return False


def step_auto_pr(analysis_json: str | None, dry_run: bool) -> bool:
    _step(8, "GitHub PR 자동 생성 (scripts/auto_pr.py)")
    if not analysis_json:
        _skip("분석 JSON 없음 — PR 자동 생성 스킵")
        return False

    token = os.environ.get("GITHUB_TOKEN")
    if not token and not dry_run:
        _skip("GITHUB_TOKEN 없음 — PR 자동 생성 스킵")
        return False

    cmd = [sys.executable, str(ROOT / "scripts" / "auto_pr.py"),
           "--analysis", analysis_json]
    if dry_run:
        cmd.append("--dry-run")

    code, out, err = _run(cmd, cwd=str(ROOT), env={"GITHUB_TOKEN": token or ""})
    for line in (out + err).splitlines():
        if "[auto_pr]" in line:
            print(f"  {line.strip()}")
    if code == 0:
        _ok("PR 자동 생성 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:300]}")
        return False


# ── 메인 ─────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="클라우드 보안 플랫폼 — 전체 파이프라인 실행")
    p.add_argument("--target",    default=None,  help="공격 대상 URL (예: http://localhost:5000)")
    p.add_argument("--log-dir",   default=str(ROOT / "analyzer" / "sample_logs"),
                   help="WAF 로그 디렉토리")
    p.add_argument("--dry-run",   action="store_true", help="실제 요청/PR 없이 시뮬레이션")
    p.add_argument("--skip-zap",  action="store_true", help="ZAP 스캔 스킵")
    p.add_argument("--skip-ai",   action="store_true", help="AI 보고서 생성 스킵")
    p.add_argument("--skip-pr",   action="store_true", help="GitHub PR 자동 생성 스킵")
    args = p.parse_args()

    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}")
    print(f"  Cloud Security Platform — 로컬 파이프라인")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}{C.RESET}")

    start = time.time()
    results = {}

    # .env 로딩 (있으면)
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    results["attack_sim"]    = step_attack_sim(args.target, args.dry_run)
    analysis_json            = step_analyzer(args.log_dir)
    results["analyzer"]      = bool(analysis_json)
    results["ab_test"]       = step_ab_test(args.target, args.log_dir, args.dry_run)
    results["zap"]           = False if args.skip_zap else step_zap(args.target)
    results["ai_report"]     = False if args.skip_ai  else step_ai_report(analysis_json)
    results["compliance"]    = step_compliance_report()
    results["pr_collector"]  = step_pr_collector()
    results["auto_pr"]       = False if args.skip_pr  else step_auto_pr(analysis_json, args.dry_run)

    elapsed = time.time() - start

    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}")
    print(f"  파이프라인 완료 ({elapsed:.1f}s)")
    print(f"{'=' * 60}{C.RESET}")

    ok = sum(1 for v in results.values() if v)
    total = len(results)
    for name, status in results.items():
        icon = f"{C.GREEN}✔{C.RESET}" if status else f"{C.YELLOW}⊘{C.RESET}"
        print(f"  {icon}  {name}")

    print(f"\n  {ok}/{total} 단계 성공\n")

    if analysis_json:
        print(f"{C.GRAY}  분석 결과: {Path(analysis_json).name}{C.RESET}")

    latest_report = _latest_file("compliance/output/*.pdf")
    if latest_report:
        print(f"{C.GRAY}  컴플라이언스 PDF: {Path(latest_report).name}{C.RESET}")

    print()


if __name__ == "__main__":
    main()
