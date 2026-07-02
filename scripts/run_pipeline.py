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

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg, now_kst
except Exception:
    def cfg(p, d=None): return d

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


def _has_aws_creds() -> bool:
    """환경변수, ~/.aws/credentials, 또는 EC2 IAM 역할(IMDS) 중 하나라도 있으면 True."""
    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
        return True
    creds = Path.home() / ".aws" / "credentials"
    config = Path.home() / ".aws" / "config"
    if creds.exists() or config.exists():
        return True
    # EC2 IAM 역할 — boto3 기본 자격증명 체인으로 확인
    try:
        import boto3
        boto3.client("sts", region_name="ap-northeast-2").get_caller_identity()
        return True
    except Exception:
        return False


def _run(cmd: list, cwd=None, env=None, timeout=300) -> tuple[int, str, str]:
    env_full = {**os.environ, **(env or {}), "PYTHONIOENCODING": "utf-8"}
    if env:
        env_full.update(env)
    r = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, env=env_full,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    return r.returncode, r.stdout or "", r.stderr or ""


def _check_docker() -> bool:
    try:
        r = subprocess.run("docker info", capture_output=True, timeout=20, shell=True)
        return r.returncode == 0
    except Exception:
        return False


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

def step_attack_sim(target: str, dry_run: bool, app: str = "all") -> bool:
    _step(1, f"공격 시뮬레이션 (attack_runner.py, app={app})")
    cmd = [sys.executable, str(ROOT / "attack_simulation" / "attack_runner.py"),
           "--app", app]
    if dry_run or not target:
        cmd.append("--dry-run")
        _info("dry-run 모드")
    else:
        cmd += ["--target", target]
        _info(f"대상: {target}  앱: {app}")

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


def step_fp_fn(analysis_json: str | None, target: str | None) -> bool:
    _step("3h", "오탐/미탐(FP/FN) 분석 (scripts/analyze_fp_fn.py)")
    cmd = [sys.executable, str(ROOT / "scripts" / "analyze_fp_fn.py")]
    if analysis_json:
        cmd += ["--analysis", analysis_json]
    ab = _latest_file("output/ab_test_*.json")
    if ab:
        cmd += ["--ab-test", ab]
    if target:
        cmd += ["--target", target]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines():
        if "[fp_fn]" in line:
            print(f"  {line.strip()}")
    if code == 0:
        _ok("오탐/미탐 분석 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_zap(target: str) -> bool:
    _step(4, "OWASP ZAP 자동 스캔 (security/zap_scanner.py)")
    if not target:
        _skip("--target 미지정 — ZAP 스킵")
        return False

    local_docker = _check_docker()
    ssh_host = cfg("servers.analysis_ip", "")

    if not local_docker and not ssh_host:
        _skip("로컬 Docker 없음 + platform.yaml servers.analysis_ip 미설정 — ZAP 스킵")
        return False

    mode = "로컬 Docker" if local_docker else f"SSH 원격 ({ssh_host})"
    _info(f"대상: {target}  실행 모드: {mode}")

    cmd = [sys.executable, str(ROOT / "security" / "zap_scanner.py"),
           "--target", target, "--baseline-only", "--out", str(ROOT / "output")]
    if not local_docker:
        cmd += ["--ssh-host", ssh_host]

    code, out, err = _run(cmd, timeout=660)
    for line in (out + err).splitlines():
        if "[ZAP]" in line:
            print(f"  {line.strip()}")
    if code == 0:
        _ok("ZAP 스캔 완료")
        return True
    else:
        _fail(f"실패 (ZAP 종료 코드: {code})")
        return False


def step_ai_report(analysis_json: str | None, model: str = "qwen2.5:7b") -> bool:
    _step(5, f"AI 보안 보고서 생성 (ai/report_generator.py, model={model})")
    if not _check_ollama():
        _skip("Ollama 미실행 — AI 보고서 스킵\n"
              "     (Ollama 설치: https://ollama.ai  모델: ollama pull qwen2.5:7b)")
        return False

    if not analysis_json:
        _skip("분석 JSON 없음 — AI 보고서 스킵")
        return False

    _info(f"입력: {Path(analysis_json).name}")
    ai_output = ROOT / "ai" / "output"
    cmd = [sys.executable, str(ROOT / "ai" / "report_generator.py"),
           "--input", analysis_json,
           "--output-dir", str(ai_output),
           "--model", model]
    code, out, err = _run(cmd, cwd=str(ROOT / "ai"))
    if code == 0:
        _ok("AI 보고서 생성 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:300]}")
        return False


def step_compliance_report(analysis_json: str | None) -> bool:
    _step(6, "컴플라이언스 감사 보고서 생성")

    real_data = str(ROOT / "compliance" / "real_data.json")

    # 6-a: 실제 분석 데이터 → compliance 포맷 변환
    if not analysis_json:
        _fail("분석 JSON 없음 — analyzer 단계가 실패했거나 --log-dir이 지정되지 않았습니다")
        return False

    _info("실제 분석 데이터 변환 중 (build_data.py)")
    cmd = [sys.executable, str(ROOT / "compliance" / "build_data.py"),
           "--analysis", analysis_json, "--out", real_data]
    code, out, err = _run(cmd, cwd=str(ROOT))
    if code != 0:
        _fail(f"build_data 실패:\n{(err or out)[:300]}")
        return False
    _ok(f"데이터 변환 완료 → {Path(real_data).name}")

    # 6-b: HTML/PDF 렌더링
    cmd = [sys.executable, str(ROOT / "compliance" / "render.py"), "--data", real_data]
    code, out, err = _run(cmd, cwd=str(ROOT))
    output_lines = [ln for ln in (out + err).splitlines() if ln.strip()]
    for line in output_lines[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("컴플라이언스 보고서 생성 완료")
        return True
    else:
        _fail(f"render 실패: {(err or out)[:300]}")
        return False


def step_collect_waf() -> bool:
    _step("3b", "WAF describe 수집 (scripts/collect_waf.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — WAF describe 스킵 (~/.aws/credentials 또는 AWS_ACCESS_KEY_ID 설정)")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_waf.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("WAF describe 수집 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_collect_cloudtrail() -> bool:
    _step("3c", "CloudTrail 변경 이력 수집 (scripts/collect_cloudtrail.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — CloudTrail 수집 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_cloudtrail.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("CloudTrail 수집 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_collect_prowler() -> bool:
    _step("3d", "Prowler 보안 점검 수집 (scripts/collect_prowler.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — Prowler 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_prowler.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("Prowler 점검 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_collect_cmk() -> bool:
    _step("3e", "CMK + Object Lock 증적 수집 (scripts/collect_cmk.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — CMK 수집 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_cmk.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("CMK 증적 수집 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_collect_config_diff() -> bool:
    _step("3f", "AWS Config 드리프트 감지 (scripts/collect_config_diff.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — Config 드리프트 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_config_diff.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("Config 드리프트 감지 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_collect_s3_security() -> bool:
    _step("3g", "S3 버킷 보안 감사 (scripts/collect_s3_security.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — S3 보안 감사 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_s3_security.py")]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-8:]:
        print(f"  {line}")
    if code == 0:
        _ok("S3 버킷 보안 감사 완료")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
        return False


def step_upload_s3() -> bool:
    _step("10", "결과물 S3 업로드 (audit-evidence 버킷)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — S3 업로드 스킵")
        return False

    try:
        import boto3
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        bucket = "cloud-sec-audit-evidence-dev"
        today = now_kst("%Y/%m/%d")
        prefix = f"pipeline-results/{today}"

        candidates = [
            *sorted((ROOT / "output").glob("analysis_*.json"))[-1:],
            *sorted((ROOT / "output").glob("ab_test_*.json"))[-1:],
            ROOT / "compliance" / "real_data.json",
            ROOT / "compliance" / "input" / "ai_analysis.json",
            *sorted((ROOT / "compliance" / "output").glob("*.pdf"))[-1:],
            ROOT / "compliance" / "output" / "report.html",
            *sorted((ROOT / "ai" / "output").glob("report_*.md"))[-1:],
        ]

        uploaded, skipped = 0, 0
        for path in candidates:
            if not path.exists():
                skipped += 1
                continue
            key = f"{prefix}/{path.name}"
            try:
                s3.upload_file(str(path), bucket, key)
                print(f"  [upload] ✔ {path.name} → s3://{bucket}/{key}")
                uploaded += 1
            except Exception as e:
                print(f"  [upload] ✘ {path.name}: {e}")

        _ok(f"S3 업로드 완료 ({uploaded}개 / 스킵 {skipped}개)")
        return uploaded > 0
    except Exception as e:
        _fail(f"S3 업로드 실패: {e}")
        return False


def step_notify_slack(analysis_json: str | None) -> bool:
    _step("9", "Slack 알림 전송 (scripts/notify_slack.py)")
    if not os.environ.get("SLACK_WEBHOOK_URL"):
        _skip("SLACK_WEBHOOK_URL 없음 — 알림 스킵 (.env에 추가하면 활성화)")
        return False
    if not analysis_json:
        _skip("분석 JSON 없음 — 알림 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "notify_slack.py"),
           "--analysis", analysis_json]
    code, out, err = _run(cmd, cwd=str(ROOT))
    for line in (out + err).splitlines()[-3:]:
        print(f"  {line}")
    if code == 0:
        _ok("Slack 알림 전송 완료")
        return True
    else:
        _skip("Slack 전송 실패 (webhook URL 또는 네트워크 확인)")
        return False


def step_generate_ai_json(analysis_json: str | None) -> bool:
    _step("5b", "AI 분석 JSON 생성 (ai/generate_analysis_json.py)")
    if not analysis_json:
        _skip("분석 JSON 없음 — AI JSON 생성 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "ai" / "generate_analysis_json.py"),
           "--analysis", analysis_json]
    code, out, err = _run(cmd, cwd=str(ROOT / "ai"))
    for line in (out + err).splitlines()[-5:]:
        print(f"  {line}")
    if code == 0:
        _ok("AI 분석 JSON 생성 완료 → compliance/input/ai_analysis.json")
        return True
    else:
        _fail(f"실패: {(err or out)[:200]}")
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
    p.add_argument("--app",       default="all", choices=["dvwa", "juiceshop", "ghost", "all"],
                   help="공격 시뮬레이션 대상 앱 (기본: all)")
    p.add_argument("--log-dir",   default=str(ROOT / "analyzer" / "sample_logs"),
                   help="WAF 로그 디렉토리")
    p.add_argument("--live",      action="store_true",
                   help="S3에서 최신 WAF 로그 다운로드 후 분석 (--log-dir 무시)")
    p.add_argument("--live-hours", default=1, type=int,
                   help="--live 사용 시 수집 시간 범위 (기본: 1시간)")
    p.add_argument("--dry-run",   action="store_true", help="실제 요청/PR 없이 시뮬레이션")
    p.add_argument("--skip-zap",  action="store_true", help="ZAP 스캔 스킵")
    p.add_argument("--skip-ai",   action="store_true", help="AI 보고서 생성 스킵")
    p.add_argument("--skip-pr",   action="store_true", help="GitHub PR 자동 생성 스킵")
    p.add_argument("--skip-fp-fn", action="store_true", help="오탐/미탐 분석 스킵")
    p.add_argument("--ai-model",  default="qwen2.5:7b", help="AI 보고서 Ollama 모델 (기본: qwen2.5:7b)")
    args = p.parse_args()

    # --live: S3에서 실시간 로그 다운로드
    if args.live:
        live_dir = str(ROOT / "analyzer" / "live_logs")
        _step("0", f"S3 WAF 실시간 로그 수집 (최근 {args.live_hours}시간)")
        code, out, err = _run(
            [sys.executable, str(ROOT / "scripts" / "collect_waf_logs.py"),
             "--hours", str(args.live_hours), "--out", live_dir],
            cwd=str(ROOT)
        )
        for line in (out + err).splitlines()[-8:]:
            print(f"  {line}")
        if code == 0:
            args.log_dir = live_dir
            _ok(f"실시간 로그 준비 완료 → {live_dir}")
        else:
            _fail("S3 로그 수집 실패 — sample_logs로 폴백")
            # log_dir은 기본값(sample_logs) 유지

    print(f"\n{C.BOLD}{C.CYAN}{'=' * 60}")
    print(f"  Cloud Security Platform — 로컬 파이프라인")
    print(f"  {now_kst('%Y-%m-%d %H:%M:%S')} (KST)")
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

    results["attack_sim"]    = step_attack_sim(args.target, args.dry_run, args.app)
    analysis_json            = step_analyzer(args.log_dir)
    results["analyzer"]      = bool(analysis_json)
    results["ab_test"]       = step_ab_test(args.target, args.log_dir, args.dry_run)
    results["fp_fn"]         = (False if args.skip_fp_fn
                                else step_fp_fn(analysis_json, args.target))

    # AWS 실데이터 수집기 (자격증명 있을 때만 실행)
    results["waf_collect"]   = step_collect_waf()
    results["ct_collect"]    = step_collect_cloudtrail()
    results["prowler"]       = step_collect_prowler()
    results["cmk_collect"]   = step_collect_cmk()
    results["config_diff"]   = step_collect_config_diff()
    results["s3_security"]   = step_collect_s3_security()

    results["zap"]           = False if args.skip_zap else step_zap(args.target)
    results["ai_report"]     = False if args.skip_ai  else step_ai_report(analysis_json, args.ai_model)
    results["ai_json"]       = step_generate_ai_json(analysis_json)

    # PR 수집은 compliance 빌드 전에 실행 (github_pr.json을 Adapter가 읽음)
    results["pr_collector"]  = step_pr_collector()

    results["compliance"]    = step_compliance_report(analysis_json)
    results["auto_pr"]       = False if args.skip_pr  else step_auto_pr(analysis_json, args.dry_run)
    results["slack_notify"]  = step_notify_slack(analysis_json)
    results["s3_upload"]     = step_upload_s3()

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
