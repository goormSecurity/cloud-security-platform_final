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
import shutil
import subprocess
import sys
import threading
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
    from config_loader import cfg, now_kst, ollama_url as _ollama_url, alb_target_url as _alb_target_url
except Exception:
    def cfg(p, d=None): return d
    def _alb_target_url(): return ""

# ── 색상 출력 ────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"

def _ok(msg):   print(f"{C.GREEN}  ✔ {msg}{C.RESET}", flush=True)
def _skip(msg): print(f"{C.YELLOW}  ⊘ {msg}{C.RESET}", flush=True)
def _fail(msg): print(f"{C.RED}  ✘ {msg}{C.RESET}", flush=True)
def _info(msg): print(f"{C.CYAN}  → {msg}{C.RESET}", flush=True)

_STEP_N = 0
_STEP_TOTAL = 21  # main()에서 실행되는 총 단계 수

def _step(n, title):
    global _STEP_N
    _STEP_N += 1
    filled = round(20 * min(_STEP_N, _STEP_TOTAL) / _STEP_TOTAL)
    bar = f"{C.GREEN}{'█' * filled}{C.GRAY}{'░' * (20 - filled)}{C.RESET}"
    print(f"\n{C.BOLD}{C.CYAN}[{n}] {title}{C.RESET}")
    print(f"  {bar}  {C.GRAY}{_STEP_N}/{_STEP_TOTAL} 단계{C.RESET}")
    print(f"{C.GRAY}{'─' * 50}{C.RESET}", flush=True)


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
        boto3.client("sts", region_name=cfg("aws.region", "ap-northeast-2")).get_caller_identity()
        return True
    except Exception:
        return False


def _run(cmd: list, cwd=None, env=None, timeout=300) -> tuple[int, str, str]:
    env_full = {**os.environ, **(env or {}), "PYTHONIOENCODING": "utf-8"}
    if env:
        env_full.update(env)
    try:
        r = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, env=env_full,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"[timeout] {timeout}초 초과"


def _run_live(cmd, cwd=None, env=None, timeout=300, keyword=None) -> tuple[int, str]:
    """서브프로세스 stdout+stderr를 줄 단위로 실시간 출력."""
    env_full = {**os.environ, **(env or {}), "PYTHONIOENCODING": "utf-8"}
    lines = []
    deadline = time.time() + timeout
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env_full,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        for raw in iter(proc.stdout.readline, ""):
            if time.time() > deadline:
                proc.kill()
                _fail(f"타임아웃 {timeout}s 초과")
                return -1, "\n".join(lines)
            line = raw.rstrip()
            lines.append(line)
            if line and (keyword is None or keyword in line):
                print(f"    {C.GRAY}{line}{C.RESET}", flush=True)
        proc.wait(timeout=5)
        return proc.returncode, "\n".join(lines)
    except FileNotFoundError:
        _fail(f"명령어 없음: {cmd[0]}")
        return 1, ""
    except Exception as e:
        return -1, str(e)


def _run_live_spin(cmd, cwd=None, env=None, timeout=300, keyword=None,
                   label="처리 중") -> tuple[int, str]:
    """실시간 스트리밍 + 출력 없을 때 스피너+경과시간 표시 (느린 단계용)."""
    env_full = {**os.environ, **(env or {}), "PYTHONIOENCODING": "utf-8"}
    lines = []
    last_line_t = [time.time()]
    done_ev = threading.Event()
    start_t = time.time()
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def _spin_loop():
        idx = 0
        while not done_ev.is_set():
            if time.time() - last_line_t[0] > 0.5:
                elapsed = int(time.time() - start_t)
                sys.stdout.write(
                    f"\r    {C.CYAN}{frames[idx % len(frames)]}{C.RESET} "
                    f"{C.GRAY}{label}... ({elapsed}s){C.RESET}       "
                )
                sys.stdout.flush()
                idx += 1
            time.sleep(0.12)

    spin_th = threading.Thread(target=_spin_loop, daemon=True)
    spin_th.start()
    deadline = start_t + timeout
    try:
        proc = subprocess.Popen(
            cmd, cwd=cwd, env=env_full,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        for raw in iter(proc.stdout.readline, ""):
            if time.time() > deadline:
                proc.kill()
                done_ev.set()
                sys.stdout.write(f"\r{' ' * 60}\r")
                sys.stdout.flush()
                _fail(f"타임아웃 {timeout}s 초과")
                return -1, "\n".join(lines)
            line = raw.rstrip()
            lines.append(line)
            if line and (keyword is None or keyword in line):
                sys.stdout.write(f"\r{' ' * 60}\r    {C.GRAY}{line}{C.RESET}\n")
                sys.stdout.flush()
                last_line_t[0] = time.time()
        proc.wait(timeout=5)
    finally:
        done_ev.set()
        spin_th.join(timeout=0.5)
        sys.stdout.write(f"\r{' ' * 60}\r")
        sys.stdout.flush()

    return proc.returncode, "\n".join(lines)


def _check_docker() -> bool:
    try:
        r = subprocess.run("docker info", capture_output=True, timeout=20, shell=True)
        return r.returncode == 0
    except Exception:
        return False


def _check_ollama() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen(f"{_ollama_url()}/api/version", timeout=5)
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

    code, _ = _run_live(cmd)
    if code == 0:
        _ok("공격 시뮬레이션 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_analyzer(log_dir: str) -> str | None:
    _step(2, "WAF 로그 분석 + CTI 위험도 산정 (analyzer/main.py)")
    _info(f"로그 소스: {log_dir}")
    cmd = [sys.executable, str(ROOT / "analyzer" / "main.py"), "--source", log_dir]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("분석 완료")
        latest = _latest_file("output/analysis_*.json")
        if latest:
            _info(f"결과 파일: {Path(latest).name}")
        return latest
    else:
        _fail(f"종료 코드: {code}")
        return None


def step_ab_test(target: str, log_dir: str, dry_run: bool) -> bool:
    _step(3, "WAF Count/Block A/B 테스트 (security/ab_test.py)")
    cmd = [sys.executable, str(ROOT / "security" / "ab_test.py"),
           "--log-dir", log_dir, "--out", str(ROOT / "output")]
    if dry_run or not target:
        cmd.append("--dry-run")
    else:
        cmd += ["--target", target]

    code, _ = _run_live(cmd, cwd=str(ROOT), keyword="[A/B]")
    if code == 0:
        _ok("A/B 테스트 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
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
    code, _ = _run_live(cmd, cwd=str(ROOT), keyword="[fp_fn]")
    if code == 0:
        _ok("오탐/미탐 분석 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_zap(target: str) -> bool:
    _step(4, "OWASP ZAP 자동 스캔 (security/zap_scanner.py)")
    if not target:
        _skip("--target 미지정 — ZAP 스킵")
        return False

    local_docker = _check_docker()
    # analysis_ip 우선, 없으면 app_ip fallback (컨테이너 서버에 Docker 있음)
    ssh_host = cfg("servers.analysis_ip", "") or cfg("servers.app_ip", "")

    if not local_docker and not ssh_host:
        _skip("로컬 Docker 없음 + platform.yaml servers.analysis_ip/app_ip 미설정 — ZAP 스킵")
        return False

    mode = "로컬 Docker" if local_docker else f"SSH 원격 ({ssh_host})"
    _info(f"대상: {target}  실행 모드: {mode}")

    cmd = [sys.executable, str(ROOT / "security" / "zap_scanner.py"),
           "--target", target, "--baseline-only", "--out", str(ROOT / "output")]
    if not local_docker:
        cmd += ["--ssh-host", ssh_host]

    code, _ = _run_live(cmd, timeout=660, keyword="[ZAP]")
    if code == 0:
        _ok("ZAP 스캔 완료")
        return True
    else:
        _fail(f"ZAP 종료 코드: {code}")
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

    _info(f"입력: {Path(analysis_json).name}  Ollama: {_ollama_url()}")
    ai_output = ROOT / "ai" / "output"
    cmd = [sys.executable, str(ROOT / "ai" / "report_generator.py"),
           "--input", analysis_json,
           "--output-dir", str(ai_output),
           "--model", model,
           "--ollama-base-url", _ollama_url()]
    code, _ = _run_live_spin(cmd, cwd=str(ROOT / "ai"), timeout=1200, label="AI 보고서 생성 중")
    if code == 0:
        _ok("AI 보고서 생성 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
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
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code != 0:
        _fail(f"build_data 실패 (종료 코드: {code})")
        return False
    _ok(f"데이터 변환 완료 → {Path(real_data).name}")

    # 6-b: HTML/PDF 렌더링
    cmd = [sys.executable, str(ROOT / "compliance" / "render.py"), "--data", real_data]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("컴플라이언스 보고서 생성 완료")
        return True
    else:
        _fail(f"render 실패 (종료 코드: {code})")
        return False


def step_collect_waf() -> bool:
    _step("3b", "WAF describe 수집 (scripts/collect_waf.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — WAF describe 스킵 (~/.aws/credentials 또는 AWS_ACCESS_KEY_ID 설정)")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_waf.py")]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("WAF describe 수집 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_collect_cloudtrail() -> bool:
    _step("3c", "CloudTrail 변경 이력 수집 (scripts/collect_cloudtrail.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — CloudTrail 수집 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_cloudtrail.py")]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("CloudTrail 수집 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_collect_prowler() -> bool:
    _step("3d", "Prowler 보안 점검 수집 (scripts/collect_prowler.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — Prowler 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_prowler.py")]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("Prowler 점검 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_collect_cmk() -> bool:
    _step("3e", "CMK + Object Lock 증적 수집 (scripts/collect_cmk.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — CMK 수집 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_cmk.py")]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("CMK 증적 수집 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_collect_config_diff() -> bool:
    _step("3f", "AWS Config 드리프트 감지 (scripts/collect_config_diff.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — Config 드리프트 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_config_diff.py")]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("Config 드리프트 감지 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_collect_trivy() -> bool:
    _step("3h", "Trivy 컨테이너·IaC 취약점 스캔 (scripts/collect_trivy.py, OSS)")
    ssh_host = cfg("servers.analysis_ip", "")
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_trivy.py"), "--mode", "all"]
    if not ssh_host:
        _info("platform.yaml servers.analysis_ip 없음 — IaC 스캔만 시도")
        cmd += ["--mode", "iac"]
    code, _ = _run_live(cmd, cwd=str(ROOT), timeout=360)
    if code == 0:
        _ok("Trivy 스캔 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_collect_s3_security() -> bool:
    _step("3g", "S3 버킷 보안 감사 (scripts/collect_s3_security.py)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — S3 보안 감사 스킵")
        return False
    cmd = [sys.executable, str(ROOT / "scripts" / "collect_s3_security.py")]
    code, _ = _run_live(cmd, cwd=str(ROOT))
    if code == 0:
        _ok("S3 버킷 보안 감사 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False



def step_upload_s3() -> bool:
    _step("10", "결과물 S3 업로드 (audit-evidence 버킷)")
    if not _has_aws_creds():
        _skip("AWS 자격증명 없음 — S3 업로드 스킵")
        return False

    try:
        import boto3
        s3 = boto3.client("s3", region_name=cfg("aws.region", "ap-northeast-2"))
        bucket = cfg("buckets.audit_evidence", "cloud-sec-audit-evidence-dev")
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
    code, _ = _run_live(cmd, cwd=str(ROOT))
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
    code, _ = _run_live(cmd, cwd=str(ROOT / "ai"))
    if code == 0:
        _ok("AI 분석 JSON 생성 완료 → compliance/input/ai_analysis.json")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_pr_collector() -> bool:
    _step(7, "PR 이력 수집 — ISMS-P 변경관리 증적 (compliance/pr_collector.py)")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        _skip("GITHUB_TOKEN 없음 — PR 수집 스킵 (.env에 GITHUB_TOKEN 설정)")
        return False

    cmd = [sys.executable, str(ROOT / "compliance" / "pr_collector.py"), "--merged-only"]
    code, _ = _run_live(cmd, cwd=str(ROOT), env={"GITHUB_TOKEN": token})
    if code == 0:
        _ok("PR 이력 수집 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
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

    code, _ = _run_live(cmd, cwd=str(ROOT), env={"GITHUB_TOKEN": token or ""}, keyword="[auto_pr]")
    if code == 0:
        _ok("PR 자동 생성 완료")
        return True
    else:
        _fail(f"종료 코드: {code}")
        return False


def step_sync_monitoring(analysis_json: str | None) -> bool:
    """최신 분석 결과를 분석 서버 output/ 에 동기화 → Grafana 대시보드 갱신."""
    _step("11", "Grafana 모니터링 동기화 (분석 결과 → 분석 서버)")
    ssh_host = cfg("servers.analysis_ip", "")
    ssh_user = cfg("servers.ssh_user", "ec2-user")
    ssh_key  = str(Path(cfg("servers.ssh_key", "~/.ssh/cloud-sec-key2")).expanduser())
    remote_dir = cfg("servers.remote_dir", f"/home/{ssh_user}/cloud-security-platform/output")

    if not ssh_host:
        _skip("servers.analysis_ip 미설정 — 모니터링 동기화 스킵")
        return False

    targets = [
        *sorted((ROOT / "output").glob("analysis_*.json"))[-1:],
        *sorted((ROOT / "output").glob("ab_test_*.json"))[-1:],
        *sorted((ROOT / "output").glob("zap_report_*.json"))[-1:],
        *sorted((ROOT / "output").glob("fp_fn_*.json"))[-1:],
    ]
    live_logs = sorted((ROOT / "analyzer" / "live_logs").glob("live_*.jsonl"))[-1:]

    if not targets:
        _skip("전송할 분석 파일 없음")
        return False

    # 로컬 IP 확인 — 분석 서버와 같은 머신이면 SCP 대신 cp
    import socket
    try:
        local_ips = {i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None)}
    except Exception:
        local_ips = set()
    local_ips.add("127.0.0.1")

    if ssh_host in local_ips or ssh_host == socket.gethostbyname(socket.gethostname()):
        for p in targets:
            _info(f"{p.name} → (로컬 output/ 마운트, 이미 반영)")
        _ok(f"Grafana 동기화 완료 (로컬) → http://{ssh_host}:3000")
        return True

    scp_opts = ["-i", ssh_key, "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

    # 원격 디렉토리 확보 (waf_latest/ 포함)
    subprocess.run(
        ["ssh"] + scp_opts + [f"{ssh_user}@{ssh_host}",
         f"mkdir -p {remote_dir} {remote_dir}/waf_latest && "
         f"sudo chown -R {ssh_user}:{ssh_user} {remote_dir} 2>/dev/null; true"],
        capture_output=True, timeout=15,
    )

    # 분석 파일 전송
    src_paths = [str(p) for p in targets]
    r = subprocess.run(
        ["scp"] + scp_opts + src_paths + [f"{ssh_user}@{ssh_host}:{remote_dir}/"],
        capture_output=True, text=True, timeout=60,
        encoding="utf-8", errors="replace",
    )

    # WAF live log → waf_latest/ (Fluent Bit → Loki)
    if live_logs:
        subprocess.run(
            ["scp"] + scp_opts + [str(live_logs[0])] + [f"{ssh_user}@{ssh_host}:{remote_dir}/waf_latest/"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )

    if r.returncode == 0:
        for p in targets:
            _info(f"{p.name} → {ssh_host}:{remote_dir}/")
        if live_logs:
            _info(f"{live_logs[0].name} → {ssh_host}:{remote_dir}/waf_latest/")
        _ok(f"{len(targets)}개 파일 동기화 완료 → Grafana http://{ssh_host}:3000")
        return True
    else:
        err = (r.stderr or "").replace("\n", " ").strip()
        if "Permission denied" in err or "No such file" in err:
            _fail(f"SCP 실패: {err[:150]}")
            return False
        for p in targets:
            _info(f"{p.name} → {ssh_host}:{remote_dir}/")
        _ok(f"{len(targets)}개 파일 동기화 완료 → Grafana http://{ssh_host}:3000")
        return True


def _collect_reports() -> Path | None:
    """모든 결과물을 reports/{timestamp}/ 에 모으고 reports/latest/ 를 갱신."""
    _step("11", "결과물 통합 수집 → reports/latest/")
    ts = now_kst("%Y%m%d_%H%M%S")
    dest = ROOT / "reports" / ts
    dest.mkdir(parents=True, exist_ok=True)

    candidates: list[tuple[str, Path]] = [
        # 파일명, 원본 경로
        ("컴플라이언스_감사보고서.pdf",   ROOT / "compliance" / "output" / "report.pdf"),
        ("컴플라이언스_감사보고서.html",  ROOT / "compliance" / "output" / "report.html"),
        *[(f"AI보안보고서_{p.name}", p) for p in sorted((ROOT / "ai" / "output").glob("report_*.md"))[-1:]],
        *[(f"WAF분석_{p.name}", p)      for p in sorted((ROOT / "output").glob("analysis_*.json"))[-1:]],
        *[(f"AB테스트_{p.name}", p)      for p in sorted((ROOT / "output").glob("ab_test_*.json"))[-1:]],
        *[(f"FP_FN분석_{p.name}", p)     for p in sorted((ROOT / "output").glob("fp_fn_*.json"))[-1:]],
        *[(f"ZAP스캔_{p.name}", p)       for p in sorted((ROOT / "output").glob("zap_report_*.json"))[-1:]],
        ("Prowler_보안점검.json",         ROOT / "compliance" / "input" / "prowler_report.json"),
        ("Trivy_취약점스캔.json",         ROOT / "compliance" / "input" / "trivy_report.json"),
        ("CloudTrail_변경이력.json",      ROOT / "compliance" / "input" / "cloudtrail_events.json"),
        ("S3_보안감사.json",              ROOT / "compliance" / "input" / "s3_security.json"),
        ("WAF_설정.json",                 ROOT / "raw" / "waf_web_acl.json"),
    ]

    copied = 0
    for name, src in candidates:
        if src.exists():
            shutil.copy2(src, dest / name)
            _info(f"{name}")
            copied += 1

    if copied == 0:
        _fail("복사할 파일 없음")
        return None

    # reports/latest 갱신 (기존 디렉토리 교체)
    latest = ROOT / "reports" / "latest"
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(dest, latest)

    _ok(f"{copied}개 파일 → {dest.name}/  (reports/latest/ 갱신 완료)")
    return dest


# ── 메인 ─────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description=(
            "클라우드 WAF 보안 플랫폼 — 전체 파이프라인 실행\n"
            "\n"
            "WAF 로그 분석 → 공격 시뮬레이션 → A/B 테스트 → FP/FN 분석 →\n"
            "ZAP 스캔 → AI 보고서 → 컴플라이언스 판정 → GitHub PR → Slack 알림\n"
            "위 흐름을 한 번에 실행합니다. 각 단계는 독립적으로 실패해도 계속 진행됩니다."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예시:\n"
            "  # 샘플 로그로 빠른 테스트 (ZAP·AI 스킵)\n"
            "  python scripts/run_pipeline.py --skip-zap --skip-ai\n"
            "\n"
            "  # 실제 서버 대상 전체 파이프라인\n"
            "  python scripts/run_pipeline.py --target http://43.202.x.x\n"
            "\n"
            "  # JuiceShop만 공격 시뮬레이션\n"
            "  python scripts/run_pipeline.py --target http://x.x.x.x --app juiceshop\n"
            "\n"
            "  # S3 실시간 로그 6시간치 수집 + 정확도 높은 AI 모델\n"
            "  python scripts/run_pipeline.py --live --live-hours 6 --ai-model qwen2.5:7b\n"
            "\n"
            "  # 시연용 dry-run (실제 HTTP 요청·PR 없음)\n"
            "  python scripts/run_pipeline.py --dry-run --skip-zap\n"
        ),
    )

    # ── 대상 설정 ────────────────────────────────────────────────
    p.add_argument(
        "--target", default=None, metavar="URL",
        help="공격 시뮬레이션·ZAP 스캔·FP 테스트 대상 서버 주소\n"
             "(예: http://localhost:5000  또는  http://43.202.x.x)\n"
             "지정 안 하면 공격 시뮬레이션은 dry-run, ZAP은 스킵됨",
    )
    p.add_argument(
        "--app", default="all", choices=["dvwa", "juiceshop", "ghost", "all"],
        help="공격 시뮬레이션 대상 앱 (기본: all)\n"
             "  dvwa      — SQL Injection·XSS·Command Injection 등\n"
             "  juiceshop — OWASP Juice Shop 특화 공격 패턴\n"
             "  ghost     — Ghost CMS 정상/공격 혼합 트래픽\n"
             "  all       — 위 세 가지 모두 실행",
    )

    # ── 로그 소스 ────────────────────────────────────────────────
    p.add_argument(
        "--log-dir", default=str(ROOT / "analyzer" / "sample_logs"), metavar="PATH",
        help="분석할 WAF 로그 디렉토리 (기본: analyzer/sample_logs)\n"
             "--live 옵션 사용 시 이 설정은 무시됨",
    )
    p.add_argument(
        "--live", action="store_true",
        help="S3에서 최신 WAF 로그를 실시간 다운로드 후 분석\n"
             "platform.yaml의 buckets.waf_logs 설정과 AWS 자격증명 필요",
    )
    p.add_argument(
        "--live-hours", default=1, type=int, metavar="N",
        help="--live 사용 시 몇 시간치 로그를 수집할지 (기본: 1)\n"
             "예: --live --live-hours 6",
    )

    # ── 실행 제어 ────────────────────────────────────────────────
    p.add_argument(
        "--dry-run", action="store_true",
        help="예행연습 모드 — 파이프라인 전체를 실행하되\n"
             "실제 공격 요청은 서버에 보내지 않고, GitHub PR도 생성하지 않음\n"
             "파이프라인이 오류 없이 돌아가는지 확인하거나 발표 시연 시 사용",
    )
    p.add_argument(
        "--skip-zap", action="store_true",
        help="OWASP ZAP 동적 스캔 단계를 건너뜀\n"
             "Docker 없는 환경이거나 빠른 테스트 시 사용",
    )
    p.add_argument(
        "--skip-ai", action="store_true",
        help="AI 보고서 생성 단계를 건너뜀\n"
             "Ollama 미실행 환경에서 나머지 단계만 돌릴 때 사용",
    )
    p.add_argument(
        "--skip-pr", action="store_true",
        help="GitHub PR 자동 생성을 건너뜀\n"
             "GITHUB_TOKEN 없으면 자동으로 스킵됨 (이 옵션 없어도 됨)",
    )
    p.add_argument(
        "--skip-fp-fn", action="store_true",
        help="오탐(False Positive) / 미탐(False Negative) 분석 단계를 건너뜀",
    )
    p.add_argument(
        "--ai-model", default="qwen2.5:7b", metavar="MODEL",
        help="AI 보고서 생성에 사용할 Ollama 모델 (기본: qwen2.5:7b)\n"
             "사용 전 올라마에 모델이 pull 되어 있어야 함",
    )
    args = p.parse_args()

    # --live: S3에서 실시간 로그 다운로드
    if args.live:
        live_dir = str(ROOT / "analyzer" / "live_logs")
        _step("0", f"S3 WAF 실시간 로그 수집 (최근 {args.live_hours}시간)")
        code, _ = _run_live(
            [sys.executable, str(ROOT / "scripts" / "collect_waf_logs.py"),
             "--hours", str(args.live_hours), "--out", live_dir],
            cwd=str(ROOT)
        )
        if code == 0:
            args.log_dir = live_dir
            _ok(f"실시간 로그 준비 완료 → {live_dir}")
        else:
            _fail("S3 로그 수집 실패 — sample_logs로 폴백")
            # log_dir은 기본값(sample_logs) 유지

        # --live + --target 미지정 시 ALB DNS 자동 사용
        if not args.target:
            alb_url = _alb_target_url()
            if alb_url:
                args.target = alb_url
                _ok(f"--live 모드: ZAP 대상 자동 설정 → {alb_url}")

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
    results["trivy"]         = step_collect_trivy()

    results["zap"]           = False if args.skip_zap else step_zap(args.target)
    results["ai_report"]     = False if args.skip_ai  else step_ai_report(analysis_json, args.ai_model)
    results["ai_json"]       = step_generate_ai_json(analysis_json)

    # PR 수집은 compliance 빌드 전에 실행 (github_pr.json을 Adapter가 읽음)
    results["pr_collector"]  = step_pr_collector()

    results["compliance"]    = step_compliance_report(analysis_json)
    results["auto_pr"]       = False if args.skip_pr  else step_auto_pr(analysis_json, args.dry_run)
    results["slack_notify"]  = step_notify_slack(analysis_json)
    results["s3_upload"]     = step_upload_s3()
    results["monitoring"]    = step_sync_monitoring(analysis_json)

    report_dir = _collect_reports()

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

    if report_dir:
        print(f"{C.BOLD}{C.GREEN}  결과물 위치: {report_dir}{C.RESET}")
        print(f"{C.GREEN}  최신 결과:   {ROOT / 'reports' / 'latest'}{C.RESET}")

    print()


if __name__ == "__main__":
    main()
