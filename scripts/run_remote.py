#!/usr/bin/env python3
"""
run_remote.py — 하이브리드 파이프라인 (로컬 스캔 + EC2 분석 + S3 결과 다운)

원시 WAF 로그는 EC2/S3 밖으로 나오지 않습니다.

[실행 흐름]
0. 코드 동기화 — EC2가 GitHub _final 레포에서 git pull
1. (선택) ZAP 웹 취약점 스캔 — 로컬에서 실행
   (EC2 IP로 스캔 시 WAF 차단 위험 → 로컬 전용)
2. (선택) 공격 시뮬레이션 (attack_runner) — 로컬에서 실행
   (EC2 IP로 공격 시 EC2 자체가 고위험 IP로 탐지됨 → 로컬 전용)
3. (선택) WAF A/B 테스트 — 로컬에서 실행 (sent_attacks.jsonl 기반)
   (EC2에서 실행하면 attack_runner를 EC2에서 다시 실행 → IP 오염 → 로컬 전용)
4. ZAP·공격·ab_test 결과를 EC2로 SCP 전달
5. EC2에서 파이프라인 실행 (--live --skip-attack-sim --skip-ab-test)
   - 원시 WAF 로그: S3에서 직접 읽고 EC2에서만 분석
   - AI 보고서·컴플라이언스·Slack 알림·S3 업로드 모두 EC2에서 처리
6. S3에서 결과물만 로컬로 다운로드
   - AI 보고서(MD), 컴플라이언스 PDF·HTML, WAF 분석 요약 JSON

사용 예:
    python scripts/run_remote.py                        # 전체 실행 (코드 동기화 + ZAP + 공격 + A/B 포함)
    python scripts/run_remote.py --skip-sync            # 코드 동기화 생략
    python scripts/run_remote.py --skip-zap             # ZAP 없이
    python scripts/run_remote.py --skip-attack          # 공격 시뮬레이션 없이
    python scripts/run_remote.py --skip-ab-test         # A/B 테스트 없이
    python scripts/run_remote.py --pull-only            # 최신 S3 결과만 내려받기
    python scripts/run_remote.py --pull-only --date 2026/07/06
    python scripts/run_remote.py --list                 # S3 결과 목록 출력
"""
import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg, now_kst
except Exception:
    def cfg(p, d=None): return d
    def now_kst(fmt=None):
        t = datetime.now(timezone(timedelta(hours=9)))
        return t.strftime(fmt) if fmt else t.isoformat(timespec="seconds")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ── S3에서 내려받을 결과물 패턴 (원시 로그 제외) ─────────────────

_PULL_PATTERNS = [
    lambda n: n.startswith("report_") and n.endswith(".md"),
    lambda n: n.endswith(".pdf"),
    lambda n: n == "report.html",
    lambda n: n.startswith("analysis_") and n.endswith(".json"),
    lambda n: n.startswith("ab_test_") and n.endswith(".json"),
    lambda n: n in ("real_data.json", "ai_analysis.json"),
]


def _is_pullable(key: str) -> bool:
    name = key.split("/")[-1]
    return any(p(name) for p in _PULL_PATTERNS)


# ── 헬퍼 ─────────────────────────────────────────────────────────

def _ssh_opts(ssh_key: str) -> list:
    return ["-i", ssh_key, "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30"]


def _print_step(n: int, title: str):
    print(f"\n\033[1m\033[96m[{n}] {title}\033[0m")
    print("─" * 50)


# ── 0단계: 코드 동기화 ───────────────────────────────────────────

_FINAL_REPO = "https://github.com/goormSecurity/cloud-security-platform_final.git"


def sync_code_to_ec2(ssh_host: str, ssh_user: str, ssh_key: str,
                     remote_path: str) -> bool:
    """EC2에서 git pull로 최신 코드 동기화.

    로컬에서 rsync 대신 EC2가 GitHub에서 직접 pull — Windows 호환, 항상 최신.
    EC2 remote가 구 레포를 가리키고 있으면 _final로 교체 후 pull.
    """
    _print_step(0, f"코드 동기화 (EC2 git pull ← GitHub _final)")

    # 현재 remote 확인 후 _final이 아니면 교체
    fix_remote = (
        f"cd {remote_path} && "
        f"CURRENT=$(git remote get-url origin 2>/dev/null || echo '') && "
        f"if [ \"$CURRENT\" != '{_FINAL_REPO}' ]; then "
        f"  git remote set-url origin {_FINAL_REPO} && "
        f"  echo '[sync] remote → _final'; "
        f"fi"
    )
    subprocess.run(
        ["ssh"] + _ssh_opts(ssh_key) + [f"{ssh_user}@{ssh_host}", fix_remote],
        capture_output=True, timeout=15,
    )

    # git pull
    pull_cmd = (
        f"cd {remote_path} && "
        f"git fetch origin main && "
        f"git reset --hard origin/main 2>&1"
    )
    r = subprocess.run(
        ["ssh"] + _ssh_opts(ssh_key) + [f"{ssh_user}@{ssh_host}", pull_cmd],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60,
    )
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        # 마지막 줄만 출력 (HEAD is now at ...)
        last = [l for l in out.splitlines() if l.strip()][-1] if out else "완료"
        print(f"  ✔ {last}")
        return True
    print(f"  ✘ git pull 실패:\n{out[:300]}")
    return False


# ── 1단계: 로컬 ZAP 스캔 ─────────────────────────────────────────

def run_zap_local(target: str):  # -> Path | None
    """로컬에서 ZAP 스캔 실행 후 결과 파일 경로 반환."""
    _print_step(1, f"ZAP 웹 취약점 스캔 (로컬 Docker) → {target}")
    out_dir = ROOT / "output"
    out_dir.mkdir(exist_ok=True)
    cmd = [
        sys.executable,
        str(ROOT / "security" / "zap_scanner.py"),
        "--target", target,
        "--baseline-only",
        "--out", str(out_dir),
    ]
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print("  ✘ ZAP 스캔 실패")
        return None

    reports = sorted(out_dir.glob("zap_report_*.json"))
    if reports:
        print(f"  ✔ ZAP 완료 → {reports[-1].name}")
        return reports[-1]
    return None


# ── 2단계: 로컬 공격 시뮬레이션 ─────────────────────────────────

def run_attack_local(target: str, app: str = "all"):  # -> Path | None
    """로컬에서 attack_runner 실행 후 sent_attacks.jsonl 경로 반환.

    EC2에서 실행하면 EC2 IP가 WAF 로그에 공격자로 기록되어
    파이프라인 서버 자체가 고위험 IP로 탐지됨 → 로컬 실행 필수.
    """
    _print_step(2, f"공격 시뮬레이션 (로컬) → {target}  app={app}")
    out_path = ROOT / "attack_simulation" / "output" / "sent_attacks.jsonl"
    cmd = [
        sys.executable,
        str(ROOT / "attack_simulation" / "attack_runner.py"),
        "--target", target,
        "--app", app,
    ]
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print("  ✘ 공격 시뮬레이션 실패")
        return None
    if out_path.exists():
        print(f"  ✔ 공격 시뮬레이션 완료 → {out_path.name}")
        return out_path
    print("  ✘ sent_attacks.jsonl 없음")
    return None


# ── 3단계: 로컬 ab_test (sent_attacks.jsonl 기반) ────────────────

def run_ab_test_local(sent_path) -> "Path | None":
    """로컬에서 ab_test 실행 (sent_attacks.jsonl 기반, EC2 IP 오염 방지).

    attack_runner를 EC2에서 다시 실행하지 않고, 이미 로컬에서 실행한
    sent_attacks.jsonl 결과를 사용해 A/B 분석.
    """
    _print_step(3, "WAF A/B 테스트 (로컬, sent_attacks.jsonl 기반)")
    if not sent_path or not Path(sent_path).exists():
        print("  ⊘ sent_attacks.jsonl 없음 — ab_test 스킵")
        return None
    out_dir = ROOT / "output"
    out_dir.mkdir(exist_ok=True)
    cmd = [
        sys.executable,
        str(ROOT / "security" / "ab_test.py"),
        "--from-sent-attacks", str(sent_path),
        "--out", str(out_dir),
    ]
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print("  ✘ ab_test 실패")
        return None
    reports = sorted(out_dir.glob("ab_test_*.json"))
    if reports:
        print(f"  ✔ ab_test 완료 → {reports[-1].name}")
        return reports[-1]
    print("  ✘ ab_test_*.json 없음")
    return None


# ── 4단계: 로컬 결과물 EC2로 전달 ────────────────────────────────

def scp_local_results_to_ec2(zap_path, attack_path, ab_test_path,
                              ssh_host: str, ssh_user: str, ssh_key: str,
                              remote_output_dir: str, remote_attack_dir: str) -> None:
    """ZAP·공격·ab_test 결과를 EC2로 전달."""
    _print_step(4, f"로컬 결과물 EC2 전달 ({ssh_host})")

    files_sent = 0
    if zap_path:
        r = subprocess.run(
            ["scp"] + _ssh_opts(ssh_key) +
            [str(zap_path), f"{ssh_user}@{ssh_host}:{remote_output_dir}/"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            print(f"  ✔ {zap_path.name} → {ssh_host}:{remote_output_dir}/")
            files_sent += 1
        else:
            print(f"  ✘ ZAP SCP 실패: {r.stderr.strip()[:120]}")

    if attack_path:
        # EC2의 attack_simulation/output/ 디렉토리 확보
        subprocess.run(
            ["ssh"] + _ssh_opts(ssh_key) + [f"{ssh_user}@{ssh_host}",
             f"mkdir -p {remote_attack_dir}"],
            capture_output=True, timeout=10,
        )
        r = subprocess.run(
            ["scp"] + _ssh_opts(ssh_key) +
            [str(attack_path), f"{ssh_user}@{ssh_host}:{remote_attack_dir}/"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            print(f"  ✔ {attack_path.name} → {ssh_host}:{remote_attack_dir}/")
            files_sent += 1
        else:
            print(f"  ✘ 공격결과 SCP 실패: {r.stderr.strip()[:120]}")

    if ab_test_path:
        r = subprocess.run(
            ["scp"] + _ssh_opts(ssh_key) +
            [str(ab_test_path), f"{ssh_user}@{ssh_host}:{remote_output_dir}/"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if r.returncode == 0:
            print(f"  ✔ {ab_test_path.name} → {ssh_host}:{remote_output_dir}/")
            files_sent += 1
        else:
            print(f"  ✘ ab_test SCP 실패: {r.stderr.strip()[:120]}")

    if files_sent == 0:
        print("  ⊘ 전달할 로컬 결과물 없음")


# ── 5단계: EC2 파이프라인 원격 실행 ──────────────────────────────

def trigger_ec2_pipeline(ssh_host: str, ssh_user: str, ssh_key: str,
                         remote_path: str, live_hours: int) -> bool:
    """EC2에서 파이프라인 실행 (--live --skip-attack-sim --skip-ab-test). 완료까지 대기."""
    _print_step(5, f"EC2 파이프라인 실행 ({ssh_host})")
    print("  원시 WAF 로그는 EC2/S3에서만 처리됩니다.")
    print("  완료까지 대기 중... (Ctrl+C로 중단 가능)\n")

    cmd = (
        f"cd {remote_path} && "
        f"source .venv/bin/activate 2>/dev/null || true && "
        f"python3 scripts/run_pipeline.py --live --live-hours {live_hours} --skip-attack-sim --skip-ab-test 2>&1"
    )
    r = subprocess.run(
        ["ssh"] + _ssh_opts(ssh_key) + [f"{ssh_user}@{ssh_host}", cmd],
        text=True, encoding="utf-8", errors="replace",
    )
    if r.returncode == 0:
        print("  ✔ EC2 파이프라인 완료")
        return True
    print(f"  ✘ EC2 파이프라인 실패 (exit={r.returncode})")
    return False


# ── 6단계: S3 결과물 로컬 다운로드 ──────────────────────────────

def _latest_prefix(s3, bucket: str, base: str):  # -> str | None
    prefixes = []
    pager = s3.get_paginator("list_objects_v2")
    for yr in pager.paginate(Bucket=bucket, Prefix=base, Delimiter="/"):
        for ycp in yr.get("CommonPrefixes", []):
            for mo in pager.paginate(Bucket=bucket, Prefix=ycp["Prefix"], Delimiter="/"):
                for mcp in mo.get("CommonPrefixes", []):
                    for dy in pager.paginate(Bucket=bucket, Prefix=mcp["Prefix"], Delimiter="/"):
                        for dcp in dy.get("CommonPrefixes", []):
                            prefixes.append(dcp["Prefix"].rstrip("/"))
    return sorted(prefixes)[-1] if prefixes else None


def pull_results(date_str=None):  # date_str: str | None -> Path | None
    """S3 pipeline-results/ 에서 결과물만 로컬 reports/pulled/ 에 저장."""
    _print_step(6, "S3 결과물 로컬 다운로드 (원시 로그 제외)")
    try:
        import boto3
    except ImportError:
        print("  boto3 없음 — pip install boto3")
        return None

    region = cfg("aws.region", "ap-northeast-2")
    bucket = cfg("buckets.audit_evidence", "cloud-sec-audit-evidence-dev")
    base   = "pipeline-results/"
    s3     = boto3.client("s3", region_name=region)

    if date_str:
        prefix = f"{base}{date_str.strip('/')}"
    else:
        print("  최신 날짜 조회 중...")
        prefix = _latest_prefix(s3, bucket, base)
        if not prefix:
            print("  S3에 결과물 없음 — 파이프라인을 먼저 실행하세요")
            return None
        print(f"  최신: {prefix}")

    objects = s3.list_objects_v2(Bucket=bucket, Prefix=prefix + "/").get("Contents", [])
    targets = [o for o in objects if _is_pullable(o["Key"])]

    if not targets:
        print(f"  {prefix}/ 에 결과물 없음")
        return None

    label = prefix.replace(base, "").replace("/", "-")
    dest  = ROOT / "reports" / "pulled" / label
    dest.mkdir(parents=True, exist_ok=True)

    print(f"\n  {len(targets)}개 파일 → {dest}/\n")
    ok = 0
    for obj in targets:
        name = obj["Key"].split("/")[-1]
        try:
            s3.download_file(bucket, obj["Key"], str(dest / name))
            size = obj["Size"]
            print(f"  ✔ {name:<45} ({size:>8,} B)")
            ok += 1
        except Exception as e:
            print(f"  ✘ {name}: {e}")

    # 최신 경로 포인터
    (ROOT / "reports" / "pulled" / "latest.txt").write_text(str(dest), encoding="utf-8")

    print(f"\n  완료 — {ok}/{len(targets)}개 다운로드")
    print(f"  저장 경로: {dest}")
    return dest


def list_available() -> None:
    """S3에 있는 날짜별 결과 목록 출력."""
    try:
        import boto3
    except ImportError:
        print("boto3 없음")
        return

    region = cfg("aws.region", "ap-northeast-2")
    bucket = cfg("buckets.audit_evidence", "cloud-sec-audit-evidence-dev")
    base   = "pipeline-results/"
    s3     = boto3.client("s3", region_name=region)

    prefixes = []
    pager = s3.get_paginator("list_objects_v2")
    for yr in pager.paginate(Bucket=bucket, Prefix=base, Delimiter="/"):
        for ycp in yr.get("CommonPrefixes", []):
            for mo in pager.paginate(Bucket=bucket, Prefix=ycp["Prefix"], Delimiter="/"):
                for mcp in mo.get("CommonPrefixes", []):
                    for dy in pager.paginate(Bucket=bucket, Prefix=mcp["Prefix"], Delimiter="/"):
                        for dcp in dy.get("CommonPrefixes", []):
                            prefixes.append(dcp["Prefix"].rstrip("/"))

    if not prefixes:
        print("S3에 결과물 없음")
        return

    print(f"\n{'날짜':<40}  파일")
    print("─" * 70)
    for pfx in sorted(prefixes, reverse=True)[:15]:
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=pfx + "/").get("Contents", [])
        pullable = [o["Key"].split("/")[-1] for o in objs if _is_pullable(o["Key"])]
        label = pfx.replace(base, "")
        files = ", ".join(pullable[:4]) + ("..." if len(pullable) > 4 else "")
        print(f"  {label:<38}  {files[:55]}")


# ── 메인 ─────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="하이브리드 파이프라인: 로컬 ZAP + EC2 분석 + S3 결과 다운",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "예시:\n"
            "  python scripts/run_remote.py                   # 전체 실행\n"
            "  python scripts/run_remote.py --skip-zap        # ZAP 없이\n"
            "  python scripts/run_remote.py --pull-only       # 최신 결과만 다운\n"
            "  python scripts/run_remote.py --list            # S3 결과 목록\n"
        ),
    )
    p.add_argument("--pull-only", action="store_true",
                   help="EC2 실행 없이 S3 최신 결과만 내려받기")
    p.add_argument("--list",      action="store_true",
                   help="S3 결과 날짜 목록 출력")
    p.add_argument("--date",      default=None, metavar="YYYY/MM/DD",
                   help="특정 날짜 결과 다운로드 (기본: 최신)")
    p.add_argument("--skip-sync",   action="store_true",
                   help="EC2 코드 동기화 건너뜀 (코드 변경 없을 때 시간 단축)")
    p.add_argument("--skip-zap",    action="store_true",
                   help="로컬 ZAP 스캔 건너뜀")
    p.add_argument("--skip-attack", action="store_true",
                   help="로컬 공격 시뮬레이션 건너뜀")
    p.add_argument("--skip-ab-test", action="store_true",
                   help="로컬 A/B 테스트 건너뜀")
    p.add_argument("--target",      default=None, metavar="URL",
                   help="ZAP/공격 대상 URL (생략 시 platform.yaml의 ALB 주소 사용)")
    p.add_argument("--live-hours",  default=24, type=int, metavar="N",
                   help="EC2가 수집할 WAF 로그 시간 범위 (기본: 24)")
    args = p.parse_args()

    # .env 로딩
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

    if args.list:
        list_available()
        return

    if args.pull_only:
        dest = pull_results(date_str=args.date)
        sys.exit(0 if dest else 1)

    # ── 전체 실행 모드 ─────────────────────────────────────────────

    ssh_host  = cfg("servers.analysis_ip", "")
    ssh_user  = cfg("servers.ssh_user", "ec2-user")
    ssh_key   = str(Path(cfg("servers.ssh_key", "~/.ssh/cloud-sec-key2")).expanduser())
    remote_path = cfg("servers.remote_path", "/opt/cloud-security-platform")
    remote_dir  = cfg("servers.remote_dir", f"/opt/cloud-security-platform/output")

    if not ssh_host:
        print("[error] platform.yaml에 servers.analysis_ip 미설정")
        sys.exit(1)

    # 0. 코드 동기화
    if not args.skip_sync:
        sync_code_to_ec2(ssh_host, ssh_user, ssh_key, remote_path)

    zap_path    = None
    attack_path = None

    # 공통 대상 URL 결정
    try:
        from config_loader import alb_target_url
        target = args.target or alb_target_url()
    except Exception:
        target = args.target or ""

    # 1. ZAP 로컬 실행
    if not args.skip_zap:
        if target:
            zap_path = run_zap_local(target)
        else:
            print("[1] ZAP 스캔 스킵 — 대상 URL 없음 (platform.yaml에 app.alb_url 설정 시 자동 사용)")

    # 2. 공격 시뮬레이션 로컬 실행
    if not args.skip_attack:
        if target:
            attack_path = run_attack_local(target)
        else:
            print("[2] 공격 시뮬레이션 스킵 — 대상 URL 없음")

    # 3. 로컬 A/B 테스트 (sent_attacks.jsonl 기반, EC2 IP 오염 방지)
    ab_test_path = None
    if not args.skip_ab_test:
        ab_test_path = run_ab_test_local(attack_path)

    # 4. 로컬 결과물 EC2로 전달
    remote_attack_dir = f"{remote_path}/attack_simulation/output"
    scp_local_results_to_ec2(zap_path, attack_path, ab_test_path,
                             ssh_host, ssh_user, ssh_key,
                             remote_dir, remote_attack_dir)

    # 5. EC2 파이프라인 실행 (attack_sim, ab_test는 EC2에서 스킵)
    ec2_ok = trigger_ec2_pipeline(ssh_host, ssh_user, ssh_key,
                                  remote_path, args.live_hours)

    # 6. S3 결과물 다운로드
    dest = pull_results(date_str=args.date)

    if dest:
        print(f"\n\033[1m\033[92m결과물이 준비됐습니다: {dest}\033[0m")
    sys.exit(0 if (ec2_ok and dest) else 1)


if __name__ == "__main__":
    main()
