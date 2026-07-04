#!/usr/bin/env python3
"""
setup.py — Cloud Security Platform 최초 설치 도우미

git clone 직후 이 파일 하나만 실행하면 모든 의존성 설치 + platform.yaml 생성까지 완료된다.

사용 예:
    python scripts/setup.py
    python scripts/setup.py --skip-config   # terraform 없는 환경, platform.yaml 직접 편집
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent.parent

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_GREEN  = "\033[92m"
C_YELLOW = "\033[93m"
C_RED    = "\033[91m"
C_CYAN   = "\033[96m"


def _run(cmd: list, **kwargs) -> int:
    print(f"  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, **kwargs).returncode


def step_python_version() -> bool:
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        print(f"{C_RED}  ✘ Python {major}.{minor} — 3.10 이상 필요{C_RESET}")
        return False
    print(f"{C_GREEN}  ✔ Python {major}.{minor}{C_RESET}")
    return True


def step_pip() -> bool:
    req = ROOT / "requirements.txt"
    if not req.exists():
        print(f"{C_RED}  ✘ requirements.txt 없음{C_RESET}")
        return False
    code = _run([sys.executable, "-m", "pip", "install", "-r", str(req), "--quiet"])
    if code != 0:
        print(f"{C_RED}  ✘ pip install 실패 — 위 오류 확인{C_RESET}")
        return False
    print(f"{C_GREEN}  ✔ 패키지 설치 완료{C_RESET}")
    return True


def step_playwright() -> bool:
    code = _run([sys.executable, "-m", "playwright", "install", "chromium"])
    if code != 0:
        print(f"{C_YELLOW}  ⊘ playwright install 실패 — 컴플라이언스 PDF 생성 불가{C_RESET}")
        print( "     나중에 수동 실행: python -m playwright install chromium")
        return False
    print(f"{C_GREEN}  ✔ Playwright Chromium 설치 완료{C_RESET}")
    return True


def step_platform_yaml(skip_config: bool) -> bool:
    yaml_file = ROOT / "platform.yaml"
    example   = ROOT / "platform.yaml.example"

    if yaml_file.exists():
        print(f"{C_GREEN}  ✔ platform.yaml 이미 존재 — 스킵{C_RESET}")
        return True

    if not example.exists():
        print(f"{C_RED}  ✘ platform.yaml.example 없음{C_RESET}")
        return False

    shutil.copy(example, yaml_file)
    print(f"{C_GREEN}  ✔ platform.yaml 생성 (platform.yaml.example 복사){C_RESET}")

    if skip_config:
        print(f"{C_CYAN}  → platform.yaml 직접 편집 후 python scripts/run_pipeline.py 실행{C_RESET}")
        return True

    print(f"{C_CYAN}  → terraform output으로 자동 채우기 시도...{C_RESET}")
    code = _run([sys.executable, str(ROOT / "scripts" / "generate_config.py")])
    if code != 0:
        print(f"{C_YELLOW}  ⊘ generate_config 실패 (terraform 미적용 또는 CLI 없음){C_RESET}")
        print( "     platform.yaml을 직접 편집하거나 terraform apply 후 재실행:")
        print( "     python scripts/generate_config.py")
    else:
        print(f"{C_GREEN}  ✔ platform.yaml 자동 생성 완료{C_RESET}")
    return True


def main():
    p = argparse.ArgumentParser(description="Cloud Security Platform 설치 도우미")
    p.add_argument("--skip-config", action="store_true",
                   help="platform.yaml 자동 생성 건너뜀 (terraform 없는 환경)")
    args = p.parse_args()

    print(f"\n{C_BOLD}{C_CYAN}{'=' * 55}")
    print( "  Cloud Security Platform — 설치 도우미")
    print(f"{'=' * 55}{C_RESET}")

    steps = [
        ("Python 버전 확인",         step_python_version),
        ("pip 패키지 설치",           step_pip),
        ("Playwright Chromium 설치",  step_playwright),
        ("platform.yaml 구성",        lambda: step_platform_yaml(args.skip_config)),
    ]

    results = []
    for label, fn in steps:
        print(f"\n[{len(results)+1}/{len(steps)}] {label}...")
        results.append(fn())

    passed = sum(results)
    total  = len(results)
    print(f"\n{C_BOLD}{C_CYAN}{'=' * 55}{C_RESET}")
    print(f"  완료: {passed}/{total} 단계 성공")

    if passed == total:
        print(f"\n{C_GREEN}  다음 단계:{C_RESET}")
        print( "    python scripts/run_pipeline.py")
        print( "    python scripts/run_pipeline.py --live   # S3 실시간 로그")
        print( "    python scripts/run_pipeline.py --dry-run  # 테스트 실행")
    else:
        print(f"\n{C_YELLOW}  일부 단계 실패 — 위 오류 확인 후 재시도{C_RESET}")

    print(f"{C_BOLD}{C_CYAN}{'=' * 55}{C_RESET}\n")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
