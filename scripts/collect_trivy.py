#!/usr/bin/env python3
"""
collect_trivy.py — Trivy 오픈소스 취약점 스캐너 (컨테이너 이미지 + IaC)

SSH로 앱 서버에 접속해 실행 중인 Docker 이미지를 스캔하거나,
Terraform 코드 정적 분석(trivy config)으로 IaC 오설정을 탐지한다.
AWS 비용 없음 — 100% 오픈소스 (Aqua Security Trivy).

출력: compliance/input/trivy_report.json

사용 예:
    python scripts/collect_trivy.py                    # SSH 자동 감지
    python scripts/collect_trivy.py --mode iac         # Terraform 정적 분석만
    python scripts/collect_trivy.py --mode image       # 컨테이너 이미지만
    python scripts/collect_trivy.py --mode all         # 둘 다
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
try:
    from config_loader import cfg, now_kst
except Exception:
    def cfg(p, d=None): return d
    from datetime import datetime, timezone, timedelta
    def now_kst(fmt=None):
        t = datetime.now(timezone(timedelta(hours=9)))
        return t.strftime(fmt) if fmt else t.isoformat(timespec="seconds")

OUT_FILE = ROOT / "compliance" / "input" / "trivy_report.json"

# 앱 서버에서 실행 중인 이미지 목록 (WAF 뒤 3개 앱)
TARGET_IMAGES = [
    "vulnerables/web-dvwa",          # DVWA
    "bkimminich/juice-shop",         # OWASP Juice Shop
    "ghost:5-alpine",                # Ghost CMS
]


def _ssh_base(host: str, user: str, key: str) -> list[str]:
    return [
        "ssh", "-i", str(Path(key).expanduser()),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        f"{user}@{host}",
    ]


def _trivy_installed_remote(ssh: list[str]) -> bool:
    r = subprocess.run(ssh + ["which trivy || trivy --version 2>/dev/null | head -1"],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def _install_trivy_remote(ssh: list[str]) -> bool:
    """원격 서버에 Trivy 없으면 자동 설치 (Amazon Linux 2)."""
    print("[trivy] 원격 서버에 Trivy 설치 중...")
    cmd = (
        "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh "
        "| sh -s -- -b /usr/local/bin"
    )
    r = subprocess.run(ssh + [cmd], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        # RPM 방식 시도
        rpm_cmd = (
            "sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/"
            "v0.50.1/trivy_0.50.1_Linux-64bit.rpm 2>/dev/null || "
            "sudo yum install -y trivy 2>/dev/null || true"
        )
        subprocess.run(ssh + [rpm_cmd], capture_output=True, text=True, timeout=120)
    r2 = subprocess.run(ssh + ["trivy --version 2>/dev/null | head -1"],
                        capture_output=True, text=True, timeout=15)
    return r2.returncode == 0


def scan_images_ssh(ssh_host: str, ssh_user: str, ssh_key: str) -> list[dict]:
    """SSH로 앱 서버 접속 → 실행 중인 컨테이너 이미지 Trivy 스캔."""
    ssh = _ssh_base(ssh_host, ssh_user, ssh_key)

    if not _trivy_installed_remote(ssh):
        if not _install_trivy_remote(ssh):
            print("[trivy] Trivy 설치 실패 — image 스캔 스킵", file=sys.stderr)
            return []

    results = []
    for image in TARGET_IMAGES:
        print(f"[trivy] 이미지 스캔: {image}")
        cmd = (
            f"trivy image --format json --quiet --no-progress "
            f"--severity CRITICAL,HIGH,MEDIUM {image} 2>/dev/null"
        )
        r = subprocess.run(ssh + [cmd], capture_output=True, text=True, timeout=300)
        if not r.stdout.strip():
            print(f"  → 결과 없음 (이미지 미설치 또는 스킵)")
            continue
        try:
            raw = json.loads(r.stdout)
        except json.JSONDecodeError:
            print(f"  → JSON 파싱 실패")
            continue

        vulns = []
        for res in raw.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                vulns.append({
                    "id":          v.get("VulnerabilityID", ""),
                    "pkg":         v.get("PkgName", ""),
                    "installed":   v.get("InstalledVersion", ""),
                    "fixed":       v.get("FixedVersion", ""),
                    "severity":    v.get("Severity", ""),
                    "title":       (v.get("Title") or "")[:120],
                    "cvss_score":  (v.get("CVSS") or {}).get("nvd", {}).get("V3Score"),
                })

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1

        results.append({
            "image":      image,
            "total":      len(vulns),
            "by_severity": by_sev,
            "top_vulns":  sorted(vulns, key=lambda x: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 9)
            ))[:10],
        })
        print(f"  → CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  MEDIUM={by_sev['MEDIUM']}")

    return results


def scan_iac_local() -> dict:
    """로컬 Terraform 코드 정적 분석 (trivy config)."""
    tf_dir = str(ROOT / "terraform")

    # 로컬 trivy 확인
    r = subprocess.run(["trivy", "--version"], capture_output=True, timeout=10)
    if r.returncode != 0:
        print("[trivy] 로컬 Trivy 없음 — IaC 스캔 스킵 (brew install trivy / apt install trivy)")
        return {"skipped": True, "reason": "trivy not installed locally"}

    print(f"[trivy] IaC 정적 분석: {tf_dir}")
    r = subprocess.run(
        ["trivy", "config", "--format", "json", "--quiet", tf_dir],
        capture_output=True, text=True, timeout=120,
    )

    try:
        raw = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return {"skipped": True, "reason": "json parse error"}

    misconfigs = []
    for res in raw.get("Results", []):
        for m in res.get("Misconfigurations") or []:
            misconfigs.append({
                "id":          m.get("ID", ""),
                "title":       m.get("Title", ""),
                "severity":    m.get("Severity", ""),
                "description": (m.get("Description") or "")[:200],
                "file":        res.get("Target", ""),
            })

    by_sev: dict[str, int] = {}
    for m in misconfigs:
        by_sev[m["severity"]] = by_sev.get(m["severity"], 0) + 1

    print(f"[trivy] IaC 오설정: {len(misconfigs)}건  {by_sev}")
    return {
        "skipped":        False,
        "target":         tf_dir,
        "total":          len(misconfigs),
        "by_severity":    by_sev,
        "misconfigs":     misconfigs[:20],
    }


def main():
    p = argparse.ArgumentParser(description="Trivy 오픈소스 취약점 스캔 (컨테이너 + IaC)")
    p.add_argument("--mode",     default="all", choices=["image", "iac", "all"],
                   help="스캔 모드 (기본: all)")
    p.add_argument("--ssh-host", default="",    help="앱 서버 IP (미입력 시 platform.yaml 참조)")
    p.add_argument("--ssh-user", default="",    help="SSH 사용자 (기본: ec2-user)")
    p.add_argument("--ssh-key",  default="",    help="SSH 키 경로")
    p.add_argument("--out",      default=str(OUT_FILE), help="결과 저장 경로")
    args = p.parse_args()

    ssh_host = args.ssh_host or cfg("servers.analysis_ip", "")
    ssh_user = args.ssh_user or cfg("servers.ssh_user", "ec2-user")
    ssh_key  = args.ssh_key  or cfg("servers.ssh_key",  "~/.ssh/cloud-sec-key2")

    image_results = []
    iac_result    = {}

    if args.mode in ("image", "all"):
        if ssh_host:
            image_results = scan_images_ssh(ssh_host, ssh_user, ssh_key)
        else:
            print("[trivy] --ssh-host 또는 platform.yaml servers.analysis_ip 필요 — image 스캔 스킵")

    if args.mode in ("iac", "all"):
        iac_result = scan_iac_local()

    # 전체 요약
    total_vulns = sum(r.get("total", 0) for r in image_results)
    crit = sum(r.get("by_severity", {}).get("CRITICAL", 0) for r in image_results)
    high = sum(r.get("by_severity", {}).get("HIGH", 0) for r in image_results)

    output = {
        "tool":         "Trivy (Aqua Security, OSS)",
        "collected_at": now_kst(),
        "images": {
            "scanned":       [r["image"] for r in image_results],
            "total_vulns":   total_vulns,
            "critical":      crit,
            "high":          high,
            "results":       image_results,
        },
        "iac": iac_result,
        "summary": {
            "total_vulns":      total_vulns,
            "critical":         crit,
            "high":             high,
            "iac_misconfigs":   iac_result.get("total", 0),
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    print(f"\n[trivy] 저장: {out_path}")
    print(f"[trivy] 컨테이너 취약점: CRITICAL={crit}  HIGH={high}  전체={total_vulns}")
    print(f"[trivy] IaC 오설정: {iac_result.get('total', 0)}건")


if __name__ == "__main__":
    main()
