#!/usr/bin/env python3
"""
collect_trivy.py — Trivy 오픈소스 취약점 스캐너 (컨테이너 이미지 + IaC)

실행 우선순위:
  1. 로컬 Docker → docker run aquasec/trivy  (Docker Desktop이면 바로 실행)
  2. 원격 SSH    → 분석 서버에 Trivy 설치 후 실행
AWS 비용 없음 — 100% 오픈소스 (Aqua Security Trivy).

출력: compliance/input/trivy_report.json

사용 예:
    python scripts/collect_trivy.py                 # 자동 감지
    python scripts/collect_trivy.py --mode iac      # Terraform 정적 분석만
    python scripts/collect_trivy.py --mode image    # 컨테이너 이미지만
    python scripts/collect_trivy.py --mode all      # 둘 다
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

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
TRIVY_IMAGE = "aquasec/trivy:latest"

# WAF 뒤 3개 앱 이미지
TARGET_IMAGES = [
    "vulnerables/web-dvwa",
    "bkimminich/juice-shop",
    "ghost:5-alpine",
]


def _docker_available() -> bool:
    try:
        r = subprocess.run(
            "docker info", shell=True, capture_output=True, timeout=15
        )
        out = (r.stdout or b"").decode("utf-8", errors="replace")
        # returncode 1이어도 출력에 Version이 있으면 Docker 실행 중 (Docker Desktop 경고 허용)
        return "Version" in out or r.returncode == 0
    except Exception:
        return False


def _run_trivy_docker(trivy_args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    """로컬 Docker로 Trivy 실행 (DOCKER_HOST 비움 → 레지스트리 직접 접근)."""
    cmd = ["docker", "run", "--rm",
           "-e", "DOCKER_HOST=",          # Docker 소켓 비우기 (레지스트리 직접 pull)
           "-e", "TRIVY_NON_SSL=false",
           TRIVY_IMAGE] + trivy_args
    return subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)


def scan_images_docker() -> list[dict]:
    """로컬 Docker Trivy로 이미지 스캔."""
    results = []
    for image in TARGET_IMAGES:
        print(f"[trivy] 이미지 스캔: {image}")
        r = _run_trivy_docker([
            "image", "--format", "json", "--quiet", "--no-progress",
            "--severity", "CRITICAL,HIGH,MEDIUM",
            image,
        ], timeout=360)

        raw_out = r.stdout.strip()
        if not raw_out:
            print(f"  → 결과 없음 (pull 실패 또는 스킵)")
            continue
        try:
            raw = json.loads(raw_out)
        except json.JSONDecodeError:
            print(f"  → JSON 파싱 실패")
            continue

        vulns = []
        for res in raw.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                vulns.append({
                    "id":        v.get("VulnerabilityID", ""),
                    "pkg":       v.get("PkgName", ""),
                    "installed": v.get("InstalledVersion", ""),
                    "fixed":     v.get("FixedVersion", ""),
                    "severity":  v.get("Severity", ""),
                    "title":     (v.get("Title") or "")[:120],
                    "cvss_score": (v.get("CVSS") or {}).get("nvd", {}).get("V3Score"),
                })

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for v in vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1

        results.append({
            "image":       image,
            "total":       len(vulns),
            "by_severity": by_sev,
            "top_vulns":   sorted(
                vulns,
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x["severity"], 9)
            )[:10],
        })
        print(f"  → CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  MEDIUM={by_sev['MEDIUM']}")

    return results


def scan_iac_docker() -> dict:
    """Docker Trivy로 Terraform IaC 정적 분석."""
    tf_dir = ROOT / "terraform"
    print(f"[trivy] IaC 정적 분석: {tf_dir}")

    # Windows 경로를 Docker volume용으로 변환
    tf_mount = str(tf_dir).replace("\\", "/")
    if tf_mount[1] == ":":   # C:/... → /c/...
        tf_mount = "/" + tf_mount[0].lower() + tf_mount[2:]

    r = subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{tf_mount}:/tf:ro",
         TRIVY_IMAGE,
         "config", "--format", "json", "--quiet", "/tf"],
        capture_output=True, text=True, timeout=120,
    )

    raw_out = (r.stdout or "").strip()
    if not raw_out:
        return {"skipped": False, "total": 0, "by_severity": {}, "misconfigs": []}

    try:
        raw = json.loads(raw_out)
    except json.JSONDecodeError:
        return {"skipped": True, "reason": "json parse error", "total": 0}

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
        "skipped":     False,
        "target":      "terraform/",
        "total":       len(misconfigs),
        "by_severity": by_sev,
        "misconfigs":  misconfigs[:20],
    }


def scan_iac_ssh(ssh_host: str, ssh_user: str, ssh_key: str) -> dict:
    """terraform 파일을 원격 서버에 올려 trivy config로 IaC 정적 분석."""
    key_path = str(Path(ssh_key).expanduser())
    tf_dir = ROOT / "terraform"
    print(f"[trivy] IaC 정적 분석 (SSH: {ssh_host})")

    # terraform/ 디렉토리 업로드 (scp)
    scp_cmd = [
        "scp", "-r", "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        str(tf_dir),
        f"{ssh_user}@{ssh_host}:/tmp/trivy_tf",
    ]
    subprocess.run(scp_cmd, capture_output=True, timeout=30)

    # trivy config 실행
    ssh = ["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10", f"{ssh_user}@{ssh_host}"]
    r = subprocess.run(
        ssh + ["trivy config --format json --quiet /tmp/trivy_tf 2>/dev/null; rm -rf /tmp/trivy_tf"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
    )

    raw_out = (r.stdout or "").strip()
    if not raw_out:
        return {"skipped": False, "total": 0, "by_severity": {}, "misconfigs": []}
    try:
        raw = json.loads(raw_out)
    except json.JSONDecodeError:
        return {"skipped": True, "reason": "json parse error", "total": 0}

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
        "skipped":     False,
        "target":      "terraform/",
        "total":       len(misconfigs),
        "by_severity": by_sev,
        "misconfigs":  misconfigs[:20],
    }


def scan_images_ssh(ssh_host: str, ssh_user: str, ssh_key: str) -> list[dict]:
    """SSH 원격 서버에서 Trivy 이미지 스캔 (Docker 사용)."""
    key_path = str(Path(ssh_key).expanduser())
    ssh = ["ssh", "-i", key_path, "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10", f"{ssh_user}@{ssh_host}"]

    results = []
    for image in TARGET_IMAGES:
        print(f"[trivy] SSH 이미지 스캔: {image}")
        cmd = (
            f"docker run --rm aquasec/trivy image --format json "
            f"--quiet --no-progress --severity CRITICAL,HIGH,MEDIUM {image} 2>/dev/null"
        )
        r = subprocess.run(ssh + [cmd], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=360)
        raw_out = (r.stdout or "").strip()
        if not raw_out:
            continue
        try:
            raw = json.loads(raw_out)
        except json.JSONDecodeError:
            continue

        vulns = []
        for res in raw.get("Results", []):
            for v in res.get("Vulnerabilities") or []:
                vulns.append({
                    "id": v.get("VulnerabilityID", ""),
                    "pkg": v.get("PkgName", ""),
                    "installed": v.get("InstalledVersion", ""),
                    "fixed": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", ""),
                    "title": (v.get("Title") or "")[:120],
                    "cvss_score": (v.get("CVSS") or {}).get("nvd", {}).get("V3Score"),
                })

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for v in vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        results.append({"image": image, "total": len(vulns),
                        "by_severity": by_sev, "top_vulns": vulns[:10]})
        print(f"  → CRITICAL={by_sev['CRITICAL']}  HIGH={by_sev['HIGH']}  MEDIUM={by_sev['MEDIUM']}")

    return results


def main():
    p = argparse.ArgumentParser(description="Trivy 오픈소스 취약점 스캔 (컨테이너 + IaC)")
    p.add_argument("--mode",     default="all", choices=["image", "iac", "all"])
    p.add_argument("--ssh-host", default="")
    p.add_argument("--ssh-user", default="")
    p.add_argument("--ssh-key",  default="")
    p.add_argument("--out",      default=str(OUT_FILE))
    args = p.parse_args()

    local_docker = _docker_available()
    ssh_host = args.ssh_host or cfg("servers.analysis_ip", "")
    ssh_user = args.ssh_user or cfg("servers.ssh_user", "ec2-user")
    ssh_key  = args.ssh_key  or cfg("servers.ssh_key",  "~/.ssh/cloud-sec-key2")

    image_results = []
    iac_result    = {}

    # 앱 서버 IP: platform.yaml에 없으면 직접 지정 가능
    app_server_ip = cfg("servers.app_ip", "")

    if args.mode in ("image", "all"):
        # 이미지 스캔: 앱 서버(컨테이너 실행 중) 우선 → 분석 서버 → 로컬 Docker
        img_ssh_host = args.ssh_host or app_server_ip or ssh_host
        if img_ssh_host:
            print(f"[trivy] SSH 이미지 스캔: {img_ssh_host}")
            image_results = scan_images_ssh(img_ssh_host, ssh_user, ssh_key)
        elif local_docker:
            print("[trivy] 로컬 Docker 모드")
            image_results = scan_images_docker()
        else:
            print("[trivy] Docker 없음, SSH 설정 없음 - image 스캔 스킵")

    if args.mode in ("iac", "all"):
        iac_ssh = args.ssh_host or app_server_ip or ssh_host
        if iac_ssh:
            iac_result = scan_iac_ssh(iac_ssh, ssh_user, ssh_key)
        elif local_docker:
            iac_result = scan_iac_docker()
        else:
            print("[trivy] Docker 없음 - IaC 스캔 스킵")
            iac_result = {"skipped": True, "reason": "no docker"}

    total_vulns = sum(r.get("total", 0) for r in image_results)
    crit = sum(r.get("by_severity", {}).get("CRITICAL", 0) for r in image_results)
    high = sum(r.get("by_severity", {}).get("HIGH", 0) for r in image_results)

    output = {
        "tool":         "Trivy (Aqua Security, OSS)",
        "collected_at": now_kst(),
        "images": {
            "scanned":     [r["image"] for r in image_results],
            "total_vulns": total_vulns,
            "critical":    crit,
            "high":        high,
            "results":     image_results,
        },
        "iac": iac_result,
        "summary": {
            "total_vulns":    total_vulns,
            "critical":       crit,
            "high":           high,
            "iac_misconfigs": iac_result.get("total", 0),
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")

    print(f"\n[trivy] 저장: {out_path}")
    print(f"[trivy] 컨테이너 취약점: CRITICAL={crit}  HIGH={high}  전체={total_vulns}")
    print(f"[trivy] IaC 오설정: {iac_result.get('total', 0)}건")


if __name__ == "__main__":
    main()
