#!/usr/bin/env python3
"""
zap_scanner.py — OWASP ZAP 자동화 스캐너

Docker로 ZAP을 실행하여 대상 URL에 대한 활성 스캔을 수행하고
WAF 차단율 검증 결과를 JSON으로 저장한다.

사용 예:
    python security/zap_scanner.py --target http://localhost:5000
    python security/zap_scanner.py --target http://localhost:5000 --baseline-only
    python security/zap_scanner.py --target http://dvwa.local --out output/
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("requests 패키지가 필요합니다: pip install requests")

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_PORT = 8090
ZAP_API_KEY = "cloud-sec-zap-key"
CONTAINER_NAME = "cloud-sec-zap"


class ZAPScanner:
    def __init__(self, target_url: str, port: int = ZAP_PORT, baseline_only: bool = False):
        self.target_url = target_url.rstrip("/")
        self.port = port
        self.baseline_only = baseline_only
        self.api = f"http://localhost:{port}"

    # ── Docker 제어 ──────────────────────────────────────────────

    def _docker_available(self) -> bool:
        return subprocess.run(
            ["docker", "info"], capture_output=True
        ).returncode == 0

    def _pull_image(self):
        print(f"[ZAP] 이미지 확인: {ZAP_IMAGE}")
        subprocess.run(["docker", "pull", ZAP_IMAGE], check=True)

    def start(self):
        if not self._docker_available():
            raise RuntimeError("Docker가 실행 중이지 않습니다. Docker Desktop을 시작하세요.")

        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
        self._pull_image()

        cmd = [
            "docker", "run", "-d",
            "--name", CONTAINER_NAME,
            "-p", f"{self.port}:{self.port}",
            "-e", f"ZAP_PORT={self.port}",
            ZAP_IMAGE,
            "zap.sh", "-daemon",
            "-host", "0.0.0.0",
            "-port", str(self.port),
            "-config", f"api.key={ZAP_API_KEY}",
            "-config", "api.addrs.addr.name=.*",
            "-config", "api.addrs.addr.regex=true",
        ]
        subprocess.run(cmd, check=True)
        print("[ZAP] 컨테이너 시작됨. API 응답 대기 중...")
        self._wait_ready()

    def stop(self):
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
        print("[ZAP] 컨테이너 종료")

    def _wait_ready(self, timeout: int = 120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = requests.get(
                    f"{self.api}/JSON/core/view/version/",
                    params={"apikey": ZAP_API_KEY},
                    timeout=5,
                )
                if r.status_code == 200:
                    print("[ZAP] 준비 완료")
                    return
            except Exception:
                pass
            time.sleep(3)
        raise TimeoutError("ZAP 시작 시간 초과 (120s)")

    # ── 스캔 ─────────────────────────────────────────────────────

    def _zap(self, component: str, view_or_action: str, endpoint: str, **params):
        params["apikey"] = ZAP_API_KEY
        url = f"{self.api}/JSON/{component}/{view_or_action}/{endpoint}/"
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def _wait_progress(self, component: str, endpoint: str, scan_id: str, label: str):
        while True:
            status = self._zap(component, "view", endpoint, scanId=scan_id)
            pct = int(status.get("status", 0))
            print(f"\r[ZAP] {label}: {pct}%", end="", flush=True)
            if pct >= 100:
                print()
                return
            time.sleep(3)

    def run_spider(self):
        print(f"[ZAP] Spider 시작: {self.target_url}")
        resp = self._zap("spider", "action", "scan", url=self.target_url)
        scan_id = resp["scan"]
        self._wait_progress("spider", "status", scan_id, "Spider")

    def run_ajax_spider(self):
        print(f"[ZAP] Ajax Spider 시작: {self.target_url}")
        self._zap("ajaxSpider", "action", "scan", url=self.target_url)
        for _ in range(60):
            status = self._zap("ajaxSpider", "view", "status")
            if status.get("status") == "stopped":
                break
            time.sleep(3)
        print("[ZAP] Ajax Spider 완료")

    def run_active_scan(self):
        print(f"[ZAP] 활성 스캔 시작: {self.target_url}")
        resp = self._zap("ascan", "action", "scan", url=self.target_url, recurse="true")
        scan_id = resp["scan"]
        self._wait_progress("ascan", "status", scan_id, "활성 스캔")

    def get_alerts(self) -> list:
        resp = self._zap("core", "view", "alerts", baseurl=self.target_url)
        return resp.get("alerts", [])

    def get_stats(self) -> dict:
        resp = self._zap("stats", "view", "allSitesStats")
        return resp.get("allSitesStats", {})

    # ── 보고서 ────────────────────────────────────────────────────

    def _summarize(self, alerts: list) -> dict:
        risk_map = {"High": [], "Medium": [], "Low": [], "Informational": []}
        for a in alerts:
            risk = a.get("risk", "Informational")
            risk_map.setdefault(risk, []).append(
                {
                    "name": a.get("alert"),
                    "url": a.get("url"),
                    "description": a.get("description", "")[:200],
                    "solution": a.get("solution", "")[:200],
                    "cwe": a.get("cweid"),
                }
            )

        total = len(alerts)
        blocked_sim = risk_map["High"].__len__() + risk_map["Medium"].__len__()
        block_rate = round(blocked_sim / max(total, 1) * 100, 1)

        return {
            "total_alerts": total,
            "risk_counts": {k: len(v) for k, v in risk_map.items()},
            "block_rate_simulation": f"{block_rate}%",
            "details": risk_map,
        }

    def scan_and_report(self, output_dir: str = "output") -> dict:
        try:
            self.start()
            self.run_spider()
            if not self.baseline_only:
                self.run_active_scan()

            alerts = self.get_alerts()
            summary = self._summarize(alerts)

            result = {
                "generated_at": datetime.now().isoformat(),
                "target_url": self.target_url,
                "scan_type": "baseline" if self.baseline_only else "active",
                **summary,
            }

            Path(output_dir).mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = os.path.join(output_dir, f"zap_report_{ts}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)

            print(f"[ZAP] 보고서 저장: {out_path}")
            print(f"[ZAP] 알림 {result['total_alerts']}건  |  "
                  f"High {result['risk_counts']['High']}  "
                  f"Medium {result['risk_counts']['Medium']}  "
                  f"Low {result['risk_counts']['Low']}")
            return result

        finally:
            self.stop()


def main():
    p = argparse.ArgumentParser(description="OWASP ZAP 자동 스캐너")
    p.add_argument("--target", required=True, help="스캔 대상 URL (예: http://localhost:5000)")
    p.add_argument("--baseline-only", action="store_true", help="Baseline 스캔만 (Active 스캔 생략)")
    p.add_argument("--port", type=int, default=ZAP_PORT, help=f"ZAP API 포트 (기본 {ZAP_PORT})")
    p.add_argument("--out", default="output", help="결과 저장 디렉토리")
    args = p.parse_args()

    scanner = ZAPScanner(args.target, port=args.port, baseline_only=args.baseline_only)
    result = scanner.scan_and_report(output_dir=args.out)
    return 0 if result["risk_counts"]["High"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
