"""
cti_checker.py — AbuseIPDB(위협 인텔리전스) 조회 + 캐시

API 키가 없으면 자동으로 비활성화되어 None을 반환한다(개발 중 막힘 없음).
키 발급: https://www.abuseipdb.com → API → Create Key (무료 1000건/일)
analyzer/.env 에 ABUSEIPDB_API_KEY=... 저장 (절대 커밋 금지)
"""
import ipaddress
import json
import os

from config import Config


class CTIChecker:
    def __init__(self):
        self.enabled = Config.CTI_ENABLED
        self.cache = {}
        if os.path.exists(Config.CTI_CACHE_FILE):
            try:
                with open(Config.CTI_CACHE_FILE, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except (json.JSONDecodeError, OSError):
                self.cache = {}

    @staticmethod
    def _is_public_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def check(self, ip):
        """IP 1건 조회 → {abuseConfidenceScore, totalReports, countryCode} 또는 None."""
        if not self.enabled or not self._is_public_ip(ip):
            return None
        if ip in self.cache:
            return self.cache[ip]

        import requests  # 키 있을 때만 import
        try:
            resp = requests.get(
                Config.ABUSEIPDB_URL,
                headers={"Key": Config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            resp.raise_for_status()
            d = resp.json().get("data", {})
            result = {
                "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
                "totalReports": d.get("totalReports", 0),
                "countryCode": d.get("countryCode", ""),
            }
        except Exception as e:  # 네트워크/쿼터 오류는 분석을 막지 않음
            result = {"error": str(e)}

        self.cache[ip] = result
        return result

    def save_cache(self):
        try:
            with open(Config.CTI_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
