"""분석 엔진 설정값. platform.yaml 우선, 없으면 환경변수·기본값 사용."""
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# platform.yaml 로더 (scripts/ 패키지 경로 추가)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
try:
    from config_loader import cfg
    _cfg_available = True
except Exception:
    _cfg_available = False
    def cfg(path, default=None):
        return default


class Config:
    # --- 로그 소스 ---
    WAF_LOGS_BUCKET = (
        cfg("buckets.waf_logs")
        or os.getenv("WAF_LOGS_BUCKET", "aws-waf-logs-cloud-sec-dev")
    )
    AWS_REGION = (
        cfg("aws.region")
        or os.getenv("AWS_REGION", "ap-northeast-2")
    )
    LOCAL_LOG_DIR = "./sample_logs"
    OUTPUT_DIR    = "./output"

    # --- 위험도 계산 ---
    IP_REQUEST_THRESHOLD = 100
    RISK_HIGH   = 70
    RISK_MEDIUM = 40

    # --- CTI (AbuseIPDB) ---
    ABUSEIPDB_API_KEY = (
        cfg("integrations.abuseipdb_key")
        or os.getenv("ABUSEIPDB_API_KEY", "")
    ) or None
    ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
    CTI_CACHE_FILE = "./cti_cache.json"
    CTI_ENABLED    = bool(ABUSEIPDB_API_KEY)
