"""분석 엔진 설정값. 조장 공지의 config.py 스펙 + CTI 설정 포함."""
import os

try:
    from dotenv import load_dotenv
    load_dotenv()  # analyzer/.env 에서 ABUSEIPDB_API_KEY 등을 읽음
except ImportError:
    pass


class Config:
    # --- 로그 소스 ---
    WAF_LOGS_BUCKET = "aws-waf-logs-cloud-sec-dev"
    AWS_REGION = "ap-northeast-2"
    LOCAL_LOG_DIR = "./sample_logs"          # 로컬 개발용 (S3에서 받아온 로그)
    OUTPUT_DIR = "./output"

    # --- 위험도 계산 ---
    IP_REQUEST_THRESHOLD = 100               # 이 횟수 기준으로 요청량 점수 환산
    RISK_HIGH = 70
    RISK_MEDIUM = 40

    # --- CTI (AbuseIPDB) ---
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    CTI_CACHE_FILE = "./cti_cache.json"
    CTI_ENABLED = bool(os.getenv("ABUSEIPDB_API_KEY"))   # 키 없으면 자동 비활성
