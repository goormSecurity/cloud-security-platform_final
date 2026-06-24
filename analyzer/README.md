# analyzer — WAF 로그 분석 엔진

WAF 로그를 파싱하여 IP별 위험도를 산정하고, AbuseIPDB CTI로 보강한 뒤 JSON으로 출력하는 분석 엔진입니다.  
출력 JSON은 AI 보고서(`ai/`), Grafana 시각화(`monitoring/`), 컴플라이언스 보고서(`compliance/`)에서 공통으로 소비합니다.

---

## 파일 구조

```
analyzer/
├── main.py           # CLI 진입점 — 아래 모듈들을 순서대로 호출
├── waf_analyzer.py   # 핵심 분석 로직 (로그 파싱 · 공격 분류 · 위험도 계산)
├── cti_checker.py    # AbuseIPDB CTI 연동 + 캐시
├── config.py         # 설정값 (버킷명, 위험도 임계값, API 키)
├── sample_logs/      # 로컬 개발용 WAF 로그 샘플
├── live_logs/        # run_pipeline.py가 S3에서 수집한 실시간 로그
└── tests/
    └── test_waf_analyzer.py
```

---

## 실행 방법

```bash
# 로컬 샘플 로그 분석 (sample_logs/)
python analyzer/main.py

# 특정 디렉터리 지정
python analyzer/main.py --source analyzer/logs_merged

# S3 실시간 로그 분석 (AWS 자격증명 필요)
python analyzer/main.py --s3

# AbuseIPDB CTI 보강 (상위 10개 IP)
python analyzer/main.py --cti --cti-top 10
```

**출력:** `output/analysis_YYYYMMDD_HHMMSS.json`

---

## 공격 유형 분류 기준

| 유형 | 탐지 패턴 (정규식) |
|---|---|
| SQLi | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, `information_schema` 등 |
| XSS | `<script>`, `onerror=`, `onload=`, `<svg>`, `javascript:` 등 |
| CommandInjection | `; cat`, `\| whoami`, 역따옴표, `$()` 등 |
| PathTraversal | `../`, `..\`, `/etc/passwd`, URL 인코딩 변형 등 |
| Scanner UA | sqlmap, Nikto, Nmap, Nuclei, Dirbuster 등 User-Agent |

---

## 위험도 계산 공식

```
risk_score (0~100) =
  요청량 점수  (요청 수 / IP_REQUEST_THRESHOLD × 30, 최대 30)
+ 차단율 점수  (block_rate × 30, 최대 30)
+ 공격유형 점수 (유형별 가중치 합산, 최대 20)
+ CTI 점수    (AbuseIPDB confidenceScore / 5, 최대 20)

HIGH   ≥ 70점
MEDIUM ≥ 40점
LOW    < 40점
```

---

## 출력 JSON 스키마

```json
{
  "generated_at": "ISO 8601",
  "summary": {
    "total_requests": 1234,
    "unique_ips": 56,
    "action_counts": { "BLOCK": 0, "ALLOW": 1100, "COUNT": 134 },
    "block_rate": 0.0,
    "high_risk_ips": 2,
    "attack_type_counts": { "SQLi": 66, "XSS": 66, "PathTraversal": 71 }
  },
  "rule_hits": {
    "AWSManagedRulesSQLiRuleSet": 66,
    "AWSManagedRulesCommonRuleSet": 265
  },
  "time_buckets": [{ "hour": "2026-06-22T18:00", "count": 45 }],
  "top_ips": [
    {
      "ip": "1.2.3.4",
      "country": "CN",
      "request_count": 312,
      "block_rate": 0.0,
      "attack_types": ["SQLi", "XSS"],
      "risk_score": 74,
      "risk_level": "HIGH",
      "cti": { "abuseConfidenceScore": 85, "totalReports": 120 }
    }
  ]
}
```

---

## 설정 변경 (`config.py`)

```python
WAF_LOGS_BUCKET = "aws-waf-logs-cloud-sec-dev"   # S3 버킷 이름
AWS_REGION      = "ap-northeast-2"
RISK_HIGH       = 70   # HIGH 임계값
RISK_MEDIUM     = 40   # MEDIUM 임계값
IP_REQUEST_THRESHOLD = 100   # 요청량 점수 기준
```

CTI 활성화는 `.env`에 `ABUSEIPDB_API_KEY` 설정으로 자동 켜집니다.
