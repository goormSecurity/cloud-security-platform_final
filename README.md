# AI 기반 클라우드 보안 운영 자동화 및 컴플라이언스 대응 플랫폼

2026 구름 정보보호 과정 17회차 세미프로젝트 파이널 프로젝트

## 📋 프로젝트 개요

AWS WAF 로그를 수집·분석하고 AI를 활용하여 설명 가능한 보안 정책 개선안을 제시하며, GitOps 기반의 변경관리와 컴플라이언스 증적을 자동화하는 플랫폼입니다.

### 핵심 특징
- **오픈소스 기반**: 관리형 서비스(Splunk, Security Hub) 비용 최소화
- **투명한 분석**: Python 코드로 공개된 분석 로직
- **설명 가능한 AI**: 로컬 LLM(Ollama)으로 할루시네이션 방지
- **자동 증적**: GitOps 기반 자동 컴플라이언스 기록
- **비용 사전 예측**: Infracost 연동으로 정책 변경 비용 자동 계산

---

## 📁 프로젝트 구조

```
cloud-security-platform/
├── analyzer/                    # WAF 로그 분석 엔진
│   ├── config.py               # 설정 관리
│   ├── waf_analyzer.py          # 핵심 분석 로직 (로그 파싱, 공격 분류, 위험도 계산)
│   ├── cti_checker.py           # AbuseIPDB 연동
│   ├── main.py                  # CLI 진입점
│   ├── requirements.txt          # 의존성
│   └── tests/                   # 테스트 파일
│
├── attack_simulation/           # 공격 시뮬레이터
│   ├── attack_runner.py         # WAF 로그 생성용 12가지 공격 패턴
│   └── README.md
│
├── monitoring/                  # Grafana 시각화
│   ├── docker-compose.yml       # Grafana + Loki 컨테이너 설정
│   ├── json_server.py           # Flask 기반 JSON API 서버
│   ├── dashboards/              # Grafana 대시보드 JSON
│   └── README.md
│
├── terraform/                   # AWS 인프라 코드
│   ├── main.tf
│   ├── provider.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── backend.tf
│   └── modules/                 # 모듈화된 리소스
│
└── README.md                    # 이 파일
```

---

## 🚀 시작하기

### 필수 요구사항
- Python 3.8+
- Git
- Docker & Docker Compose (Grafana 실행용)
- AWS 계정 (WAF, S3, CloudTrail 활성화)

### 1. 저장소 클론
```bash
git clone https://github.com/goormSecurity/cloud-security-platform.git
cd cloud-security-platform
```

### 2. 분석 엔진 설정

**의존성 설치**:
```bash
pip install -r analyzer/requirements.txt
```

**.env 파일 생성** (AbuseIPDB API 키 선택사항):
```bash
cp .env.example .env
# .env 파일 열어서 ABUSEIPDB_API_KEY 설정 (선택사항)
```

**로그 분석 실행**:
```bash
# 로컬 샘플 로그 분석
python analyzer/main.py

# S3에서 직접 분석
python analyzer/main.py --s3

# CTI 데이터 추가 조회
python analyzer/main.py --cti --cti-top 10
```

결과: `output/analysis_YYYYMMDD_HHMMSS.json`

### 3. 공격 시뮬레이션

**공격 패턴 목록 확인**:
```bash
python attack_simulation/attack_runner.py --dry-run
```

**공격 시뮬레이션 실행**:
```bash
# 모든 공격 패턴 1회씩 전송
python attack_simulation/attack_runner.py

# 특정 패턴만 실행 (SQLi, XSS)
python attack_simulation/attack_runner.py --category sqli xss

# 각 패턴 3회, 0.5초 간격
python attack_simulation/attack_runner.py --count 3 --delay 0.5
```

결과: `output/sent_attacks.jsonl`

### 4. Grafana 모니터링

**Grafana 실행**:
```bash
cd monitoring
docker-compose up -d
```

**접속**:
- URL: http://localhost:3000
- 기본 계정: admin / admin123!

**JSON 데이터 서버 실행**:
```bash
python json_server.py
```

---

## 📊 데이터 흐름

```
1. 공격 시뮬레이션
   └─→ ALB + WAF 거침 → S3에 로그 저장

2. 로그 분석
   ├─→ WAF 로그 파싱
   ├─→ 공격 유형 분류 (SQLi, XSS, PathTraversal 등)
   ├─→ 위험도 계산 (0~100점, HIGH/MEDIUM/LOW)
   └─→ CTI 강화 (선택사항: AbuseIPDB)
   └─→ JSON 출력

3. 시각화
   ├─→ JSON API 서버 제공
   └─→ Grafana 대시보드 표시

4. 정책 수립 (향후)
   ├─→ AI 분석 결과 기반 정책 추천
   ├─→ GitOps PR 자동 생성
   ├─→ Infracost 비용 계산
   └─→ 운영자 승인 후 Terraform Apply
```

---

## 🔧 설정 가이드

### analyzer/config.py
```python
# AWS 설정
WAF_LOGS_BUCKET = "your-bucket-name"
AWS_REGION = "ap-northeast-2"

# 위험도 임계값
RISK_HIGH = 70    # 70점 이상: HIGH
RISK_MEDIUM = 40  # 40점 이상: MEDIUM, 40점 미만: LOW

# CTI (Cyber Threat Intelligence)
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CTI_ENABLED = bool(ABUSEIPDB_API_KEY)
```

### attack_simulation/attack_runner.py
```python
# 기본 대상 (CloudFront 적용 시 변경)
DEFAULT_TARGET = "http://cloud-sec-alb-ADDRESS.region.elb.amazonaws.com"
```

---

## 📈 주요 기능

### 1. WAF 로그 분석 엔진 (analyzer/)

**기능**:
- 로컬 파일 또는 S3에서 WAF 로그 읽기
- 공격 유형 자동 분류 (규칙 + 정규식 기반)
- IP별 위험도 계산 (요청량 + 차단율 + 공격유형 + CTI)
- JSON 형식 출력

**분석 결과 JSON 스키마**:
```json
{
  "generated_at": "ISO 8601",
  "summary": {
    "total_requests": 1000,
    "unique_ips": 50,
    "action_counts": {"BLOCK": 600, "ALLOW": 400, "COUNT": 0},
    "block_rate": 0.60,
    "high_risk_ips": 5,
    "attack_type_counts": {"SQLi": 100, "XSS": 50}
  },
  "top_ips": [
    {
      "ip": "192.0.2.1",
      "country": "US",
      "risk_score": 85,
      "risk_level": "HIGH",
      "attack_types": ["SQLi", "PathTraversal"],
      "cti": {
        "abuseConfidenceScore": 75,
        "totalReports": 15
      }
    }
  ],
  "time_buckets": [...]
}
```

### 2. 공격 시뮬레이터 (attack_simulation/)

**공격 패턴** (12가지):
- SQLi: Boolean-based, UNION SELECT, Stacked queries
- XSS: `<script>`, `<img onerror>`, `<svg onload>`
- Path Traversal: `../`, URL 인코딩
- Command Injection: `;`, `|`, 역따옴표
- Scanner UA: sqlmap, Nikto

**고유 추적**:
- 각 요청에 `X-Attack-Sim` 헤더 + `asid` 쿼리 파라미터
- WAF 로그에서 정확하게 추적 가능

### 3. Grafana 대시보드 (monitoring/)

**패널**:
1. 상위 IP 요청 수 (Bar 차트)
2. 시간대별 요청 수 (Line 차트)
3. WAF 룰 탐지 (Bar 차트)
4. 공격 유형 분포 (Pie 차트)

---

## 🔐 보안 고려사항

1. **API 키**: `.env` 파일은 `.gitignore`에 포함 (공유 금지)
2. **로그**: S3에는 접근 제어 필수 (KMS 암호화 권장)
3. **Grafana**: 기본 계정 변경 필수 (운영 환경)
4. **WAF 룰**: 테스트 환경에서는 COUNT 모드, 운영에서는 BLOCK 모드

---

## 📚 팀 역할 분담

| 역할 | 담당자 | 담당 영역 |
|------|--------|---------|
| 팀장 | 유지원 | 전체 조율, 산출물 검수 |
| 인프라 | 천혜수 | Terraform, AWS 배포 |
| 분석 | 박소연 | Python 분석 엔진, 데이터 시각화 |
| AI | 송일환 | LangChain + Ollama 연동 |
| 보안 테스트 | 현수민 | 공격 시뮬레이션, 검증 |
| 컴플라이언스 | 김병옥 | ISMS-P 매핑, 리포트 생성 |

---

## 🔄 개발 흐름

1. **feature/** 브랜치에서 기능 개발
2. **Pull Request** 생성 (코드 검토)
3. **main** 브랜치로 병합
4. **GitHub Actions** (향후): 자동 테스트, 배포

---

## 🚧 향후 계획

### 단기 (향후 2주)
- [ ] Python 분석 규칙 고도화
- [ ] Grafana 대시보드 추가 패널
- [ ] 실시간 알림 기능 (Slack 연동)

### 중기 (1개월)
- [ ] Wazuh 연동 SIEM 기능 확장
- [ ] ISMS-P 전체 통제 항목 매핑
- [ ] AI 챗봇 (보안 현황 자연어 조회)

### 장기 (3개월)
- [ ] 멀티 클라우드 확장 (Azure, GCP)
- [ ] 실시간 스트림 분석 (배치 → 실시간)
- [ ] OpenCTI 통합

---

## 📞 문의 및 피드백

프로젝트 관련 질문이나 개선 제안은 이슈(Issues)를 통해 제출해주세요.

---

## 📄 라이선스

[프로젝트 라이선스 정보]

---

## 🙏 감사의 말

팀원들의 헌신적인 개발과 협력에 감사합니다!
