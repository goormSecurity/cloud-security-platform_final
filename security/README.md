# security — 보안 테스트 도구

WAF 정책 효과를 검증하는 A/B 테스트와 OWASP ZAP 자동 웹 취약점 스캔 모듈입니다.

---

## 파일 구조

```
security/
├── ab_test.py      # WAF Count 모드 vs Block 모드 탐지율 비교
└── zap_scanner.py  # OWASP ZAP Docker 기반 자동 스캔
```

---

## ab_test.py — WAF A/B 테스트

`attack_runner.py`의 공격 패턴을 `waf_analyzer`의 탐지 규칙에 적용하여 현재 모드(Count)와 Block 모드의 차단율을 비교합니다.

**실행 방법**

```bash
# 기본 실행 (실제 ALB에 요청 전송)
python security/ab_test.py

# 요청 없이 패턴 분석만
python security/ab_test.py --dry-run

# 대상 변경
python security/ab_test.py --target http://your-alb.elb.amazonaws.com

# 특정 로그 디렉터리 기준으로 분석
python security/ab_test.py --log-dir analyzer/sample_logs
```

**비교 항목**

| 항목 | Count 모드 | Block 모드 |
|---|---|---|
| SQLi 탐지 시 동작 | 로그만 기록 | 요청 차단 (403) |
| CommonRuleSet 탐지 시 | 로그만 기록 | 요청 차단 (403) |
| 악성 IP 차단 | 항상 Block (IPSet 기반) | 항상 Block |

> 현재 AWS WAF는 Block 모드로 전환 완료 (`terraform/modules/waf/main.tf` — `override_action { none {} }`)

---

## zap_scanner.py — OWASP ZAP 자동 스캔

Docker로 OWASP ZAP을 실행하여 ALB 엔드포인트에 대한 웹 취약점 스캔을 수행합니다.

**사전 요구사항**

```bash
# Docker Desktop 실행 확인
docker --version

# ZAP 이미지 사전 pull (선택, 파이프라인에서 자동 pull 가능)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

**실행 방법**

```bash
# 기본 실행 (ALB 대상)
python security/zap_scanner.py

# 대상 변경
python security/zap_scanner.py --target http://your-alb.elb.amazonaws.com

# 스캔 강도 조정 (기본: medium)
python security/zap_scanner.py --level low
```

**출력:** `output/zap_report_YYYYMMDD_HHMMSS.json`

**결과 예시**

```
알림 24건 | High 0  Medium 3  Low 19
```

| 위험도 | 의미 |
|---|---|
| High | 즉시 조치 필요 (SQL Injection, RCE 등) |
| Medium | 검토 필요 (XSS, CSRF 등) |
| Low | 권고 사항 (보안 헤더 누락 등) |

---

## 파이프라인 통합

`scripts/run_pipeline.py`가 Step 3(A/B 테스트)과 Step 4(ZAP)에서 자동 호출합니다.

```powershell
.\run_local.ps1 -SkipZap   # ZAP 생략
.\run_local.ps1            # ZAP 포함 전체 실행
```
