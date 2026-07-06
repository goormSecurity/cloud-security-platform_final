# AI 기반 클라우드 보안 운영 자동화 및 컴플라이언스 대응 플랫폼

2026 구름 정보보호 17회차 파이널 프로젝트 — 6조 구름방범대

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [아키텍처](#2-아키텍처)
3. [전체 파이프라인 흐름](#3-전체-파이프라인-흐름)
4. [기술 스택](#4-기술-스택)
5. [환경 설정](#5-환경-설정)
6. [실행 방법](#6-실행-방법)
7. [결과물 확인](#7-결과물-확인)
8. [개별 단계 실행](#8-개별-단계-실행)
9. [자주 묻는 문제](#9-자주-묻는-문제)
10. [출력 파일 구조](#10-출력-파일-구조)
11. [프로젝트 디렉터리 구조](#11-프로젝트-디렉터리-구조)
12. [팀 구성](#12-팀-구성)

---

## 빠른 시작

```bash
# 저장소 클론
git clone https://github.com/goormSecurity/cloud-security-platform.git
cd cloud-security-platform

# 가상환경 + 의존성
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium

# 환경 변수 설정
cp .env.example .env
# .env 파일을 열어 AWS 자격증명, GitHub Token 입력

# ① 운영 모드 (권장) — EC2에서 분석 후 S3 결과만 로컬 다운
python scripts/run_remote.py --skip-zap   # ZAP 없이 빠르게
python scripts/run_remote.py              # 로컬 ZAP + EC2 분석 전체

# ② 개발/테스트 모드 — 샘플 로그로 로컬 실행 (AWS 불필요)
python scripts/run_pipeline.py --skip-zap --skip-ai
```

### 실행 후 생성되는 결과물

| 파일 | 설명 | 위치 |
|---|---|---|
| `report_*.md` | AI 보안 분석 보고서 (9개 섹션) | `reports/pulled/YYYY-MM-DD/` |
| `report.pdf` | ISMS-P / PCI-DSS 컴플라이언스 증적 | `reports/pulled/YYYY-MM-DD/` |
| `report.html` | 컴플라이언스 HTML (브라우저) | `reports/pulled/YYYY-MM-DD/` |
| `analysis_*.json` | WAF 분석 요약 | `reports/pulled/YYYY-MM-DD/` |

---

## 1. 프로젝트 개요

AWS WAF 로그를 자동 수집·분석하고, EC2 GPU 서버의 로컬 LLM(Ollama + qwen2.5:7b)으로 설명 가능한 AI 보안 보고서를 생성한 뒤, GitOps 기반으로 WAF 차단 정책을 자동 갱신하고 ISMS-P / PCI-DSS 컴플라이언스 증적을 자동화하는 플랫폼입니다.

**핵심 특징**

- **보안 중심 설계** — 원시 WAF 로그는 EC2/S3 밖으로 나오지 않으며, 로컬에는 가공된 보고서만 전달
- **설명 가능한 AI** — EC2 GPU(qwen2.5:7b)로 외부 유출 없이 한국어 9개 섹션 보안 보고서 생성
- **할루시네이션 방지** — `build_key_metrics()`로 핵심 지표를 명시적으로 추출, AWS 계정 ID·CVE 번호가 통계로 오용되는 문제 차단
- **GitOps 자동화** — 고위험 IP 탐지 시 Terraform 변수 수정 PR 자동 생성
- **ISMS-P / PCI-DSS 자동 증적** — CloudTrail·Prowler·CMK·Config·S3·Trivy·ZAP 수집기로 감사 증적 자동화

---

## 2. 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│  로컬 PC                                                         │
│                                                                  │
│  1. ZAP 웹 취약점 스캔 (ALB 대상)                               │
│     → zap_report.json                                           │
│  2. python scripts/run_remote.py                                 │
│     - ZAP 결과 → EC2 SCP 전달                                  │
│     - EC2 파이프라인 SSH 트리거                                  │
│     - S3에서 최종 결과물만 다운로드                             │
│                                                                  │
│  [결과물 저장: reports/pulled/YYYY-MM-DD/]                      │
│  AI 보고서 MD  |  컴플라이언스 PDF  |  분석 요약 JSON           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ SSH 트리거 / SCP
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  EC2 분석 서버 (43.201.194.252)                                  │
│                                                                  │
│  WAF 로그 ←── S3 (aws-waf-logs-cloud-sec-dev)                  │
│  ↓ 분석 (analyzer/)                                             │
│  ↓ A/B 테스트 / FP/FN 분석                                     │
│  ↓ 증적 수집 (CloudTrail / Prowler / Trivy / CMK / Config)      │
│  ↓ AI 보고서 (Ollama qwen2.5:7b GPU)                           │
│  ↓ 컴플라이언스 PDF 생성                                        │
│  ↓ Slack 알림                                                   │
│  ↓ S3 업로드 ──→ cloud-sec-audit-evidence-dev/pipeline-results/ │
│  ↓ Grafana 동기화 (:3000)                                       │
│                                                                  │
│  [원시 WAF 로그는 이 서버 밖으로 나가지 않음]                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. 전체 파이프라인 흐름

```
[Step 0]  S3 WAF 실시간 로그 수집                    collect_waf_logs.py
          S3(aws-waf-logs-cloud-sec-dev) → EC2 내부
          │
[Step 1]  공격 시뮬레이션 (dry-run 또는 실제 전송)   attack_runner.py
          SQLi / XSS / PathTraversal / CommandInjection / ScannerUA
          │
[Step 2]  WAF 로그 분석 + CTI 위험도 산정            analyzer/main.py
          AbuseIPDB API → IP별 위험도 (HIGH/MEDIUM/LOW)
          → output/analysis_YYYYMMDD_HHMMSS.json
          │
[Step 3]  WAF A/B 테스트 (Count vs Block 차단율 비교) ab_test.py
          │
[Step 3b] FP/FN 오탐/미탐 분석                       analyze_fp_fn.py
          │
[Step 3c] WAF WebACL·IPSet describe 수집             collect_waf.py
          → raw/waf_web_acl.json
          │
[Step 3d] CloudTrail 변경 이력 수집 (14일)            collect_cloudtrail.py
          → compliance/input/cloudtrail_events.json
          │
[Step 3e] Prowler 보안 점검                           collect_prowler.py
          MFA·S3 암호화·CloudTrail 로그 검증
          → compliance/input/prowler_report.json
          │
[Step 3f] CMK + Object Lock 증적 수집                 collect_cmk.py
          → compliance/input/{bucket_encryption, kms_key, object_lock ...}.json
          │
[Step 3g] AWS Config 드리프트 감지                    collect_config_diff.py
          → compliance/input/config_diff.json
          │
[Step 3h] S3 버킷 보안 감사                           collect_s3_security.py
          → compliance/input/s3_security.json
          │
[Step 3i] Trivy 컨테이너·IaC 취약점 스캔              collect_trivy.py
          SSH → EC2 앱 서버 Docker 이미지 스캔
          → compliance/input/trivy_report.json
          │
[Step 4]  OWASP ZAP 웹 취약점 스캔                   zap_scanner.py
          ★ 로컬 PC에서 실행 (EC2 스캔 시 WAF 차단 위험)
          → output/zap_report_YYYYMMDD_HHMMSS.json
          │
[Step 5]  AI 보안 보고서 생성                         ai/report_generator.py
          Ollama(qwen2.5:7b) + LangChain → 9개 섹션 Markdown
          할루시네이션 방지: build_key_metrics()로 핵심 지표 명시적 추출
          → ai/output/report_YYYYMMDD_HHMMSS.md
          │
[Step 5b] AI 분석 JSON 변환                           generate_analysis_json.py
          → compliance/input/ai_analysis.json
          │
[Step 6]  GitHub PR 이력 수집                         pr_collector.py
          → compliance/input/github_pr.json
          │
[Step 7]  ISMS-P / PCI-DSS 컴플라이언스 보고서 생성   build_data.py + render.py
          → compliance/output/report.html / report.pdf
          │
[Step 8]  고위험 IP → GitHub PR 자동 생성             auto_pr.py
          → terraform/waf_blocked_ips.auto.tfvars 수정
          → GitHub PR (goormSecurity/cloud-security-platform)
          │
[Step 9]  Slack 알림                                  notify_slack.py
          WAF 모드 판단: waf_web_acl.json OverrideAction 기반
          │
[Step 10] S3 업로드                                   (run_pipeline.py 내장)
          → s3://cloud-sec-audit-evidence-dev/pipeline-results/YYYY/MM/DD/
          │
[Step 11] Grafana 동기화 (EC2 → EC2 output/ 반영)
          → http://43.201.194.252:3000
```

---

## 4. 기술 스택

| 분류 | 기술 | 용도 |
|---|---|---|
| **인프라(IaC)** | Terraform | WAF / ALB / EC2 / S3 / VPC |
| **AWS 서비스** | WAF v2, ALB, S3, CloudTrail, KMS | 실험 대상 인프라 |
| **언어** | Python 3.10+ | 전체 파이프라인 |
| **AI** | Ollama + qwen2.5:7b (EC2 GPU) | 로컬 LLM 한국어 보안 보고서 |
| **AI 파이프라인** | LangChain (langchain-ollama) | LCEL 파이프라인 |
| **할루시네이션 방지** | build_key_metrics() | 핵심 지표 명시적 추출 |
| **위협 인텔리전스** | AbuseIPDB API | IP 위험도 보강 (CTI) |
| **웹 스캔** | OWASP ZAP (Docker) | 자동 웹 취약점 스캔 |
| **보안 점검** | Prowler (boto3 직접 구현) | AWS 설정 보안 점검 |
| **컨테이너 스캔** | Trivy (SSH 원격) | CVE·IaC 취약점 스캔 |
| **보고서 렌더링** | Jinja2 + Playwright | ISMS-P HTML·PDF |
| **형상 관리** | GitHub REST API | PR 이력 수집, IP 차단 PR |
| **알림** | Slack / Discord Webhook | 위험 등급별 색상 알림 |
| **CI/CD** | GitHub Actions | 자동 테스트 |
| **모니터링** | Grafana + Loki + Fluent Bit | EC2 대시보드 시각화 |

### 현재 인프라 상태

| 리소스 | 이름 | 상태 |
|---|---|---|
| WAF WebACL | `cloud-sec-web-acl` | ✅ Block 모드 |
| ALB | `cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com` | ✅ 운영 중 |
| EC2 분석 서버 | `43.201.194.252` | ✅ Grafana + Ollama(qwen2.5:7b) |
| EC2 앱 서버 | `3.36.87.194` | ✅ DVWA + Juice Shop + Ghost |
| S3 WAF 로그 버킷 | `aws-waf-logs-cloud-sec-dev` | ✅ SSE-S3 암호화 |
| S3 증적 버킷 | `cloud-sec-audit-evidence-dev` | ✅ Object Lock COMPLIANCE 365일 |
| CloudTrail | `cloud-sec-trail` | ✅ 로그 검증 활성화 |

---

## 5. 환경 설정

### 5-1. 사전 요구사항

| 항목 | 버전 | 확인 방법 |
|---|---|---|
| Python | 3.10 이상 | `python --version` |
| AWS CLI | v2 | `aws --version` |
| Docker Desktop | 최신 (ZAP 로컬 실행 시) | `docker --version` |
| OpenSSH | - | `ssh -V` |

### 5-2. Python 의존성 설치

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium    # 컴플라이언스 PDF 변환용
```

### 5-3. 환경 변수

```bash
cp .env.example .env
```

`.env`에 아래 값을 입력합니다.

```dotenv
# AWS 자격증명 (필수)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-northeast-2

# GitHub Token (PR 자동 생성용, repo scope 필요)
GITHUB_TOKEN=ghp_...

# Slack / Discord Webhook (선택 — 없으면 알림 스킵)
SLACK_WEBHOOK_URL=https://hooks.slack.com/...

# AbuseIPDB (선택 — 없으면 CTI 없이 실행)
ABUSEIPDB_API_KEY=
```

> `.env`는 `.gitignore`에 포함되어 있어 Git에 절대 커밋되지 않습니다.

### 5-4. platform.yaml 확인

EC2 접속 정보를 확인합니다. (`platform.yaml`은 `.gitignore`로 Git에서 제외)

```yaml
servers:
  analysis_ip: 43.201.194.252
  ssh_user: ec2-user
  ssh_key: ~/.ssh/cloud-sec-key2
  remote_dir: /opt/cloud-security-platform/output
  remote_path: /opt/cloud-security-platform
```

### 5-5. IAM 권한

파이프라인 실행용 IAM 사용자에게 필요한 최소 권한:

```
AmazonWAFReadOnlyAccess
AmazonS3ReadOnlyAccess       ← WAF 로그 읽기
AmazonS3FullAccess            ← 증적 버킷 업로드
CloudTrailReadOnlyAccess
IAMReadOnlyAccess
AmazonKMSReadOnlyAccess
AWSConfigReadOnlyAccess
```

---

## 6. 실행 방법

### 6-1. 운영 모드 — `run_remote.py` (권장)

원시 WAF 로그가 로컬 PC로 내려오지 않습니다. EC2에서 전체 분석 후 S3 결과물만 내려받습니다.

```bash
# 전체 실행 (로컬 ZAP → ZAP 결과 EC2 전달 → EC2 파이프라인 → S3 결과 pull)
python scripts/run_remote.py

# ZAP 없이 빠르게
python scripts/run_remote.py --skip-zap

# EC2 파이프라인 실행 없이 S3 최신 결과만 내려받기
python scripts/run_remote.py --pull-only

# 특정 날짜 결과 내려받기
python scripts/run_remote.py --pull-only --date 2026/07/06

# S3에 있는 날짜별 결과 목록 확인
python scripts/run_remote.py --list

# WAF 로그 수집 시간 범위 조정 (기본 6시간)
python scripts/run_remote.py --live-hours 12
```

**실행 흐름:**

```
1단계: 로컬 ZAP 스캔 → zap_report.json 생성
       (ZAP을 EC2에서 실행 시 WAF가 내부 스캔 트래픽 차단 위험)
2단계: ZAP 결과를 EC2로 SCP 전달
3단계: EC2 SSH 트리거 → 파이프라인 실행 (--live --skip-zap)
       원시 WAF 로그는 EC2/S3에서만 처리됨
4단계: S3에서 최종 결과물만 로컬 다운로드
       reports/pulled/YYYY-MM-DD/ 에 저장
```

### 6-2. 개발/테스트 모드 — `run_pipeline.py`

샘플 로그로 AWS 없이 파이프라인 전체를 테스트합니다.

```bash
# 샘플 로그 기반 전체 실행 (AWS 불필요)
python scripts/run_pipeline.py

# ZAP·AI 없이 빠른 테스트
python scripts/run_pipeline.py --skip-zap --skip-ai

# 특정 옵션 조합
python scripts/run_pipeline.py --skip-zap               # ZAP만 스킵
python scripts/run_pipeline.py --skip-ai                # AI 보고서만 스킵
python scripts/run_pipeline.py --dry-run --skip-zap     # 시연용 (HTTP 전송 없음)
```

> **주의**: `--live` 옵션은 로컬 PC로 원시 WAF 로그를 내려받습니다.  
> 실제 운영에서는 `run_remote.py`를 사용하세요.

### 6-3. 주요 옵션 비교

| 옵션 | `run_remote.py` | `run_pipeline.py` |
|---|---|---|
| 원시 로그 로컬 저장 | **없음** | `--live` 시 있음 |
| AI 모델 | EC2 GPU (qwen2.5:7b) | 로컬 Ollama |
| ZAP 위치 | 로컬 실행 후 EC2 전달 | 로컬 Docker |
| 결과 저장 위치 | `reports/pulled/` | `reports/latest/` |
| AWS 필요 여부 | 필수 | 샘플 로그 시 불필요 |

---

## 7. 결과물 확인

### 7-1. 결과물 열기

```bash
# AI 보안 보고서 (Markdown)
cat reports/pulled/latest.txt    # 저장 경로 확인
ls reports/pulled/YYYY-MM-DD/    # 파일 목록

# Windows에서 결과물 폴더 열기
start reports\pulled\2026-07-06

# 컴플라이언스 PDF
start reports\pulled\2026-07-06\report.pdf

# AI 보고서
notepad reports\pulled\2026-07-06\report_*.md
```

### 7-2. Grafana 대시보드

실시간 WAF 통계·공격 분포·A/B 테스트 결과를 확인합니다.

- URL: `http://43.201.194.252:3000`
- 계정: `admin` / `admin123!`

**대시보드 패널**

| 패널 | 내용 |
|---|---|
| 총 요청 수 / WAF 차단 수 / 차단율 | 최신 분석 요약 |
| ALLOW / BLOCK 비율 | 도넛 차트 |
| 시간대별 요청 추이 | 막대 차트 |
| 공격 유형 분포 / WAF 룰셋 탐지 | 분포 차트 |
| TOP 10 위험 IP | 위험도·국가·공격유형 |
| Count 모드 vs Block 모드 비교 | A/B 테스트 결과 |
| ZAP High/Medium/Low 알림 수 | 취약점 현황 |
| 현재 보안 상태 | WAF 모드·차단율·MFA |

### 7-3. 컴플라이언스 판정 확인

```bash
python -X utf8 compliance/check_output.py
```

출력 예시:
```
판정: 부분 적정
WAF 차단율: 12.7%  |  HIGH 위험 IP: 1개

PCI DSS: e1 충족 / e2 충족 / e3 충족 / e4 충족 / e5 부분충족
ISMS-P : 2.5~2.11 전항목 적정 (KMS·Config 보류 중)
```

---

## 8. 개별 단계 실행

### 공격 시뮬레이션

```bash
# dry-run (전송 없이 목록만)
python scripts/attack_runner.py --dry-run

# 실제 전송 (모든 앱 대상)
python scripts/attack_runner.py --target http://cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com

# 특정 앱·유형만
python scripts/attack_runner.py --app juiceshop --category sqli xss
```

### WAF 로그 분석

```bash
# 샘플 로그 분석
python analyzer/main.py --source analyzer/sample_logs

# 특정 로그 디렉토리
python analyzer/main.py --source analyzer/live_logs
```

### 증적 수집기 개별 실행

```bash
python scripts/collect_waf.py           # WAF WebACL·IPSet
python scripts/collect_cloudtrail.py    # CloudTrail 14일
python scripts/collect_prowler.py       # Prowler 보안 점검
python scripts/collect_cmk.py          # CMK + Object Lock
python scripts/collect_config_diff.py  # Config 드리프트
python scripts/collect_s3_security.py  # S3 버킷 보안
python scripts/collect_trivy.py        # Trivy 취약점 스캔
```

### AI 보고서 생성

```bash
# EC2 Ollama 연결 (platform.yaml의 analysis_ip 사용)
python ai/report_generator.py

# 특정 분석 파일 지정
python ai/report_generator.py --input output/analysis_20260706_223342.json
```

### 컴플라이언스 보고서 생성

```bash
python compliance/build_data.py    # → compliance/real_data.json
python compliance/render.py        # → compliance/output/report.html + report.pdf
```

### 알림 테스트

```bash
python scripts/notify_slack.py     # 최신 분석 결과로 Slack/Discord 전송
```

---

## 9. 자주 묻는 문제

**Q. `run_remote.py` 실행 시 SSH 연결이 안 됩니다.**

`platform.yaml`의 `ssh_key` 경로와 `analysis_ip`를 확인하세요.

```bash
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 "echo OK"
```

---

**Q. S3에 결과물이 없다고 나옵니다 (`--pull-only` 시).**

EC2에서 파이프라인이 아직 실행되지 않았거나 S3 업로드가 실패했습니다.

```bash
# EC2 파이프라인만 실행 (ZAP 없이)
python scripts/run_remote.py --skip-zap

# 또는 날짜 목록 확인
python scripts/run_remote.py --list
```

---

**Q. Grafana 대시보드에 데이터가 없습니다.**

`run_remote.py` 실행 후 자동 동기화됩니다. 수동으로 트리거하려면:

```bash
# EC2 파이프라인 재실행 후 자동 반영 (Grafana 동기화 포함)
python scripts/run_remote.py --skip-zap --pull-only  # 결과만 pull
```

---

**Q. AI 보고서에서 잘못된 수치가 보입니다 (할루시네이션).**

`ai/report_generator.py`의 `build_key_metrics()`가 핵심 지표를 명시적으로 추출합니다.  
허용 수치 목록 방식(`build_allowed_numbers()`)은 AWS 계정 ID 등 노이즈 오염 문제로 제거됐습니다.

보고서 검증:
```bash
python -c "
import json
from pathlib import Path
from ai.report_generator import validate_report
report = Path('reports/pulled/latest').read_text(encoding='utf-8') if Path('reports/pulled/latest').is_file() else ''
# latest.txt에서 경로 읽기
latest = Path('reports/pulled/latest.txt')
if latest.exists():
    dest = Path(latest.read_text().strip())
    for md in dest.glob('report_*.md'):
        txt = md.read_text(encoding='utf-8')
        ok = validate_report(txt, [])
        print('검증:', '통과' if ok else '실패')
"
```

---

**Q. ZAP 스캔을 건너뛰면 컴플라이언스 보고서에 영향이 있나요?**

이전 ZAP 결과가 S3에 있으면 EC2 파이프라인이 자동으로 사용합니다.  
최초 실행 또는 최신 결과가 없을 때만 ZAP 항목이 "데이터 없음"으로 표시됩니다.

---

**Q. `NoCredentialsError` 오류가 납니다.**

`.env` 파일에 AWS 자격증명이 입력되어 있는지 확인하세요.

```bash
python -c "import boto3; boto3.client('s3').list_buckets()"
```

---

**Q. 컴플라이언스 PDF가 생성되지 않습니다.**

```bash
playwright install chromium
python compliance/render.py
```

---

## 10. 출력 파일 구조

```
reports/
├── pulled/
│   ├── 2026-07-06/              # run_remote.py --pull-only로 S3에서 내려받은 결과물
│   │   ├── report_*.md          # AI 보안 보고서
│   │   ├── report.pdf           # 컴플라이언스 감사보고서 PDF
│   │   ├── report.html          # 컴플라이언스 HTML
│   │   ├── analysis_*.json      # WAF 분석 요약
│   │   ├── ab_test_*.json       # A/B 테스트 결과
│   │   └── real_data.json       # 컴플라이언스 매핑 데이터
│   └── latest.txt               # 가장 최신 결과 폴더 경로
│
└── latest/                      # run_pipeline.py 로컬 실행 결과 최신본

output/                          # 로컬 파이프라인 중간 결과물
├── analysis_YYYYMMDD_HHMMSS.json
└── zap_report_YYYYMMDD_HHMMSS.json

compliance/input/                # 증적 원본 (수집기 출력)
├── cloudtrail_events.json       # CloudTrail 14일 이벤트
├── prowler_report.json          # Prowler 보안 점검
├── trivy_report.json            # Trivy 취약점 스캔
├── s3_security.json             # S3 버킷 보안 감사
├── kms_key.json                 # KMS 키 메타데이터
├── object_lock_config.json      # Object Lock 설정
├── config_diff.json             # Config 드리프트
├── ai_analysis.json             # AI 분석 요약 JSON
└── github_pr.json               # GitHub PR 이력

analyzer/live_logs/              # ★ .gitignore — Git 커밋 안됨
                                 # run_pipeline.py --live 시 임시 저장 (개발용)
                                 # run_remote.py 사용 시 이 폴더에 로그가 내려오지 않음
```

---

## 11. 프로젝트 디렉터리 구조

```
cloud-security-platform/
│
├── scripts/
│   ├── run_pipeline.py          # 로컬 파이프라인 실행기 (개발/테스트용)
│   ├── run_remote.py            # ★ 운영 모드 — EC2 실행 + S3 결과 pull
│   ├── collect_waf_logs.py      # S3 WAF 로그 수집
│   ├── collect_waf.py           # WAF WebACL·IPSet describe
│   ├── collect_cloudtrail.py    # CloudTrail 이벤트 수집
│   ├── collect_prowler.py       # Prowler 보안 점검
│   ├── collect_cmk.py          # CMK + Object Lock
│   ├── collect_config_diff.py   # Config 드리프트
│   ├── collect_s3_security.py   # S3 버킷 보안 감사
│   ├── collect_trivy.py         # Trivy 취약점 스캔
│   ├── notify_slack.py          # Slack/Discord 알림
│   ├── auto_pr.py               # 고위험 IP → GitHub PR
│   └── config_loader.py        # 설정 로더
│
├── analyzer/
│   ├── main.py                  # WAF 로그 분석 CLI
│   ├── waf_analyzer.py          # 로그 파싱·공격 분류·위험도
│   ├── cti_checker.py           # AbuseIPDB CTI 연동
│   └── sample_logs/             # 로컬 테스트용 샘플 WAF 로그
│
├── ai/
│   ├── report_generator.py      # LangChain + Ollama 보고서 생성
│   │                            # build_key_metrics(): 할루시네이션 방지
│   ├── prompts.py               # 시스템·유저 프롬프트 템플릿
│   ├── generate_analysis_json.py
│   └── tests/
│       └── test_report_generator.py   # 49개 검증 테스트
│
├── security/
│   ├── ab_test.py               # WAF Count/Block A/B 테스트
│   └── zap_scanner.py           # OWASP ZAP (Docker)
│
├── compliance/
│   ├── build_data.py            # 증적 통합 Adapter
│   ├── render.py                # Jinja2 HTML·PDF 렌더링
│   ├── template.html            # 보고서 HTML 템플릿
│   ├── check_output.py          # 판정 결과 요약 출력
│   ├── pr_collector.py          # GitHub PR 이력 수집
│   └── input/                   # 수집기 출력 파일
│
├── monitoring/
│   ├── docker-compose.yml       # Grafana + Loki + Fluent Bit + JSON API
│   ├── json_server.py           # Flask JSON API (EC2에서 실행)
│   └── dashboards/
│       └── security_dashboard.json   # Grafana 대시보드 정의
│
├── terraform/
│   ├── main.tf / variables.tf / outputs.tf
│   └── modules/
│       ├── waf/   alb/   ec2/   s3/   networking/   logging/
│
├── .env.example                 # 환경 변수 템플릿
├── platform.yaml                # EC2·S3 설정 (gitignore)
└── requirements.txt
```

---

## 12. 팀 구성

| 역할 | 담당자 | 담당 영역 |
|---|---|---|
| 팀장 / 통합 | 유지원 | 전체 파이프라인 통합, 수집기 구현, 산출물 검수 |
| 인프라 | 천혜수 | Terraform IaC, AWS 배포, CI/CD |
| 분석 | 박소연 | WAF 로그 분석 엔진, Grafana 시각화 |
| AI | 송일환 | LangChain + Ollama 보고서 생성기 |
| 보안 테스트 | 현수민 | 공격 시뮬레이션, ZAP 스캐너, A/B 테스트 |
| 컴플라이언스 | 김병옥 | ISMS-P 매핑, 컴플라이언스 보고서 렌더러 |
