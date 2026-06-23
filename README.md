# AI 기반 클라우드 보안 운영 자동화 및 컴플라이언스 대응 플랫폼

2026 구름 정보보호 17회차 파이널 프로젝트 — 6조 구름 방범대

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [구현 현황](#2-구현-현황)
3. [전체 파이프라인 흐름](#3-전체-파이프라인-흐름)
4. [기술 스택](#4-기술-스택)
5. [실험 환경 구성](#5-실험-환경-구성)
6. [환경 변수 설정](#6-환경-변수-설정)
7. [전체 파이프라인 실행](#7-전체-파이프라인-실행)
8. [실행 결과 확인](#8-실행-결과-확인)
9. [개별 단계 실행](#9-개별-단계-실행)
10. [자주 묻는 문제](#10-자주-묻는-문제)
11. [선택: Grafana 모니터링 스택](#11-선택-grafana-모니터링-스택)
12. [출력 파일 구조](#12-출력-파일-구조)
13. [프로젝트 디렉터리 구조](#13-프로젝트-디렉터리-구조)
14. [팀 구성](#14-팀-구성)

---

## 빠른 시작 (처음 실행하는 경우)

처음 클론하는 팀원을 위한 최소 실행 경로입니다. 상세 설명은 각 섹션을 참고하세요.

```powershell
# 1. 클론
git clone https://github.com/goormSecurity/cloud-security-platform.git
cd cloud-security-platform

# 2. 가상환경 + 의존성
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
playwright install chromium

# 3. 환경 변수 (.env 파일 생성 후 AWS/GitHub 키 입력)
copy .env.example .env
notepad .env

# 4. Ollama 모델 준비 (4.7 GB, 최초 1회)
$env:OLLAMA_MODELS = "C:\ollama\models"
ollama pull llama3.1:8b

# 5. 파이프라인 실행 (샘플 로그 기반, ZAP + AI 포함)
.\run_local.ps1
```

실행이 끝나면 아래 파일이 생성됩니다.

| 파일 | 설명 |
|---|---|
| `compliance/output/report.pdf` | ISMS-P 감사 보고서 (제출용) |
| `ai/output/report_*.md` | AI 생성 보안 분석 보고서 |
| `output/analysis_*.json` | WAF 로그 분석 결과 |
| `output/zap_report_*.json` | ZAP 웹 취약점 스캔 결과 |

> **AWS 자격증명 없이도 실행 가능합니다** — `analyzer/sample_logs/`의 샘플 로그로 분석하며, AWS 관련 수집기는 자동으로 스킵됩니다.  
> **Ollama 없이도 실행 가능합니다** — `.\run_local.ps1 -SkipAI`로 AI 보고서 단계를 건너뜁니다.

---

## 2. 구현 현황

### 완료된 항목

| 분류 | 항목 | 비고 |
|---|---|---|
| **파이프라인** | WAF 로그 수집 (S3 실시간 / 샘플 로그) | `collect_waf_logs.py` |
| **파이프라인** | 공격 시뮬레이션 12종 패턴 | `attack_runner.py` |
| **파이프라인** | WAF 로그 분석 + CTI 위험도 산정 | `waf_analyzer.py` + AbuseIPDB |
| **파이프라인** | WAF Count/Block A/B 테스트 | `ab_test.py` |
| **파이프라인** | OWASP ZAP 자동 웹 취약점 스캔 | Docker 기반 |
| **파이프라인** | AI 보안 보고서 생성 | LangChain + Ollama(llama3.1:8b) |
| **파이프라인** | ISMS-P 컴플라이언스 보고서 HTML | Jinja2 렌더링 |
| **파이프라인** | 고위험 IP → GitHub PR 자동 생성 | GitOps 기반 |
| **증적 수집** | WAF WebACL·IPSet describe | `collect_waf.py` |
| **증적 수집** | CloudTrail 변경 이력 14일 | `collect_cloudtrail.py` |
| **증적 수집** | Prowler 보안 점검 (MFA·S3·CloudTrail) | `collect_prowler.py` (boto3 직접 구현) |
| **증적 수집** | CMK + Object Lock 증적 수집기 코드 | `collect_cmk.py` ← 인프라 활성화 시 수집 가능 |
| **증적 수집** | AWS Config 드리프트 감지 수집기 코드 | `collect_config_diff.py` ← 인프라 활성화 시 수집 가능 |
| **증적 수집** | AI 분석 JSON 변환 | `generate_analysis_json.py` |
| **증적 수집** | GitHub PR 이력 수집 | `pr_collector.py` |
| **인프라** | WAF Block 모드 전환 | SQLiRuleSet·CommonRuleSet `none {}` 적용 완료 |
| **인프라** | audit-evidence S3 버킷 생성 | Object Lock COMPLIANCE 365일, SSE-S3 |
| **인프라** | WAF 로그 버킷 SSE-S3 암호화 명시 | 기존 버킷 암호화 설정 Terraform 관리 편입 |
| **CI/CD** | GitHub Actions 자동 테스트 | `.github/workflows/ci.yml` |
| **모니터링** | Grafana + Loki + Fluent Bit 스택 구성 | `monitoring/docker-compose.yml` (별도 실행) |

### 비용 문제로 보류 중인 항목 (프리티어 종료 후 활성화)

| 항목 | 예상 비용 | 활성화 방법 |
|---|---|---|
| **KMS CMK 생성** | ~$1/월 고정 | `terraform/main.tf`에서 `module "kms"` 주석 해제 후 apply |
| **S3 SSE-KMS 전환** | KMS 종속 | `modules/s3/main.tf` SSE 알고리즘 `aws:kms`로 변경 |
| **AWS Config Recorder** | $0.003/건 (리소스 변경 시마다) | `modules/logging/main.tf` 주석 해제 후 apply |

> Terraform 코드는 모두 작성 완료(`modules/kms/`, `modules/logging/` 주석 처리 상태).  
> 프리티어 종료 후 해당 주석만 해제하면 즉시 배포 가능.

### 현재 인프라 상태 (AWS 배포 완료)

| 리소스 | 이름 | 상태 |
|---|---|---|
| WAF WebACL | `cloud-sec-web-acl` | ✅ Block 모드 적용 |
| ALB | `cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com` | ✅ 운영 중 |
| S3 WAF 로그 버킷 | `aws-waf-logs-cloud-sec-dev` | ✅ SSE-S3 암호화 |
| S3 audit-evidence 버킷 | `cloud-sec-audit-evidence-dev` | ✅ Object Lock COMPLIANCE |
| EC2 앱 서버 | `43.203.205.203` (DVWA + Juice Shop) | ✅ 운영 중 |
| CloudTrail | `cloud-sec-trail` | ✅ 로그 검증 활성화 |

---

## 1. 프로젝트 개요

AWS WAF 로그를 자동 수집·분석하고, 로컬 LLM(Ollama)으로 설명 가능한 AI 보안 보고서를 생성한 뒤, GitOps 기반으로 WAF 차단 정책을 자동 갱신하고 ISMS-P 컴플라이언스 증적을 자동화하는 플랫폼입니다.

**핵심 특징**

- **오픈소스 기반** — 관리형 SIEM/SOAR 비용 없이 Python + boto3로 직접 구현
- **설명 가능한 AI** — 로컬 LLM(llama3.1:8b)으로 외부 유출 없이 한국어 보고서 생성
- **GitOps 자동화** — 고위험 IP 탐지 시 Terraform 변수 수정 PR 자동 생성
- **ISMS-P 자동 증적** — CloudTrail·Prowler·CMK·Config 수집기로 감사 증적 자동화

---

## 2. 전체 파이프라인 흐름

```
[run_local.ps1]
      │
      ▼
Step 0   S3 실시간 WAF 로그 수집 (--Live 옵션 시)
         collect_waf_logs.py
         S3(aws-waf-logs-cloud-sec-dev) → analyzer/live_logs/*.jsonl
      │
      ▼
Step 1   공격 시뮬레이션
         attack_simulation/attack_runner.py
         SQLi / XSS / PathTraversal / CommandInjection / Scanner UA → ALB
         → attack_simulation/output/sent_attacks.jsonl
      │
      ▼
Step 2   WAF 로그 분석 + CTI 위험도 산정
         analyzer/main.py + waf_analyzer.py + cti_checker.py
         AbuseIPDB API 조회 → IP별 위험도 (0~100점, HIGH/MEDIUM/LOW)
         → output/analysis_YYYYMMDD_HHMMSS.json
      │
      ▼
Step 3   WAF A/B 테스트 (Count vs Block 탐지율 비교)
         security/ab_test.py
      │
Step 3b  WAF WebACL·IPSet describe 수집
         scripts/collect_waf.py
         → raw/waf_web_acl.json, raw/waf_ipset.json, raw/waf_resources.json
      │
Step 3c  CloudTrail 변경 이력 수집 (14일)
         scripts/collect_cloudtrail.py
         → compliance/input/cloudtrail_events.json
      │
Step 3d  Prowler 보안 점검 (MFA·루트계정·S3암호화·CloudTrail)
         scripts/collect_prowler.py
         → compliance/input/prowler_report.json
      │
Step 3e  CMK + Object Lock 증적 수집 (ISMS-P 2.7)
         scripts/collect_cmk.py
         → compliance/input/{bucket_encryption, kms_key, kms_rotation,
                              kms_key_policy, object_lock_config,
                              object_retention, object_head}.json
      │
Step 3f  AWS Config 드리프트 감지 (ISMS-P 2.10)
         scripts/collect_config_diff.py
         → compliance/input/config_diff.json
      │
      ▼
Step 4   OWASP ZAP 자동 스캔 (Docker 필요, --SkipZap 으로 생략 가능)
         security/zap_scanner.py
         → output/zap_report_YYYYMMDD_HHMMSS.json
      │
      ▼
Step 5   AI 보안 보고서 생성 (Ollama + LangChain)
         ai/report_generator.py
         → ai/output/report_YYYYMMDD_HHMMSS.md
      │
Step 5b  AI 분석 JSON 변환
         ai/generate_analysis_json.py
         → compliance/input/ai_analysis.json
      │
      ▼
Step 6   GitHub PR 이력 수집
         compliance/pr_collector.py
         → compliance/input/github_pr.json
      │
      ▼
Step 7   ISMS-P 컴플라이언스 보고서 생성
         compliance/build_data.py   ← 모든 수집 파일 통합
         → compliance/real_data.json
         compliance/render.py (Jinja2 렌더링)
         → compliance/output/report.html
      │
      ▼
Step 8   고위험 IP → GitHub PR 자동 생성
         scripts/auto_pr.py
         → terraform/waf_blocked_ips.auto.tfvars 수정
         → GitHub PR (goormSecurity/cloud-security-platform)
```

---

## 3. 기술 스택

| 분류 | 기술 | 용도 |
|---|---|---|
| **인프라(IaC)** | Terraform | WAF / ALB / EC2 / S3 / VPC 인프라 코드 관리 |
| **AWS 서비스** | WAF v2, ALB, S3, CloudTrail, KMS | 실험 대상 인프라 |
| **언어** | Python 3.10+ | 전체 파이프라인 로직 |
| **실행 래퍼** | PowerShell | `run_local.ps1` 로컬 실행 |
| **AWS SDK** | boto3 | WAF·S3·CloudTrail·KMS·Config API 호출 |
| **AI** | Ollama + llama3.1:8b | 로컬 LLM 서버 및 모델 |
| **AI 파이프라인** | LangChain (langchain-ollama, langchain-core) | LCEL 파이프라인으로 프롬프트·모델·파서 연결 |
| **위협 인텔리전스** | AbuseIPDB API | IP 위험도 보강 (CTI) |
| **웹 스캔** | OWASP ZAP (Docker) | 자동 웹 취약점 스캔 |
| **보안 점검** | Prowler (boto3 직접 구현) | AWS 설정 보안 점검 |
| **보고서 렌더링** | Jinja2 | ISMS-P HTML 컴플라이언스 보고서 |
| **형상 관리** | GitHub REST API | PR 이력 수집, 차단 IP PR 자동 생성 |
| **CI/CD** | GitHub Actions | 자동 테스트 파이프라인 |
| **모니터링 (선택)** | Grafana + Loki + Fluent Bit | 로그 시각화 (docker-compose 별도 실행) |

---

## 4. 실험 환경 구성

### 4-1. 사전 요구사항

| 항목 | 버전 | 확인 방법 |
|---|---|---|
| Python | 3.10 이상 | `python --version` |
| pip | 최신 | `pip --version` |
| Git | 2.x | `git --version` |
| AWS CLI | v2 | `aws --version` |
| Ollama | 최신 | `ollama --version` |
| Docker Desktop | 최신 (ZAP 사용 시) | `docker --version` |
| PowerShell | 5.1 이상 (Windows) | `$PSVersionTable.PSVersion` |

### 4-2. 저장소 클론

```bash
git clone https://github.com/goormSecurity/cloud-security-platform.git
cd cloud-security-platform
```

### 4-3. Python 가상환경 및 의존성 설치

```bash
# 가상환경 생성 (권장)
python -m venv .venv

# 활성화
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# 전체 의존성 설치
pip install -r requirements.txt

# Playwright 브라우저 설치 (PDF 변환용)
playwright install chromium
```

### 4-4. AWS 인프라 준비

파이프라인은 아래 AWS 리소스가 이미 배포되어 있다고 가정합니다.  
Terraform으로 한번에 배포할 수 있습니다.

**배포된 리소스**

| 리소스 | 이름 / 식별자 |
|---|---|
| WAF WebACL | `cloud-sec-web-acl` (리전: ap-northeast-2) |
| ALB | `cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com` |
| S3 WAF 로그 버킷 | `aws-waf-logs-cloud-sec-dev` |
| CloudTrail | 활성화 상태 필요 |

**Terraform으로 인프라 배포 (최초 1회)**

```bash
cd terraform

# terraform.tfvars 생성
cat > terraform.tfvars <<EOF
aws_region     = "ap-northeast-2"
environment    = "dev"
project_name   = "cloud-sec"
ssh_public_key = "ssh-rsa AAAA..."   # 본인 SSH 공개키
EOF

terraform init
terraform plan
terraform apply
```

> `terraform apply` 완료 후 출력되는 ALB DNS 주소를 `.env`의 `TARGET` 또는 `run_local.ps1`의 `-Target` 인수로 사용합니다.

### 4-5. IAM 권한 설정

파이프라인 실행용 IAM 사용자에게 아래 권한이 필요합니다.

```
AmazonWAFReadOnlyAccess
AmazonS3ReadOnlyAccess
CloudTrailReadOnlyAccess
IAMReadOnlyAccess
AmazonKMSReadOnlyAccess
AWSConfigReadOnlyAccess     ← collect_config_diff.py
```

AWS 콘솔 → IAM → 사용자 → 보안 자격 증명 → **액세스 키 만들기**로 발급한 뒤 `.env`에 입력합니다.

### 4-6. Ollama 설치 및 모델 준비

AI 보고서 생성(Step 5)에 필요합니다. ZAP과 함께 선택적이지만, 컴플라이언스 보고서에 AI 분석 항목이 포함되므로 권장합니다.

**설치**

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows — https://ollama.com/download 에서 설치 파일 다운로드
```

**모델 다운로드**

```bash
ollama pull llama3.1:8b
```

> 모델 크기: 약 4.7 GB. 최초 1회만 다운로드합니다.

**Windows 한글 경로 이슈 해결**

Windows에서 사용자 이름이 한글인 경우 Ollama가 모델 경로를 찾지 못할 수 있습니다.  
`run_local.ps1`은 자동으로 `C:\ollama\models`로 우회하지만, 직접 실행 시에는 아래를 설정합니다.

```powershell
# PowerShell
$env:OLLAMA_MODELS = "C:\ollama\models"
ollama serve    # 별도 터미널에서 실행
```

**동작 확인**

```bash
ollama list     # llama3.1:8b 가 목록에 있어야 함
ollama run llama3.1:8b "hello"   # 응답 확인
```

### 4-7. OWASP ZAP 설치 (선택)

웹 취약점 자동 스캔(Step 4)에 사용합니다. Docker Desktop이 실행 중이면 자동으로 이미지를 받습니다.

```bash
# 이미지 사전 pull (선택 — 파이프라인에서 자동 pull 가능)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

ZAP 없이 실행하려면 `--SkipZap` 옵션을 사용합니다.

---

## 5. 환경 변수 설정

```bash
cp .env.example .env
```

`.env` 파일을 열어 아래 값을 채웁니다.

```dotenv
# ── AWS 자격증명 ─────────────────────────────────────────────────
# 필수. IAM → 보안 자격 증명 → 액세스 키에서 발급
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=ap-northeast-2

# ── GitHub Token ─────────────────────────────────────────────────
# 필수. GitHub → Settings → Developer settings
#       → Personal access tokens → Tokens (classic) → Generate new token
# 필요 scope: repo
GITHUB_TOKEN=ghp_...

# ── AbuseIPDB (선택) ─────────────────────────────────────────────
# https://www.abuseipdb.com/register?plan=free (무료 1,000건/일)
# 없으면 CTI 없이 파이프라인 정상 실행됨
ABUSEIPDB_API_KEY=
```

> `.env` 파일은 `.gitignore`에 포함되어 있어 Git에 커밋되지 않습니다.  
> 절대 공개 저장소에 올리지 마세요.

---

## 6. 전체 파이프라인 실행

모든 실행은 저장소 루트(`cloud-security-platform/`)에서 합니다.

### 기본 실행 (샘플 로그 분석)

```powershell
.\run_local.ps1
```

`analyzer/sample_logs/` 폴더의 로컬 WAF 샘플 로그를 분석합니다.  
ZAP과 AI 보고서는 기본 포함되며, `.env`에 키가 없는 항목은 자동 스킵됩니다.

### 실시간 S3 로그 분석

```powershell
.\run_local.ps1 -Live
.\run_local.ps1 -Live -LiveHours 2    # 최근 2시간 로그 수집
```

S3 버킷(`aws-waf-logs-cloud-sec-dev`)에서 실제 WAF 로그를 수집하여 분석합니다.  
AWS 자격증명이 `.env`에 설정되어 있어야 합니다.

### 옵션 조합 예시

```powershell
# ZAP 스킵 (Docker 없을 때)
.\run_local.ps1 -SkipZap

# AI 보고서 스킵 (Ollama 없을 때)
.\run_local.ps1 -SkipAI

# PR 수집 스킵 (GitHub 토큰 없을 때)
.\run_local.ps1 -SkipPR

# 실시간 로그 + ZAP 스킵 + AI 스킵
.\run_local.ps1 -Live -SkipZap -SkipAI

# 대상 ALB 주소 변경
.\run_local.ps1 -Target "http://your-alb-address.elb.amazonaws.com"

# 로그 디렉터리 직접 지정
.\run_local.ps1 -LogDir "analyzer/logs_merged"
```

### 전체 파라미터 목록

| 파라미터 | 기본값 | 설명 |
|---|---|---|
| `-LogDir` | `analyzer/sample_logs` | 로컬 WAF 로그 디렉터리 |
| `-Target` | ALB DNS 주소 | 공격 시뮬레이션 대상 URL |
| `-Live` | off | S3 실시간 로그 수집 활성화 |
| `-LiveHours` | `1` | 실시간 수집 시간 범위 (시간) |
| `-SkipZap` | off | OWASP ZAP 스캔 생략 |
| `-SkipAI` | off | AI 보고서 생성 생략 |
| `-SkipPR` | off | GitHub PR 이력 수집 생략 |

---

## 8. 실행 결과 확인

파이프라인이 끝난 뒤 아래 명령으로 결과를 빠르게 점검할 수 있습니다.

### 컴플라이언스 판정 상태 확인

```powershell
python -X utf8 compliance/check_output.py
```

출력 예시:
```
=== 최종 판정 ===
판정: 부분 적정
총 요청: 208 건
최고위험 IP: 1.231.150.121 / Path Traversal

=== PCI DSS (e1~e5) ===
  e1: 충족  e2: 충족  e3: 충족  e4: 충족  e5: 부분충족

=== ISMS-P (2.5~2.11) ===
  2.5: 적정  2.6: 적정  2.7: 적정  2.8: 조건부  2.9: 적정  2.10: 적정  2.11: 적정

=== 인프라 보안 현황 ===
  S3 암호화: AES256 (PASS)
  KMS CMK : NOT_FOUND          ← 프리티어 보류
  Object Lock: True / COMPLIANCE / 365일 (PASS)
  Config 드리프트: NOT_CONFIGURED  ← 프리티어 보류

=== 소스 커버리지 ===
  [+] analyzer / attack_sim / waf_raw / cloudtrail / github_pr
  [+] ai / prowler / bucket_encryption / kms_key / object_lock / config_diff
```

### 보고서 열기

```powershell
# PDF 보고서 (제출/공유용)
Start-Process compliance\output\report.pdf

# HTML 보고서 (브라우저)
Start-Process compliance\output\report.html

# AI 분석 보고서 (Markdown)
Get-ChildItem ai\output\report_*.md | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object { notepad $_.FullName }
```

### 출력 파일 생성 여부 확인

```powershell
# 오늘 생성된 파일 목록
Get-ChildItem output\, ai\output\, compliance\output\ -Recurse |
  Where-Object { $_.LastWriteTime -gt (Get-Date).Date } |
  Select-Object Name, @{N='KB';E={[math]::Round($_.Length/1KB,1)}}, LastWriteTime |
  Format-Table -AutoSize
```

---

## 9. 개별 단계 실행

파이프라인의 특정 단계만 실행할 수 있습니다.

### 공격 시뮬레이션

```bash
# 전체 공격 패턴 목록 확인 (전송 없음)
python attack_simulation/attack_runner.py --dry-run

# 전체 전송 (SQLi 3종, XSS 3종, PathTraversal 2종, CommandInjection 2종, ScannerUA 2종)
python attack_simulation/attack_runner.py

# 특정 유형만
python attack_simulation/attack_runner.py --category sqli xss

# 각 패턴 3회, 0.5초 간격
python attack_simulation/attack_runner.py --count 3 --delay 0.5

# 대상 변경
python attack_simulation/attack_runner.py --target http://your-alb.elb.amazonaws.com
```

### WAF 로그 분석

```bash
# 로컬 샘플 로그 분석
python analyzer/main.py

# S3 실시간 로그 분석
python analyzer/main.py --live --live-hours 1

# 특정 로그 디렉터리
python analyzer/main.py --log-dir analyzer/logs_merged

# CTI 상위 10개 IP 조회
python analyzer/main.py --cti --cti-top 10
```

### 개별 수집기 실행

```bash
# WAF WebACL / IPSet describe
python scripts/collect_waf.py

# CloudTrail 변경 이력 (최근 14일)
python scripts/collect_cloudtrail.py

# Prowler 보안 점검
python scripts/collect_prowler.py

# CMK + Object Lock 증적
python scripts/collect_cmk.py
python scripts/collect_cmk.py --bucket your-bucket-name --region ap-northeast-2

# AWS Config 드리프트 감지
python scripts/collect_config_diff.py
python scripts/collect_config_diff.py --days 14
```

### AI 보고서 생성

```bash
# Ollama 서버가 실행 중인 상태에서 실행
# Windows (한글 경로 이슈 시 OLLAMA_MODELS 환경변수 먼저 설정)
$env:OLLAMA_MODELS = "C:\ollama\models"

python ai/report_generator.py

# AI 분석 JSON 변환 (컴플라이언스 보고서용)
python ai/generate_analysis_json.py

# 특정 파일 지정
python ai/generate_analysis_json.py \
  --analysis output/analysis_20260623_030250.json \
  --md ai/output/report_20260623_030816.md
```

### 컴플라이언스 보고서 생성

```bash
# compliance/input/ 의 수집 파일을 통합하여 HTML 보고서 생성
python compliance/build_data.py     # → compliance/real_data.json
python compliance/render.py         # → compliance/output/report.html
```

### GitHub PR 자동 생성

```bash
# 분석 결과에서 HIGH 위험 IP를 WAF IPSet에 추가하는 PR 생성
python scripts/auto_pr.py
```

---

## 10. 자주 묻는 문제

### Ollama 관련

**Q. AI 보고서 생성 단계에서 `Connection refused` 오류가 납니다.**

Ollama 서버가 실행 중이지 않습니다.

```powershell
# 별도 터미널에서 실행 (백그라운드 유지)
$env:OLLAMA_MODELS = "C:\ollama\models"
ollama serve
```

---

**Q. `llama3.1:8b` 모델을 찾을 수 없습니다.**

```powershell
$env:OLLAMA_MODELS = "C:\ollama\models"
ollama pull llama3.1:8b    # 약 4.7 GB, 최초 1회
ollama list                # 목록 확인
```

---

**Q. Windows 한글 사용자 이름 경로 오류가 납니다.**

`run_local.ps1`은 자동으로 `C:\ollama\models`로 우회합니다. 직접 실행할 때는 다음을 먼저 실행하세요.

```powershell
$env:OLLAMA_MODELS = "C:\ollama\models"
```

---

### AWS / 자격증명 관련

**Q. `NoCredentialsError` 또는 `Unable to locate credentials` 오류가 납니다.**

`.env` 파일에 AWS 자격증명이 입력되어 있는지 확인하세요.

```powershell
cat .env | Select-String "AWS_ACCESS_KEY"
```

값이 비어 있으면 AWS 콘솔 → IAM → 보안 자격 증명 → 액세스 키에서 발급 후 `.env`에 입력합니다.

---

**Q. AWS 자격증명 없이도 실행할 수 있나요?**

가능합니다. 샘플 로그(`analyzer/sample_logs/`)가 있으므로 분석·AI·ZAP·컴플라이언스 보고서 생성까지 가능합니다. AWS 수집기(CloudTrail, WAF describe, CMK 등)는 자동 스킵됩니다.

```powershell
.\run_local.ps1    # .env에 AWS 키 없어도 실행됨
```

---

### ZAP / Docker 관련

**Q. ZAP 단계에서 `docker: command not found` 오류가 납니다.**

Docker Desktop이 설치·실행되어 있지 않습니다. ZAP 없이 실행하려면 `-SkipZap`을 사용하세요.

```powershell
.\run_local.ps1 -SkipZap
```

---

**Q. ZAP 컨테이너가 오래 실행됩니다.**

기본 타임아웃은 Spider + Active Scan 포함 최대 5분입니다. 빠르게 끝내려면 `security/zap_scanner.py`에서 스캔 레벨을 낮추세요.

```bash
python security/zap_scanner.py --level low
```

---

### 파이프라인 / 결과 관련

**Q. `compliance/output/report.pdf`가 생성되지 않습니다.**

Playwright Chromium이 설치되어 있는지 확인하세요.

```powershell
playwright install chromium
```

---

**Q. PCI e5가 "부분충족"으로 나옵니다.**

샘플 로그에는 실제 차단(BLOCK) 기록이 없어 `block_rate = 0%`로 산정됩니다. 실제 S3 로그로 실행하면 정확한 판정이 나옵니다.

```powershell
.\run_local.ps1 -Live    # 실시간 S3 로그 사용 (AWS 자격증명 필요)
```

---

**Q. auto_pr.py가 PR을 생성하지 않습니다.**

정상 동작입니다. HIGH 위험 IP가 없으면 불필요한 PR을 생성하지 않습니다. 샘플 로그 기반 실행에서는 대부분 HIGH IP가 0개입니다.

---

## 11. 선택: Grafana 모니터링 스택

파이프라인과는 별도로 실행하는 시각화 레이어입니다.  
파이프라인 실행 후 생성된 `output/analysis_*.json` 파일을 Grafana 대시보드로 확인할 수 있습니다.

**실행**

```bash
cd monitoring
docker-compose up -d
```

**컨테이너 구성**

| 컨테이너 | 역할 | 포트 |
|---|---|---|
| `grafana` | 시각화 대시보드 | 3000 |
| `loki` | 로그 저장소 | 3100 |
| `fluent-bit` | 로그 수집 에이전트 | - |
| `json-api` | 분석 결과 JSON API 서버 | 5000 |

**접속**

- Grafana: [http://localhost:3000](http://localhost:3000)  
  계정: `admin` / `admin123!`
- JSON API: [http://localhost:5000](http://localhost:5000)

**종료**

```bash
docker-compose down
```

---

## 12. 출력 파일 구조

파이프라인 실행 후 생성되는 파일 목록입니다.

```
output/
├── analysis_YYYYMMDD_HHMMSS.json    # WAF 로그 분석 결과 (메인 출력)
└── zap_report_YYYYMMDD_HHMMSS.json  # ZAP 웹 취약점 스캔 결과

attack_simulation/output/
└── sent_attacks.jsonl               # 전송한 공격 요청 기록

ai/output/
└── report_YYYYMMDD_HHMMSS.md        # AI 생성 보안 보고서 (한국어 Markdown)

raw/
├── waf_web_acl.json                 # WAF WebACL 설정 스냅샷
├── waf_ipset.json                   # WAF IPSet 목록
└── waf_resources.json               # WAF 연결 리소스 목록

compliance/input/                    # 컴플라이언스 증적 원본 (수집기 출력)
├── cloudtrail_events.json           # CloudTrail 14일 이벤트 (ISMS-P 2.9)
├── prowler_report.json              # Prowler 보안 점검 결과 (ISMS-P 2.6)
├── bucket_encryption.json           # S3 버킷 암호화 현황 (ISMS-P 2.7)
├── kms_key.json                     # KMS 키 메타데이터
├── kms_rotation.json                # KMS 자동 키 회전 여부
├── kms_key_policy.json              # KMS 키 정책
├── object_lock_config.json          # S3 Object Lock 설정 (ISMS-P 2.7)
├── object_retention.json            # 개별 오브젝트 보존 기간
├── object_head.json                 # 최신 오브젝트 헤더 (무결성 샘플)
├── config_diff.json                 # AWS Config 드리프트 감지 (ISMS-P 2.10)
├── ai_analysis.json                 # AI 분석 요약 (build_data 소비)
└── github_pr.json                   # GitHub PR 이력 (변경관리 증적)

compliance/
├── real_data.json                   # 모든 수집 파일 통합 데이터
└── output/report.html               # ISMS-P 컴플라이언스 HTML 보고서

terraform/
└── waf_blocked_ips.auto.tfvars      # auto_pr.py가 자동 갱신하는 차단 IP 목록
```

---

## 13. 프로젝트 디렉터리 구조

```
cloud-security-platform/
├── run_local.ps1                    # 전체 파이프라인 로컬 실행 래퍼
├── requirements.txt                 # 공통 Python 의존성
├── .env.example                     # 환경 변수 템플릿
│
├── scripts/                         # 파이프라인 오케스트레이터 + 수집기
│   ├── run_pipeline.py              # 전체 파이프라인 실행기
│   ├── collect_waf_logs.py          # S3 WAF 로그 실시간 수집
│   ├── collect_waf.py               # WAF WebACL·IPSet describe
│   ├── collect_cloudtrail.py        # CloudTrail 이벤트 수집
│   ├── collect_prowler.py           # Prowler 보안 점검
│   ├── collect_cmk.py               # CMK + Object Lock 증적 수집
│   ├── collect_config_diff.py       # AWS Config 드리프트 감지
│   └── auto_pr.py                   # 고위험 IP → GitHub PR 자동 생성
│
├── analyzer/                        # WAF 로그 분석 엔진
│   ├── main.py                      # CLI 진입점
│   ├── waf_analyzer.py              # 로그 파싱, 공격 분류, 위험도 계산
│   ├── cti_checker.py               # AbuseIPDB CTI 연동
│   ├── config.py                    # 설정 (버킷명, 임계값 등)
│   └── sample_logs/                 # 로컬 테스트용 WAF 로그 샘플
│
├── attack_simulation/               # 공격 시뮬레이터
│   └── attack_runner.py             # 12종 공격 패턴 ALB 전송
│
├── ai/                              # AI 보고서 생성
│   ├── report_generator.py          # LangChain + Ollama 보고서 생성
│   ├── generate_analysis_json.py    # AI 보고서 → JSON 변환
│   └── prompts.py                   # 프롬프트 템플릿
│
├── security/                        # 보안 테스트 도구
│   ├── ab_test.py                   # WAF Count/Block A/B 테스트
│   └── zap_scanner.py               # OWASP ZAP 자동 스캔 (Docker)
│
├── compliance/                      # ISMS-P 컴플라이언스 보고서
│   ├── build_data.py                # 수집 파일 통합 Adapter
│   ├── render.py                    # Jinja2 HTML 렌더링
│   ├── template.html                # 보고서 HTML 템플릿
│   ├── pr_collector.py              # GitHub PR 이력 수집
│   └── input/                       # 각 수집기의 Raw 출력 파일
│
├── monitoring/                      # 선택: Grafana 시각화 스택
│   ├── docker-compose.yml           # Grafana + Loki + Fluent Bit + JSON API
│   ├── fluent-bit.conf              # Fluent Bit 수집 설정
│   ├── json_server.py               # Flask JSON API 서버
│   └── provisioning/                # Grafana 자동 프로비저닝 설정
│
└── terraform/                       # AWS 인프라 코드
    ├── main.tf                      # 루트 모듈
    ├── variables.tf / outputs.tf
    └── modules/
        ├── waf/                     # WAF WebACL, IPSet, 룰 그룹
        ├── alb/                     # Application Load Balancer
        ├── ec2/                     # 웹 서버 인스턴스
        ├── s3/                      # WAF 로그 버킷
        ├── networking/              # VPC, 서브넷, IGW
        └── logging/                 # CloudTrail, 로그 설정
```

---

## 14. 팀 구성

| 역할 | 담당자 | 담당 영역 |
|---|---|---|
| 팀장 / 통합 | 유지원 | 전체 파이프라인 통합, 수집기 구현, 산출물 검수 |
| 인프라 | 천혜수 | Terraform IaC, AWS 배포, CI/CD |
| 분석 | 박소연 | WAF 로그 분석 엔진, Grafana 시각화 |
| AI | 송일환 | LangChain + Ollama 보고서 생성기 |
| 보안 테스트 | 현수민 | 공격 시뮬레이션, ZAP 스캐너, A/B 테스트 |
| 컴플라이언스 | 김병옥 | ISMS-P 매핑, 컴플라이언스 보고서 렌더러 |
