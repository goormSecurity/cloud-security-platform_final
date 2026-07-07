# AI 기반 클라우드 보안 운영 자동화 및 컴플라이언스 대응 플랫폼

2026 구름 정보보호 17회차 파이널 프로젝트 — 6조 구름방범대

---

## 목차

1. [프로젝트 개요](#1-프로젝트-개요)
2. [아키텍처](#2-아키텍처)
3. [사전 준비사항](#3-사전-준비사항)
4. [필수 키 및 자격증명 목록](#4-필수-키-및-자격증명-목록)
5. [인프라 배포 (Terraform)](#5-인프라-배포-terraform) — [⚠️ 최초 배포 수동 설정 체크리스트](#5-0-최초-배포-수동-설정-체크리스트)
6. [EC2 서버 초기 설정](#6-ec2-서버-초기-설정)
7. [로컬 환경 설정](#7-로컬-환경-설정)
8. [파이프라인 실행](#8-파이프라인-실행)
9. [결과물 확인](#9-결과물-확인)
10. [Grafana 대시보드](#10-grafana-대시보드)
11. [GitOps WAF 자동 차단 흐름](#11-gitops-waf-자동-차단-흐름)
12. [GitHub Actions CI/CD 설정](#12-github-actions-cicd-설정)
13. [개별 단계 실행](#13-개별-단계-실행)
14. [전체 파이프라인 흐름](#14-전체-파이프라인-흐름)
15. [주의사항](#15-주의사항)
16. [자주 묻는 문제](#16-자주-묻는-문제)
17. [출력 파일 구조](#17-출력-파일-구조)
18. [프로젝트 디렉터리 구조](#18-프로젝트-디렉터리-구조)
19. [팀 구성](#19-팀-구성)

---

## 1. 프로젝트 개요

AWS WAF 로그를 자동 수집·분석하고, EC2 GPU 서버의 로컬 LLM(Ollama + qwen2.5:7b)으로 한국어 9개 섹션 AI 보안 보고서를 생성한 뒤, GitOps 기반으로 WAF 차단 정책을 자동 갱신하고 ISMS-P / PCI-DSS 컴플라이언스 증적을 자동화하는 플랫폼입니다.

**핵심 특징**

- **보안 중심 설계** — 원시 WAF 로그는 EC2/S3 밖으로 나오지 않으며, 로컬에는 가공된 보고서만 전달됩니다
- **설명 가능한 AI** — EC2 GPU(qwen2.5:7b)로 외부 API 유출 없이 한국어 9개 섹션 보안 보고서 생성
- **할루시네이션 방지** — `build_key_metrics()`로 핵심 지표를 명시적으로 추출해 LLM에 전달
- **GitOps 자동화** — 고위험 IP 탐지 시 Terraform 변수 수정 PR 자동 생성 → 중복 생성 방지 로직 포함
- **ISMS-P / PCI-DSS 자동 증적** — CloudTrail·Prowler·CMK·Config·S3·Trivy·ZAP 수집기로 감사 증적 자동화
- **실시간 모니터링** — Grafana 대시보드 (시간 범위 연동) + Loki 실시간 로그 스트림

---

## 2. 아키텍처

```
┌───────────────────────────────────────────────────────────────────┐
│  로컬 PC                                                           │
│                                                                   │
│  python scripts/run_remote.py                                     │
│    ① ZAP 웹 취약점 스캔  → zap_report.json                       │
│    ② 공격 시뮬레이션     → attack_result.json                    │
│    ③ ZAP·공격 결과 → EC2 SCP 전달                               │
│    ④ EC2 파이프라인 SSH 트리거                                   │
│    ⑤ S3에서 최종 결과물만 로컬 다운로드                          │
│       → reports/pulled/YYYY-MM-DD/                               │
│    ⑥ EC2 reports/latest/ → 로컬 동기화                          │
└───────────────────┬───────────────────────────────────────────────┘
                    │ SSH / SCP
                    ▼
┌───────────────────────────────────────────────────────────────────┐
│  EC2 분석 서버 (43.201.194.252)                                    │
│                                                                   │
│  WAF 로그 ←── S3 (aws-waf-logs-cloud-sec-dev)                   │
│    ↓ WAF 로그 분석 (analyzer/main.py)                            │
│    ↓ A/B 테스트 / FP·FN 분석                                    │
│    ↓ 증적 수집 (CloudTrail / Prowler / Trivy / CMK / Config)     │
│    ↓ AI 보고서 생성 (Ollama qwen2.5:7b GPU)                     │
│    ↓ 컴플라이언스 PDF 생성 (Jinja2 + Playwright)                 │
│    ↓ Slack 알림 전송                                             │
│    ↓ S3 업로드 → cloud-sec-audit-evidence-dev/pipeline-results/  │
│    ↓ Grafana 대시보드 반영 (json-api:5000, Grafana:3000)         │
│                                                                   │
│  [원시 WAF 로그는 이 서버 밖으로 나가지 않음]                     │
└───────────────────────────────────────────────────────────────────┘
                    │ 고위험 IP 탐지
                    ▼
┌───────────────────────────────────────────────────────────────────┐
│  GitOps 자동 차단                                                  │
│                                                                   │
│  auto_pr.py → terraform/waf_blocked_ips.auto.tfvars 수정         │
│            → GitHub PR 자동 생성                                 │
│  PR 검토 후 merge → terraform apply → AWS WAF IPSet 갱신         │
└───────────────────────────────────────────────────────────────────┘
```

---

## 3. 사전 준비사항

### 3-1. 로컬 소프트웨어

| 항목 | 버전 | 확인 방법 | 용도 |
|---|---|---|---|
| Python | 3.10 이상 | `python --version` | 전체 파이프라인 |
| AWS CLI | v2 | `aws --version` | S3 결과물 다운로드 |
| Docker Desktop | 최신 | `docker --version` | ZAP 로컬 스캔 |
| OpenSSH | - | `ssh -V` | EC2 원격 실행 |
| Git | - | `git --version` | 저장소 관리 |
| Terraform | 1.5+ | `terraform --version` | 인프라 배포 (선택) |

### 3-2. AWS 서비스 (사전 생성 필요)

| 리소스 | 이름 | 비고 |
|---|---|---|
| EC2 분석 서버 | `cloud-sec-analysis` | GPU 권장 (g4dn.xlarge 이상), Amazon Linux 2023 |
| EC2 앱 서버 | `cloud-sec-app` | DVWA / Juice Shop / Ghost 컨테이너 실행 |
| S3 버킷 — WAF 로그 | `aws-waf-logs-cloud-sec-dev` | WAF 로그 자동 저장 (이름이 `aws-waf-logs-`로 시작해야 함) |
| S3 버킷 — 증적 | `cloud-sec-audit-evidence-dev` | Object Lock COMPLIANCE 365일 |
| WAF WebACL | `cloud-sec-web-acl` | ALB 연결, REGIONAL scope |
| ALB | - | WAF와 연결, EC2 앱 서버 타깃 |
| SSH 키페어 | `cloud-sec-key2` | `~/.ssh/cloud-sec-key2` 로컬 저장 |

> Terraform으로 위 리소스 전체를 자동 배포할 수 있습니다 → [5. 인프라 배포](#5-인프라-배포-terraform)

### 3-3. 외부 계정 및 서비스

| 서비스 | 필수 여부 | 용도 |
|---|---|---|
| AWS IAM 계정 | **필수** | 파이프라인 실행 자격증명 |
| GitHub 계정 | **필수** | PR 자동 생성, Actions CI/CD |
| AbuseIPDB | 선택 | IP 위험도 보강 (CTI), 무료 1,000건/일 |
| Slack | 선택 | HIGH 위험 IP 탐지 시 알림 |

---

## 4. 필수 키 및 자격증명 목록

시스템 실행에 필요한 모든 키를 아래 표에 정리합니다.

### 4-1. 로컬 `.env` 파일 (필수)

```bash
cp .env.example .env
# .env 파일을 열어 아래 값 입력
```

| 환경변수 | 필수 | 발급 위치 | 설명 |
|---|---|---|---|
| `AWS_ACCESS_KEY_ID` | **필수** | AWS 콘솔 → IAM → 사용자 → 보안 자격 증명 → 액세스 키 | AWS API 호출용 |
| `AWS_SECRET_ACCESS_KEY` | **필수** | 위와 동일 (액세스 키 생성 시 1회만 표시) | AWS API 호출용 |
| `AWS_DEFAULT_REGION` | **필수** | - | `ap-northeast-2` 고정 |
| `GITHUB_TOKEN` | **필수** | GitHub → Settings → Developer settings → Personal access tokens (Classic) → `repo` scope 선택 | PR 생성·조회 |
| `ABUSEIPDB_API_KEY` | 선택 | [abuseipdb.com](https://www.abuseipdb.com/register?plan=free) → 무료 가입 | IP 위험도 보강 (없으면 CTI 생략) |
| `SLACK_WEBHOOK_URL` | 선택 | Slack 앱 → Incoming Webhooks → 채널 선택 → Webhook URL 복사 | 위험 알림 (없으면 알림 스킵) |

`.env` 파일 예시:
```dotenv
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=ap-northeast-2

GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

ABUSEIPDB_API_KEY=
SLACK_WEBHOOK_URL=
```

> `.env`는 `.gitignore`에 포함되어 있어 절대 커밋되지 않습니다.

### 4-2. IAM 권한 (최소 권한 원칙)

```
AmazonWAFReadOnlyAccess       ← WAF 로그 분석, WebACL 조회
AmazonS3ReadOnlyAccess        ← WAF 로그 버킷 읽기
AmazonS3FullAccess            ← 증적 버킷 업로드
CloudTrailReadOnlyAccess      ← CloudTrail 이벤트 14일 수집
IAMReadOnlyAccess             ← Prowler MFA·정책 점검
AmazonKMSReadOnlyAccess       ← CMK 메타데이터 수집
AWSConfigReadOnlyAccess       ← Config 드리프트 감지
AmazonEC2ReadOnlyAccess       ← (선택) Trivy EC2 앱 서버 스캔
```

### 4-3. SSH 키 (`~/.ssh/cloud-sec-key2`)

EC2 접속에 사용합니다. Terraform 배포 시 자동 생성되거나 AWS 콘솔에서 수동 생성합니다.

```bash
# 키 존재 여부 확인
ls -la ~/.ssh/cloud-sec-key2

# 권한 설정 (처음 한 번만)
chmod 400 ~/.ssh/cloud-sec-key2

# 연결 테스트
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 "echo OK"
```

### 4-4. `platform.yaml` (EC2·S3 설정)

Terraform 배포 후 출력값으로 자동 생성하거나 수동으로 작성합니다.

```bash
# 방법 1: 자동 생성 (Terraform 출력 기반)
python scripts/generate_config.py

# 방법 2: 수동 작성
cp platform.yaml.example platform.yaml
# platform.yaml 편집
```

```yaml
# platform.yaml 예시 (실제 값으로 변경 필요)
aws:
  region: ap-northeast-2
  account_id: "677673473281"

project:
  name: cloud-sec
  environment: dev

buckets:
  waf_logs: aws-waf-logs-cloud-sec-dev
  audit_evidence: cloud-sec-audit-evidence-dev
  alb_logs: cloud-sec-alb-logs-dev
  cloudtrail: cloud-sec-cloudtrail-dev

waf:
  acl_name: cloud-sec-web-acl

alb:
  dns_name: cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com

cloudtrail:
  trail_name: cloud-sec-trail

servers:
  analysis_ip: 43.201.194.252      # 분석 서버 EC2 퍼블릭 IP
  app_ip: 3.36.87.194              # 앱 서버 EC2 퍼블릭 IP
  ssh_user: ec2-user
  ssh_key: ~/.ssh/cloud-sec-key2
  remote_path: /opt/cloud-security-platform
  remote_dir: /opt/cloud-security-platform/output

integrations:
  github_repo: "goormSecurity/cloud-security-platform_final"
  slack_webhook: ""
  abuseipdb_key: ""
```

> `platform.yaml`은 `.gitignore`에 포함되어 있어 절대 커밋되지 않습니다.

### 4-5. GitHub Actions Secrets (CI/CD용)

GitHub 저장소 → Settings → Secrets and variables → Actions에서 등록합니다.

| Secret 이름 | 필수 | 값 | 용도 |
|---|---|---|---|
| `AWS_ACCESS_KEY_ID` | **필수** | IAM 액세스 키 | Terraform Apply (수동 워크플로) |
| `AWS_SECRET_ACCESS_KEY` | **필수** | IAM 시크릿 키 | Terraform Apply |
| `AWS_REGION` | **필수** | `ap-northeast-2` | Terraform Apply |
| `SSH_PUBLIC_KEY` | **필수** | `cat ~/.ssh/cloud-sec-key2.pub` 출력값 | EC2 키페어 등록 |
| `EC2_HOST` | **필수** | `43.201.194.252` | EC2 자동 배포 |
| `EC2_SSH_PRIVATE_KEY` | **필수** | `cat ~/.ssh/cloud-sec-key2` 출력값 (전체 PEM) | EC2 자동 배포 |
| `GITHUB_TOKEN` | 자동 제공 | - | PR 코멘트 등 (Actions에서 자동 주입) |
| `INFRACOST_API_KEY` | 선택 | [infracost.io](https://www.infracost.io) 가입 후 발급 | WAF 정책 변경 비용 분석 PR 댓글 |

---

## 5. 인프라 배포 (Terraform)

> **⚠️ 아래 수동 설정을 완료하지 않으면 EC2 부트스트랩이 실패합니다. Terraform apply 전에 반드시 읽으세요.**

### 5-0. 최초 배포 수동 설정 체크리스트

자동화 범위: EC2 부팅 → Docker 설치 → Ollama 설치 → Grafana 스택 기동 → `platform.yaml` 자동 생성까지 자동화되어 있습니다.  
**자동화되지 않는 항목** (반드시 수동으로 먼저 완료해야 합니다):

| # | 항목 | 위치 | 완료 시점 |
|---|---|---|---|
| ① | SSM 파라미터 등록 (GitHub Token / AbuseIPDB / Slack) | AWS 콘솔 또는 CLI | **Terraform apply 전** |
| ② | GitHub Actions Secrets 등록 | GitHub 저장소 Settings | Terraform apply 전 또는 직후 |
| ③ | `terraform/backend.hcl` 작성 | 로컬 파일 | Terraform init 전 |
| ④ | `platform.yaml` 후보정 (`alb.dns_name`, `app_ip`) | EC2 SSH 또는 로컬→SCP | Terraform apply 완료 후 |
| ⑤ | `qwen2.5:7b` 모델 다운로드 완료 확인 | EC2 SSH | AI 보고서 실행 전 |

---

#### ① SSM 파라미터 등록 — Terraform apply 전 필수

EC2 user_data 스크립트가 부팅 시 SSM에서 자동으로 시크릿을 읽어 `.env`를 생성합니다.  
**파라미터가 없으면 `.env`가 빈 값으로 생성되어 파이프라인이 실패합니다.**

```bash
# GitHub Personal Access Token (repo 권한 필수)
aws ssm put-parameter \
  --name /cloud-sec/github_token \
  --value "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --type SecureString \
  --region ap-northeast-2

# AbuseIPDB API 키 (선택 — 없으면 CTI 조회 생략)
aws ssm put-parameter \
  --name /cloud-sec/abuseipdb_api_key \
  --value "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --type SecureString \
  --region ap-northeast-2

# Slack Webhook URL (선택 — 없으면 알림 스킵)
aws ssm put-parameter \
  --name /cloud-sec/slack_webhook_url \
  --value "https://hooks.slack.com/services/<T_ID>/<B_ID>/<WEBHOOK_TOKEN>" \
  --type SecureString \
  --region ap-northeast-2
```

> 파라미터가 이미 등록되어 있으면 `--overwrite` 플래그를 추가하세요.

EC2 IAM Role에 `AmazonSSMReadOnlyAccess` 또는 아래 최소 권한이 필요합니다:

```json
{
  "Effect": "Allow",
  "Action": ["ssm:GetParameter", "ssm:GetParameters"],
  "Resource": "arn:aws:ssm:ap-northeast-2:*:parameter/cloud-sec/*"
}
```

---

#### ② GitHub Actions Secrets 등록

CI/CD 파이프라인과 Terraform apply에 필요한 7개 Secret을 GitHub 저장소에 등록합니다.

**필요 Secret 목록**

| Secret 이름 | 필수 | 값 | 언제 등록 |
|---|---|---|---|
| `AWS_ACCESS_KEY_ID` | **필수** | IAM 액세스 키 ID | Terraform apply 전 |
| `AWS_SECRET_ACCESS_KEY` | **필수** | IAM 시크릿 키 | Terraform apply 전 |
| `AWS_REGION` | **필수** | `ap-northeast-2` | Terraform apply 전 |
| `SSH_PUBLIC_KEY` | **필수** | EC2 공개키 전체 | Terraform apply 전 |
| `EC2_HOST` | **필수** | EC2 퍼블릭 IP | **Terraform apply 완료 후 업데이트** |
| `EC2_SSH_PRIVATE_KEY` | **필수** | EC2 개인키 전체 PEM | EC2 배포 후 |
| `INFRACOST_API_KEY` | 선택 | infracost.io 발급 | 선택 |

> `EC2_HOST`는 Terraform 배포 전에는 IP를 알 수 없습니다. **배포 완료 후 반드시 업데이트**해야 `deploy-ec2` 자동 배포가 동작합니다.

---

**방법 A — gh CLI (권장)**

```bash
# AWS 리전 (고정값)
gh secret set AWS_REGION \
  --body "ap-northeast-2" \
  --repo goormSecurity/cloud-security-platform_final

# AWS IAM 키 (값 직접 입력)
gh secret set AWS_ACCESS_KEY_ID \
  --body "AKIAIOSFODNN7EXAMPLE" \
  --repo goormSecurity/cloud-security-platform_final

gh secret set AWS_SECRET_ACCESS_KEY \
  --body "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  --repo goormSecurity/cloud-security-platform_final

# SSH 키 (파일에서 자동 읽기)
# macOS / Linux
gh secret set SSH_PUBLIC_KEY \
  --body "$(cat ~/.ssh/cloud-sec-key2.pub)" \
  --repo goormSecurity/cloud-security-platform_final

gh secret set EC2_SSH_PRIVATE_KEY \
  --body "$(cat ~/.ssh/cloud-sec-key2)" \
  --repo goormSecurity/cloud-security-platform_final

# EC2 IP (Terraform 완료 후 등록)
gh secret set EC2_HOST \
  --body "43.201.194.252" \
  --repo goormSecurity/cloud-security-platform_final
```

> Windows PowerShell에서는 `$(cat ...)` 대신 아래 방식을 사용합니다:
> ```powershell
> gh secret set SSH_PUBLIC_KEY `
>   --body (Get-Content ~/.ssh/cloud-sec-key2.pub -Raw) `
>   --repo goormSecurity/cloud-security-platform_final
>
> gh secret set EC2_SSH_PRIVATE_KEY `
>   --body (Get-Content ~/.ssh/cloud-sec-key2 -Raw) `
>   --repo goormSecurity/cloud-security-platform_final
> ```

---

**방법 B — GitHub 웹 UI**

`https://github.com/goormSecurity/cloud-security-platform_final` → **Settings → Secrets and variables → Actions → New repository secret**

각 Secret 이름과 값을 입력 후 **Add secret** 클릭.

SSH 키 값 확인 방법:
```bash
# 공개키 (SSH_PUBLIC_KEY) — 출력 전체를 복사
cat ~/.ssh/cloud-sec-key2.pub

# 개인키 (EC2_SSH_PRIVATE_KEY) — -----BEGIN RSA PRIVATE KEY----- 부터 -----END----- 까지 전체 복사
cat ~/.ssh/cloud-sec-key2
```

```powershell
# Windows PowerShell
Get-Content ~/.ssh/cloud-sec-key2.pub   # 공개키
Get-Content ~/.ssh/cloud-sec-key2       # 개인키
```

---

**AWS IAM 키 발급 위치**

1. AWS 콘솔 → **IAM** → **사용자** → 본인 계정 선택
2. **보안 자격 증명** 탭 → **액세스 키** → **액세스 키 만들기**
3. `AWS_ACCESS_KEY_ID`와 `AWS_SECRET_ACCESS_KEY`를 즉시 복사 (시크릿 키는 생성 시 1회만 표시됨)

> 기존 액세스 키가 있으면 재사용 가능합니다. 없으면 위 절차로 새로 생성하세요.

---

**등록 확인**

```bash
gh secret list --repo goormSecurity/cloud-security-platform_final
```

아래 6개가 모두 나와야 정상입니다:
```
AWS_ACCESS_KEY_ID       Updated YYYY-MM-DD
AWS_SECRET_ACCESS_KEY   Updated YYYY-MM-DD
AWS_REGION              Updated YYYY-MM-DD
EC2_HOST                Updated YYYY-MM-DD
EC2_SSH_PRIVATE_KEY     Updated YYYY-MM-DD
SSH_PUBLIC_KEY          Updated YYYY-MM-DD
```

---

#### ③ backend.hcl 작성 → 5-1~5-2 참고

`terraform/backend.hcl.example`을 복사해 Terraform State 버킷 이름을 작성합니다.  
Terraform init 전에 완료해야 합니다.

---

#### ④ platform.yaml 후보정 — Terraform apply 완료 후

Terraform 배포가 끝나면 `python scripts/generate_config.py`로 `platform.yaml`을 자동 생성합니다 (5-4 참고).  
EC2 user_data도 부팅 시 자동 생성하지만, `alb.dns_name`과 `app_ip`가 비어 있을 수 있습니다.

EC2에서 값 확인:

```bash
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@<EC2_IP> \
  'grep -E "dns_name|app_ip" /opt/cloud-security-platform/platform.yaml'
```

값이 비어 있으면 로컬에서 생성 후 SCP로 전송합니다:

```bash
# 로컬에서 platform.yaml 생성
python scripts/generate_config.py

# EC2로 전송 (EC2_IP는 Terraform 출력값으로 교체)
scp -i ~/.ssh/cloud-sec-key2 platform.yaml \
  ec2-user@<EC2_IP>:/opt/cloud-security-platform/platform.yaml
```

---

#### ⑤ qwen2.5:7b 모델 다운로드 완료 확인

EC2 user_data가 백그라운드로 모델을 다운로드합니다 (**약 5 GB, 20~30분 소요**).  
AI 보고서(`run_pipeline.py` 또는 `ai-report` 워크플로)를 실행하기 전에 반드시 완료 여부를 확인하세요.

```bash
# 다운로드 완료 확인 (qwen2.5:7b가 목록에 보이면 준비 완료)
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@<EC2_IP> 'ollama list'

# 다운로드 진행 중이면 로그 확인
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@<EC2_IP> \
  'tail -f /var/log/ollama-pull.log'
```

---

### 5-1. Terraform State S3 버킷 생성 (최초 1회)

```bash
# Terraform state 저장용 버킷 생성 (이름은 직접 지정)
aws s3 mb s3://my-terraform-state-bucket --region ap-northeast-2
aws s3api put-bucket-versioning \
  --bucket my-terraform-state-bucket \
  --versioning-configuration Status=Enabled
```

### 5-2. backend.hcl 설정

```bash
cp terraform/backend.hcl.example terraform/backend.hcl
# backend.hcl 편집: bucket 이름을 위에서 생성한 버킷으로 변경
```

```hcl
# terraform/backend.hcl
bucket = "my-terraform-state-bucket"
key    = "cloud-security/terraform.tfstate"
region = "ap-northeast-2"
encrypt      = true
use_lockfile = true
```

### 5-3. 배포 실행

```bash
cd terraform

# 초기화
terraform init -backend-config=backend.hcl

# 계획 확인
terraform plan -var="ssh_public_key=$(cat ~/.ssh/cloud-sec-key2.pub)"

# 배포
terraform apply -var="ssh_public_key=$(cat ~/.ssh/cloud-sec-key2.pub)"
```

### 5-4. 출력값으로 platform.yaml 자동 생성

```bash
# 배포 완료 후 루트 디렉터리로 이동
cd ..

# Terraform 출력값 기반으로 platform.yaml 자동 생성
python scripts/generate_config.py
```

### 5-5. WAF IP 차단 목록 수동 적용 (필요 시)

`auto_pr.py`가 생성한 PR을 merge한 후 WAF 차단 목록을 실제 AWS에 반영합니다.

```bash
cd terraform
terraform plan -var="ssh_public_key=$(cat ~/.ssh/cloud-sec-key2.pub)" -out=tfplan
terraform apply tfplan
```

> GitHub Actions `deploy` 워크플로(workflow_dispatch)를 사용해 원격으로도 실행할 수 있습니다.

---

## 6. EC2 서버 초기 설정

분석 서버에 Docker, Ollama, Grafana 스택을 설치합니다. **최초 1회만 실행합니다.**

### 6-1. EC2 접속

```bash
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252
```

### 6-2. 기본 패키지 및 Docker 설치

```bash
# 패키지 업데이트
sudo yum update -y

# Docker 설치 (Amazon Linux 2023)
sudo yum install -y docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker ec2-user

# docker-compose 설치
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Git 설치
sudo yum install -y git
```

### 6-3. 저장소 클론

```bash
sudo mkdir -p /opt/cloud-security-platform
sudo chown ec2-user:ec2-user /opt/cloud-security-platform

git clone https://github.com/goormSecurity/cloud-security-platform_final.git \
  /opt/cloud-security-platform
cd /opt/cloud-security-platform
```

### 6-4. Python 가상환경 및 의존성 설치

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium --with-deps
```

### 6-5. Ollama 및 LLM 모델 설치

```bash
# Ollama 설치
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable ollama
sudo systemctl start ollama

# qwen2.5:7b 모델 다운로드 (약 5GB, 시간 소요)
ollama pull qwen2.5:7b

# 설치 확인
ollama list
# NAME              ID              SIZE    MODIFIED
# qwen2.5:7b        ...             4.7 GB  ...
```

### 6-6. Grafana 모니터링 스택 실행

```bash
cd /opt/cloud-security-platform/monitoring
sudo docker-compose up -d

# 컨테이너 상태 확인
sudo docker-compose ps
# NAME         STATUS
# loki         running
# fluent-bit   running
# json-api     running
# grafana      running
```

### 6-7. 디렉터리 초기화

```bash
mkdir -p /opt/cloud-security-platform/output
mkdir -p /opt/cloud-security-platform/reports/latest
mkdir -p /opt/cloud-security-platform/compliance/input
```

### 6-8. AWS 자격증명 설정 (EC2)

```bash
# ~/.aws/credentials 설정 (IAM 자격증명)
aws configure
# AWS Access Key ID: AKIA...
# AWS Secret Access Key: ...
# Default region: ap-northeast-2
# Default output format: json
```

---

## 7. 로컬 환경 설정

### 7-1. 저장소 클론 및 의존성 설치

```bash
git clone https://github.com/goormSecurity/cloud-security-platform_final.git
cd cloud-security-platform

# 가상환경 생성
python -m venv .venv

# 활성화 (OS별)
source .venv/bin/activate          # macOS / Linux
.venv\Scripts\Activate.ps1         # Windows PowerShell

# 의존성 설치
pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium         # 컴플라이언스 PDF 변환용
```

### 7-2. 환경 변수 설정

```bash
cp .env.example .env
# .env 파일을 편집기로 열어 키 값 입력
```

### 7-3. platform.yaml 설정

```bash
cp platform.yaml.example platform.yaml
# platform.yaml 편집 또는 자동 생성:
python scripts/generate_config.py
```

### 7-4. 설정 확인

```bash
# AWS 자격증명 확인
aws sts get-caller-identity

# SSH 연결 확인
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 "echo OK"

# Python 환경 확인
python -c "import boto3, langchain_ollama; print('OK')"
```

---

## 8. 파이프라인 실행

### 8-1. 운영 모드 — `run_remote.py` (권장)

원시 WAF 로그가 로컬 PC로 내려오지 않습니다. EC2에서 전체 분석 후 S3 결과물만 로컬에 다운로드합니다.

```bash
# 전체 실행 (ZAP 스캔 + 공격 시뮬레이션 + EC2 분석)
python scripts/run_remote.py

# ZAP 없이 빠르게 (공격 시뮬레이션 + EC2 분석)
python scripts/run_remote.py --skip-zap

# WAF 로그 수집 대기 시간 조정 (기본 180초)
# WAF 로그가 S3에 반영되는 데 2~5분 소요되므로 처음에는 그대로 사용
python scripts/run_remote.py --waf-sync-delay 300

# S3 최신 결과만 로컬에 내려받기 (EC2 파이프라인 재실행 없음)
python scripts/run_remote.py --pull-only

# 특정 날짜 결과 내려받기
python scripts/run_remote.py --pull-only --date 2026/07/07

# S3에 저장된 날짜별 결과 목록 확인
python scripts/run_remote.py --list

# WAF 로그 수집 시간 범위 조정 (기본 6시간)
python scripts/run_remote.py --live-hours 12
```

**실행 단계:**

```
① 로컬 ZAP 스캔 (ALB 대상) → zap_report.json
   (ZAP을 EC2에서 직접 실행하면 WAF가 스캔 트래픽을 차단할 위험)
② 로컬 공격 시뮬레이션 → attack_result.json
③ ZAP·공격 결과를 EC2로 SCP 전달
④ EC2 SSH 트리거 → run_pipeline.py --live --skip-zap
   (원시 WAF 로그는 EC2/S3에서만 처리됨)
⑤ S3에서 최종 결과물만 로컬 다운로드
   → reports/pulled/YYYY-MM-DD/
⑥ EC2 reports/latest/ → 로컬 reports/latest/ 동기화 (자동)
```

### 8-2. 개발/테스트 모드 — `run_pipeline.py`

샘플 로그로 AWS 없이 파이프라인 전체를 테스트합니다.

```bash
# 샘플 로그 기반 전체 실행
python scripts/run_pipeline.py

# ZAP·AI 없이 빠른 테스트
python scripts/run_pipeline.py --skip-zap --skip-ai

# 시연용 드라이런 (HTTP 전송 없음)
python scripts/run_pipeline.py --dry-run --skip-zap
```

> **주의**: `--live` 옵션을 사용하면 원시 WAF 로그가 로컬 PC에 저장됩니다. 운영 환경에서는 `run_remote.py`를 사용하세요.

### 8-3. 실행 모드 비교

| 옵션 | `run_remote.py` | `run_pipeline.py` |
|---|---|---|
| 원시 WAF 로그 로컬 저장 | **없음** | `--live` 시 있음 |
| AI 모델 위치 | EC2 GPU (qwen2.5:7b) | 로컬 Ollama |
| ZAP 실행 위치 | 로컬 → EC2 SCP | 로컬 Docker |
| 결과 저장 위치 | `reports/pulled/` | `reports/latest/` |
| AWS 필요 여부 | 필수 | 샘플 로그 시 불필요 |
| 권장 용도 | 실제 운영 | 개발·테스트 |

---

## 9. 결과물 확인

### 9-1. 결과 파일 위치

```bash
# 결과 저장 경로 확인
cat reports/pulled/latest.txt

# 날짜별 파일 목록
ls reports/pulled/2026-07-07/
```

| 파일 | 설명 |
|---|---|
| `report_*.md` | AI 보안 분석 보고서 (9개 섹션, 한국어) |
| `report.pdf` | ISMS-P / PCI-DSS 컴플라이언스 감사보고서 PDF |
| `report.html` | 컴플라이언스 보고서 HTML (브라우저) |
| `analysis_*.json` | WAF 분석 요약 (위험 IP, 차단율, 공격 유형) |
| `ab_test_*.json` | A/B 테스트 결과 (Count vs Block 모드 비교) |

```bash
# Windows에서 결과 폴더 열기
start reports\pulled\2026-07-07

# 컴플라이언스 판정 요약 출력
python -X utf8 compliance/check_output.py
```

### 9-2. 컴플라이언스 판정 예시

```
판정: 부분 적정
WAF 차단율: 58.5%  |  HIGH 위험 IP: 1개  |  차단 중: 1개

PCI DSS: e1 충족 / e2 충족 / e3 충족 / e4 충족 / e5 부분충족
ISMS-P : 2.5~2.11 전항목 적정
```

---

## 10. Grafana 대시보드

### 10-1. 접속 정보

| 항목 | 값 |
|---|---|
| URL | `http://43.201.194.252:3000` |
| 계정 | `admin` |
| 비밀번호 | `admin123!` |

### 10-2. 대시보드 패널

| 패널 | 데이터 소스 | 내용 | 시간 범위 반응 |
|---|---|---|---|
| 총 요청 수 / WAF 차단 수 / 차단율 | json-api | 분석 요약 통계 | ✅ |
| HIGH 위험 IP / 고유 IP 수 | json-api | IP 분석 | ✅ |
| ALLOW / BLOCK 비율 (파이 차트) | json-api | 액션별 비율 | ✅ |
| 시간대별 요청 추이 (막대 차트) | json-api | 5분 단위 트래픽 | ✅ |
| 공격 유형 분포 / WAF 룰셋 탐지 | json-api | 공격 분류 | ✅ |
| TOP 10 위험 IP 목록 | json-api | 위험도·국가·공격유형 | ✅ |
| IP 위험 등급 분포 (파이 차트) | json-api | HIGH/MEDIUM/LOW | ✅ |
| 파이프라인 실행 이력 | json-api | 최근 10회 결과 | ✅ |
| **BLOCK / ALLOW 실시간 추이** | **Loki** | **실시간 시계열** | ✅ |
| **WAF 이벤트 라이브 스트림** | **Loki** | **실시간 로그 스트림** | ✅ |
| Count 모드 vs Block 모드 비교 | json-api | A/B 테스트 결과 | - |
| ZAP High/Medium/Low 알림 수 | json-api | 취약점 현황 | - |
| 현재 보안 상태 | json-api | WAF 모드·MFA 등 | - |

> **시간 범위 연동**: Grafana 우측 상단 시간 범위 선택기를 조정하면 json-api 패널 및 Loki 패널 모두 해당 시간 범위의 데이터를 표시합니다. 선택 범위 내 파이프라인 실행 결과가 없으면 패널이 빈 상태로 표시됩니다.

### 10-3. 대시보드 자동 갱신

파이프라인 실행 완료 후 `run_remote.py`가 EC2 `reports/latest/`를 로컬로 동기화합니다. Grafana 대시보드는 10초마다 자동으로 갱신됩니다.

수동 갱신이 필요한 경우:

```bash
# EC2에서 컨테이너 재시작
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 \
  "sudo docker-compose -f /opt/cloud-security-platform/monitoring/docker-compose.yml restart json-api"
```

---

## 11. GitOps WAF 자동 차단 흐름

파이프라인이 HIGH 위험 IP를 탐지하면 WAF 차단 목록에 자동으로 추가됩니다.

### 자동 흐름

```
① 파이프라인 실행 → 위험 IP 분석 (risk_score ≥ 70 = HIGH)
② auto_pr.py 실행
   - 현재 terraform/waf_blocked_ips.auto.tfvars와 대조
   - 이미 차단 중인 IP는 PR 생성 스킵 (중복 방지)
   - 신규 HIGH 위험 IP만 tfvars에 추가
③ GitHub PR 자동 생성
   제목: "fix(waf): 신규 HIGH 위험 IP N개 차단 목록 추가"
④ PR 검토 후 main 브랜치에 merge
⑤ 차단 반영
   - GitHub Actions workflow_dispatch → Terraform Apply (자동)
   - 또는 로컬 Terraform Apply (수동)
```

### 로컬 Terraform Apply (PR merge 후)

```bash
cd terraform

# 최신 코드 pull (PR merge 반영)
git pull

# 계획 확인
terraform plan \
  -var="ssh_public_key=$(cat ~/.ssh/cloud-sec-key2.pub)" \
  -out=tfplan

# 적용 (WAF IPSet 갱신)
terraform apply tfplan
```

### 위험도 산정 기준

```
risk_score = volume(최대 40점) + block_rate×30 + attack_type×20 + CTI×30
HIGH   ≥ 70점
MEDIUM ≥ 40점
LOW    < 40점
```

---

## 12. GitHub Actions CI/CD 설정

### 12-1. Secrets 등록 방법

> 상세 등록 절차 (gh CLI / 웹 UI / IAM 키 발급 방법 포함) → **[5-0 ② GitHub Actions Secrets 등록](#-github-actions-secrets-등록)** 참고

등록이 필요한 Secret 목록:

```
AWS_ACCESS_KEY_ID       = AKIA...
AWS_SECRET_ACCESS_KEY   = ...
AWS_REGION              = ap-northeast-2
SSH_PUBLIC_KEY          = (cat ~/.ssh/cloud-sec-key2.pub 의 전체 출력)
EC2_HOST                = 43.201.194.252  ← Terraform 완료 후 업데이트
EC2_SSH_PRIVATE_KEY     = (cat ~/.ssh/cloud-sec-key2 의 전체 PEM 내용)
INFRACOST_API_KEY       = (선택)
```

등록 확인:
```bash
gh secret list --repo goormSecurity/cloud-security-platform_final
```

### 12-2. 워크플로 구성

| 워크플로 | 트리거 | 내용 |
|---|---|---|
| **[CI] Validate & Test** | PR / push | Python 문법 검사, pytest, Terraform fmt·validate, tfsec |
| **[CI] Infracost** | PR | WAF 정책 변경 비용 분석 → PR 댓글 게시 |
| **[CD] Security Analysis Pipeline** | main push | 샘플 로그 분석 → 컴플라이언스 보고서 → artifact 저장 |
| **[CD] Deploy to EC2** | main push | EC2 `git pull` + json-api 컨테이너 재시작 |
| **[CD] Deploy to AWS (Terraform Apply)** | 수동 (workflow_dispatch) | WAF·EC2·S3 인프라 갱신 (IP 차단 목록 반영) |
| **[Manual] AI Security Report** | 수동 (workflow_dispatch) | self-hosted runner에서 AI 보고서 생성 |

### 12-3. 수동 Terraform Apply (GitHub Actions)

WAF IP 차단 목록 PR을 머지한 뒤 아래 방법 중 하나로 Terraform apply를 실행합니다.

**웹 UI:**
```
GitHub Actions 탭 → "Cloud Security Platform — CI/CD" 선택
→ "Run workflow" 버튼 클릭 → 브랜치: main → Run workflow
```

**gh CLI:**
```bash
# 워크플로 트리거
gh workflow run "Cloud Security Platform — CI/CD" \
  --repo goormSecurity/cloud-security-platform_final

# 실행 상태 확인
gh run list \
  --repo goormSecurity/cloud-security-platform_final \
  --workflow "Cloud Security Platform — CI/CD" \
  --limit 3

# 실시간 로그 스트림
gh run watch --repo goormSecurity/cloud-security-platform_final
```

> `[Manual] AI Security Report` 잡은 `self-hosted` 러너가 없으면 대기 상태로 남습니다. `[CD] Deploy to AWS (Terraform Apply)` 잡만 완료되면 WAF 정책이 반영됩니다.

---

## 13. 개별 단계 실행

### 공격 시뮬레이션

```bash
# dry-run (전송 없이 목록만 출력)
python attack_simulation/attack_runner.py --dry-run

# 실제 전송 (ALB 대상)
python attack_simulation/attack_runner.py \
  --target http://cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com

# 특정 앱·유형만
python attack_simulation/attack_runner.py --app juiceshop --category sqli xss
```

### WAF 로그 분석

```bash
# 샘플 로그 분석
python analyzer/main.py --source analyzer/sample_logs

# 특정 로그 디렉터리
python analyzer/main.py --source analyzer/live_logs
```

### 증적 수집기 개별 실행

```bash
python scripts/collect_waf.py           # WAF WebACL·IPSet
python scripts/collect_cloudtrail.py    # CloudTrail 14일 이벤트
python scripts/collect_prowler.py       # Prowler MFA·S3·CloudTrail 점검
python scripts/collect_cmk.py           # CMK + Object Lock
python scripts/collect_config_diff.py   # AWS Config 드리프트
python scripts/collect_s3_security.py   # S3 버킷 보안 감사
python scripts/collect_trivy.py         # Trivy 컨테이너·IaC 취약점 스캔
```

### AI 보고서 생성

```bash
# EC2 Ollama 연결 (platform.yaml의 analysis_ip 사용)
python ai/report_generator.py

# 특정 분석 파일 지정
python ai/report_generator.py --input output/analysis_20260707_064403.json
```

### 컴플라이언스 보고서 생성

```bash
python compliance/build_data.py    # 수집기 출력 통합 → compliance/real_data.json
python compliance/render.py        # HTML + PDF 렌더링 → compliance/output/
```

### Slack 알림 테스트

```bash
python scripts/notify_slack.py     # 최신 분석 결과로 Slack/Discord 전송
```

---

## 14. 전체 파이프라인 흐름

```
[Step 0]  S3 WAF 실시간 로그 수집                      collect_waf_logs.py
          S3(aws-waf-logs-cloud-sec-dev) → EC2 내부
          │
[Step 1]  공격 시뮬레이션 (로컬 실행)                   attack_runner.py
          SQLi / XSS / PathTraversal / CommandInjection / ScannerUA
          │
[Step 2]  WAF 로그 분석 + CTI 위험도 산정               analyzer/main.py
          AbuseIPDB API → IP별 위험도 (HIGH/MEDIUM/LOW)
          → output/analysis_YYYYMMDD_HHMMSS.json
          │
[Step 3]  WAF A/B 테스트 (Count vs Block 차단율 비교)   ab_test.py
          │
[Step 3b] FP/FN 오탐/미탐 분석                         analyze_fp_fn.py
          │
[Step 3c] WAF WebACL·IPSet describe 수집               collect_waf.py
          → raw/waf_web_acl.json
          │
[Step 3d] CloudTrail 변경 이력 수집 (14일)              collect_cloudtrail.py
          → compliance/input/cloudtrail_events.json
          │
[Step 3e] Prowler 보안 점검                             collect_prowler.py
          MFA·S3 암호화·CloudTrail 로그 검증
          → compliance/input/prowler_report.json
          │
[Step 3f] CMK + Object Lock 증적 수집                  collect_cmk.py
          → compliance/input/{bucket_encryption, kms_key, object_lock}.json
          │
[Step 3g] AWS Config 드리프트 감지                      collect_config_diff.py
          → compliance/input/config_diff.json
          │
[Step 3h] S3 버킷 보안 감사                             collect_s3_security.py
          → compliance/input/s3_security.json
          │
[Step 3i] Trivy 컨테이너·IaC 취약점 스캔               collect_trivy.py
          SSH → EC2 앱 서버 Docker 이미지 스캔
          → compliance/input/trivy_report.json
          │
[Step 4]  OWASP ZAP 웹 취약점 스캔 (로컬 실행)         zap_scanner.py
          ★ EC2에서 실행 시 WAF가 스캔 트래픽 차단 위험
          → output/zap_report_YYYYMMDD_HHMMSS.json
          │
[Step 5]  AI 보안 보고서 생성 (EC2 GPU)                ai/report_generator.py
          Ollama(qwen2.5:7b) + LangChain → 9개 섹션 Markdown
          → ai/output/report_YYYYMMDD_HHMMSS.md
          │
[Step 5b] AI 분석 JSON 변환                             generate_analysis_json.py
          → compliance/input/ai_analysis.json
          │
[Step 6]  GitHub PR 이력 수집                           pr_collector.py
          → compliance/input/github_pr.json
          │
[Step 7]  ISMS-P / PCI-DSS 컴플라이언스 보고서 생성    build_data.py + render.py
          → compliance/output/report.html / report.pdf
          │
[Step 8]  고위험 IP → GitHub PR 자동 생성              auto_pr.py
          → terraform/waf_blocked_ips.auto.tfvars 수정
          → GitHub PR (이미 차단된 IP는 PR 생성 스킵)
          │
[Step 9]  Slack 알림                                    notify_slack.py
          WAF 모드 판단: waf_web_acl.json OverrideAction 기반
          │
[Step 10] S3 업로드                                     (run_pipeline.py 내장)
          → s3://cloud-sec-audit-evidence-dev/pipeline-results/YYYY/MM/DD/
          │
[Step 11] Grafana 동기화 (분석 결과 → EC2 output/ 반영)
          → http://43.201.194.252:3000
```

---

## 15. 주의사항

### 보안

- **원시 WAF 로그 로컬 저장 금지**: 반드시 `run_remote.py`를 사용하세요. `run_pipeline.py --live`는 개발·테스트 전용입니다.
- **`.env` / `platform.yaml` Git 커밋 금지**: 두 파일 모두 `.gitignore`에 포함되어 있습니다. `git status`로 확인 후 커밋하세요.
- **SSH 키 권한**: `chmod 400 ~/.ssh/cloud-sec-key2` 설정이 필요합니다. 너무 넓은 권한(644)이면 SSH 연결이 거부됩니다.
- **IAM 최소 권한**: 파이프라인 계정에 관리자 권한을 부여하지 마세요. [4-2. IAM 권한](#4-2-iam-권한-최소-권한-원칙) 목록만 부여합니다.

### ZAP 스캔 위치

ZAP을 EC2에서 실행하면 WAF가 스캔 트래픽을 공격으로 판단해 EC2 IP를 차단할 수 있습니다. ZAP은 반드시 **로컬 PC**에서 실행하고 `run_remote.py`가 결과를 EC2로 전달합니다.

### Terraform 상태 파일

`terraform.tfstate`에는 AWS 리소스 ID·IP 등 민감 정보가 포함됩니다. `backend.hcl`로 S3에 원격 저장하며, 로컬에 `.tfstate` 파일이 생성되면 즉시 `.gitignore`에 추가하고 원격 state를 사용하세요.

### WAF 로그 S3 반영 지연

WAF 로그는 S3에 **2~5분** 후 반영됩니다. `run_remote.py`의 `--waf-sync-delay` 기본값은 180초입니다. 공격 후 로그가 없다면 지연 시간을 300초로 늘려보세요.

```bash
python scripts/run_remote.py --waf-sync-delay 300
```

### Ollama 모델 메모리

`qwen2.5:7b` 모델은 약 5GB VRAM이 필요합니다. GPU 없는 EC2(`t-series`)에서는 CPU 추론으로 실행되며, 보고서 생성에 20~40분 소요될 수 있습니다. GPU 인스턴스(`g4dn.xlarge` 이상) 권장.

---

## 16. 자주 묻는 문제

**Q. `run_remote.py` 실행 시 SSH 연결이 안 됩니다.**

`platform.yaml`의 `ssh_key` 경로와 `analysis_ip`, 키 파일 권한을 확인하세요.

```bash
chmod 400 ~/.ssh/cloud-sec-key2
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 "echo OK"
```

---

**Q. S3에 결과물이 없다고 나옵니다 (`--pull-only` 시).**

EC2 파이프라인이 아직 실행되지 않았거나 S3 업로드 단계에서 실패한 것입니다.

```bash
# EC2에서 파이프라인 실행 상태 확인
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 \
  "ls -lt /opt/cloud-security-platform/output/ | head -5"

# 저장된 날짜 목록 확인
python scripts/run_remote.py --list
```

---

**Q. Grafana 대시보드에 데이터가 없습니다.**

파이프라인 실행 후 자동 동기화됩니다. 수동으로 새로고침하려면:

```bash
# json-api 컨테이너 재시작 (EC2)
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 \
  "sudo docker-compose -f /opt/cloud-security-platform/monitoring/docker-compose.yml restart json-api"
```

---

**Q. 시간 범위를 바꿔도 일부 Grafana 패널이 변하지 않습니다.**

ZAP 통계 (`/zap-stats`) 및 A/B 테스트 (`/ab-test`) 패널은 각각 별도 스캔·비교 시점의 스냅샷을 표시하므로 시간 범위에 영향받지 않습니다. 그 외 WAF 분석 패널은 모두 시간 범위 연동됩니다.

---

**Q. AI 보고서에 잘못된 수치가 보입니다 (할루시네이션).**

`ai/report_generator.py`의 `build_key_metrics()`가 핵심 지표를 명시적으로 추출해 LLM에 전달합니다. 할루시네이션이 지속되면 Ollama 모델 상태를 확인하세요.

```bash
# EC2에서 Ollama 상태 확인
ssh -i ~/.ssh/cloud-sec-key2 ec2-user@43.201.194.252 \
  "ollama list && curl -s http://localhost:11434/api/tags | python3 -m json.tool"
```

---

**Q. `NoCredentialsError` 오류가 납니다.**

`.env` 파일에 AWS 자격증명이 입력되어 있는지 확인하세요.

```bash
python -c "import boto3; print(boto3.client('sts').get_caller_identity())"
```

---

**Q. 컴플라이언스 PDF가 생성되지 않습니다.**

Playwright Chromium이 설치되어 있는지 확인합니다.

```bash
playwright install chromium
python compliance/render.py
```

---

**Q. GitHub PR 자동 생성이 실패합니다.**

`.env`의 `GITHUB_TOKEN`이 유효한지, `repo` scope가 있는지 확인합니다.

```bash
# 토큰 권한 확인
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/goormSecurity/cloud-security-platform_final

# platform.yaml의 github_repo 확인
grep github_repo platform.yaml
```

---

**Q. Terraform Apply가 GitHub Actions에서 실패합니다.**

GitHub Secrets에 `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`이 모두 등록되어 있는지 확인합니다. 없으면 로컬에서 직접 실행합니다.

```bash
cd terraform
terraform init -backend-config=backend.hcl
terraform apply -var="ssh_public_key=$(cat ~/.ssh/cloud-sec-key2.pub)"
```

---

## 17. 출력 파일 구조

```
reports/
├── pulled/
│   ├── 2026-07-07/              ← run_remote.py로 S3에서 내려받은 결과물
│   │   ├── report_*.md          ← AI 보안 보고서 (9개 섹션)
│   │   ├── report.pdf           ← ISMS-P / PCI-DSS 감사보고서 PDF
│   │   ├── report.html          ← 컴플라이언스 보고서 HTML
│   │   ├── analysis_*.json      ← WAF 분석 요약 (Grafana용)
│   │   ├── ab_test_*.json       ← A/B 테스트 결과
│   │   └── real_data.json       ← 컴플라이언스 매핑 데이터
│   └── latest.txt               ← 가장 최신 결과 폴더 경로
│
└── latest/                      ← EC2 reports/latest/ 동기화본 (run_remote.py 6-B 단계)

output/                          ← 로컬 파이프라인 중간 결과물
├── analysis_YYYYMMDD_HHMMSS.json
└── zap_report_YYYYMMDD_HHMMSS.json

compliance/input/                ← 증적 수집기 출력 (감사 원본)
├── cloudtrail_events.json       ← CloudTrail 14일 이벤트
├── prowler_report.json          ← Prowler 보안 점검 결과
├── trivy_report.json            ← Trivy 컨테이너·IaC 취약점 스캔
├── s3_security.json             ← S3 버킷 보안 감사
├── kms_key.json                 ← KMS 키 메타데이터
├── object_lock_config.json      ← Object Lock 설정
├── config_diff.json             ← AWS Config 드리프트 탐지
├── ai_analysis.json             ← AI 분석 요약 JSON
└── github_pr.json               ← GitHub PR 이력

terraform/
└── waf_blocked_ips.auto.tfvars  ← auto_pr.py가 자동 갱신 (수동 수정 금지)

analyzer/live_logs/              ← .gitignore — Git 커밋 안됨
                                 ← run_pipeline.py --live 시 임시 저장 (개발용)
                                 ← run_remote.py 사용 시 이 폴더에 로그가 생성되지 않음
```

---

## 18. 프로젝트 디렉터리 구조

```
cloud-security-platform/
│
├── scripts/
│   ├── run_pipeline.py          ← 로컬 파이프라인 실행기 (개발·테스트용)
│   ├── run_remote.py            ← ★ 운영 모드 — EC2 실행 + S3 결과 pull
│   ├── auto_pr.py               ← 고위험 IP → GitHub PR (중복 방지 포함)
│   ├── collect_waf_logs.py      ← S3 WAF 로그 수집
│   ├── collect_waf.py           ← WAF WebACL·IPSet describe
│   ├── collect_cloudtrail.py    ← CloudTrail 이벤트 수집
│   ├── collect_prowler.py       ← Prowler 보안 점검
│   ├── collect_cmk.py           ← CMK + Object Lock 증적
│   ├── collect_config_diff.py   ← AWS Config 드리프트 감지
│   ├── collect_s3_security.py   ← S3 버킷 보안 감사
│   ├── collect_trivy.py         ← Trivy 취약점 스캔 (SSH 원격)
│   ├── notify_slack.py          ← Slack/Discord 위험 알림
│   ├── generate_config.py       ← platform.yaml 자동 생성 (Terraform 출력 기반)
│   └── config_loader.py         ← 설정 로더 (platform.yaml + .env)
│
├── analyzer/
│   ├── main.py                  ← WAF 로그 분석 CLI
│   ├── waf_analyzer.py          ← 로그 파싱·공격 분류·위험도 산정
│   ├── cti_checker.py           ← AbuseIPDB CTI 연동
│   └── sample_logs/             ← 로컬 테스트용 샘플 WAF 로그
│
├── ai/
│   ├── report_generator.py      ← LangChain + Ollama 보고서 생성
│   │                               build_key_metrics(): 할루시네이션 방지
│   ├── prompts.py               ← 시스템·유저 프롬프트 템플릿
│   ├── generate_analysis_json.py
│   └── tests/
│       └── test_report_generator.py  ← 단위 테스트
│
├── attack_simulation/
│   ├── attack_runner.py         ← SQLi/XSS/CMDI/PathTraversal 시뮬레이션
│   └── zap_scanner.py           ← OWASP ZAP (Docker 기반)
│
├── security/
│   └── ab_test.py               ← WAF Count/Block A/B 테스트
│
├── compliance/
│   ├── build_data.py            ← 증적 통합 Adapter (수집기 출력 통합)
│   ├── render.py                ← Jinja2 HTML·PDF 렌더링
│   ├── template.html            ← ISMS-P / PCI-DSS 보고서 HTML 템플릿
│   ├── check_output.py          ← 판정 결과 요약 출력
│   ├── pr_collector.py          ← GitHub PR 이력 수집 (변경관리 증적)
│   └── input/                   ← 수집기 출력 파일
│
├── monitoring/
│   ├── docker-compose.yml       ← Grafana + Loki + Fluent Bit + JSON API
│   ├── json_server.py           ← Flask JSON API (EC2 컨테이너에서 실행)
│   │                               시간 범위 파라미터 지원 (from/to)
│   ├── loki-config.yml          ← Loki 설정
│   ├── fluent-bit.conf          ← Fluent Bit → Loki 파이프라인
│   ├── provisioning/            ← Grafana 자동 프로비저닝 설정
│   │   ├── datasources/         ← Loki + Infinity 데이터소스
│   │   └── dashboards/          ← 대시보드 자동 로드 설정
│   └── dashboards/
│       └── security_dashboard_ec2.json  ← Grafana 대시보드 정의
│
├── terraform/
│   ├── main.tf / variables.tf / outputs.tf / provider.tf
│   ├── backend.tf               ← S3 원격 state (partial config)
│   ├── backend.hcl.example      ← backend.hcl 템플릿 (gitignore)
│   ├── waf_blocked_ips.auto.tfvars  ← auto_pr.py 자동 갱신 (수동 수정 금지)
│   └── modules/
│       ├── waf/                 ← WAF WebACL + IP 차단 목록
│       ├── alb/                 ← ALB + 리스너
│       ├── ec2/                 ← 분석 서버 + 앱 서버
│       ├── s3/                  ← WAF 로그 + 감사 증적 버킷
│       ├── networking/          ← VPC + 서브넷 + 보안 그룹
│       ├── logging/             ← CloudTrail
│       └── kms/                 ← CMK (선택)
│
├── .github/
│   └── workflows/
│       └── ci.yml               ← CI/CD 파이프라인
│
├── .env.example                 ← 환경 변수 템플릿 (커밋됨)
├── .env                         ← 실제 키 값 (.gitignore — 커밋 안됨)
├── platform.yaml.example        ← EC2·S3 설정 템플릿 (커밋됨)
├── platform.yaml                ← 실제 설정 값 (.gitignore — 커밋 안됨)
└── requirements.txt             ← Python 의존성
```

---

## 19. 팀 구성

| 역할 | 담당자 | 담당 영역 |
|---|---|---|
| 팀장 / 통합 | 유지원 | 전체 파이프라인 통합, 수집기 구현, 대시보드, 산출물 검수 |
| 인프라 | 천혜수 | Terraform IaC, AWS 배포, CI/CD |
| 분석 | 박소연 | WAF 로그 분석 엔진, Grafana 시각화 |
| AI | 송일환 | LangChain + Ollama 보고서 생성기 |
| 보안 테스트 | 현수민 | 공격 시뮬레이션, ZAP 스캐너, A/B 테스트 |
| 컴플라이언스 | 김병옥 | ISMS-P 매핑, 컴플라이언스 보고서 렌더러 |
