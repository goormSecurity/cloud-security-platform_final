# scripts — 파이프라인 오케스트레이터 및 수집기

전체 파이프라인 실행기(`run_pipeline.py`)와 ISMS-P 컴플라이언스 증적 수집기 모음입니다.

---

## 파일 구조

```
scripts/
├── run_pipeline.py          # 전체 파이프라인 실행기 (Step 0 ~ Step 8)
├── collect_waf_logs.py      # S3 WAF 로그 실시간 수집
├── collect_waf.py           # WAF WebACL·IPSet describe
├── collect_cloudtrail.py    # CloudTrail 변경 이력 수집 (ISMS-P 2.9)
├── collect_prowler.py       # Prowler 보안 점검 (boto3 직접 구현)
├── collect_cmk.py           # CMK + Object Lock 증적 수집 (ISMS-P 2.7)
├── collect_config_diff.py   # AWS Config 드리프트 감지 (ISMS-P 2.10)
└── auto_pr.py               # 고위험 IP → WAF 차단 GitHub PR 자동 생성
```

---

## run_pipeline.py

전체 파이프라인을 순서대로 실행하며 각 단계의 성공/실패를 기록합니다.  
보통 `run_local.ps1`을 통해 간접 실행합니다.

```bash
# 직접 실행 (샘플 로그)
python scripts/run_pipeline.py

# 실시간 S3 로그
python scripts/run_pipeline.py --live --live-hours 1

# 단계 생략
python scripts/run_pipeline.py --skip-zap --skip-ai --skip-pr
```

---

## 수집기 목록

### collect_waf_logs.py

S3 버킷에서 WAF 로그를 다운로드합니다.

```bash
python scripts/collect_waf_logs.py --hours 1
# → analyzer/live_logs/live_YYYYMMDD_HHMMSS.jsonl
```

### collect_waf.py

WAF WebACL 규칙 구성과 IPSet을 수집합니다.

```bash
python scripts/collect_waf.py
# → raw/waf_web_acl.json
# → raw/waf_ipset.json
# → raw/waf_resources.json
```

### collect_cloudtrail.py

최근 14일간 WAF·IAM·KMS 관련 CloudTrail 이벤트를 수집합니다.

```bash
python scripts/collect_cloudtrail.py
# → compliance/input/cloudtrail_events.json
```

수집 대상 이벤트 종류 (18종): `PutWebACL`, `UpdateWebACL`, `CreateIPSet`, `DeleteIPSet`, `CreateKey`, `PutKeyPolicy`, `CreateTrail`, `PutBucketEncryption` 등

### collect_prowler.py

boto3를 사용해 Prowler 방식의 보안 점검을 직접 구현합니다.

```bash
python scripts/collect_prowler.py
# → compliance/input/prowler_report.json
```

| 점검 항목 | ISMS-P 매핑 |
|---|---|
| 루트 계정 MFA 활성화 | 2.5 인증 및 접근통제 |
| WAF WebACL 존재 여부 | 2.11 악성코드 통제 |
| S3 버킷 암호화 (SSE ≥ AES256) | 2.7 암호화 적용 |
| CloudTrail 로그 검증 활성화 | 2.9 로그 및 접속기록 |

### collect_cmk.py

WAF 로그 버킷의 암호화·KMS·Object Lock 상태를 수집합니다.

```bash
python scripts/collect_cmk.py
python scripts/collect_cmk.py --bucket your-bucket --region ap-northeast-2
```

**출력 파일 7종 (`compliance/input/`)**

| 파일 | 내용 |
|---|---|
| `bucket_encryption.json` | SSE 알고리즘, KMS 키 ID |
| `kms_key.json` | 키 ARN, 상태, 관리자 |
| `kms_rotation.json` | 자동 회전 여부 |
| `kms_key_policy.json` | 키 정책 |
| `object_lock_config.json` | Object Lock 설정 (COMPLIANCE 모드) |
| `object_retention.json` | 개별 오브젝트 보존 기간 |
| `object_head.json` | 최신 오브젝트 헤더 (무결성 샘플) |

> KMS CMK가 없는 경우 `NOT_FOUND` 상태로 기록되며 파이프라인은 정상 진행됩니다.

### collect_config_diff.py

AWS Config Recorder로 WAF·ALB·S3 리소스 변경 이력을 수집합니다.

```bash
python scripts/collect_config_diff.py
python scripts/collect_config_diff.py --days 14
# → compliance/input/config_diff.json
```

> Config Recorder가 비활성화된 경우 `NOT_CONFIGURED` (WARN) 상태로 기록됩니다.

### auto_pr.py

분석 결과에서 HIGH 위험 IP를 추출하여 WAF IPSet 차단 PR을 자동 생성합니다.

```bash
python scripts/auto_pr.py
```

**동작 흐름**

```
analysis_*.json 로드
    ↓
HIGH 위험 IP 추출
    ↓
terraform/waf_blocked_ips.auto.tfvars 업데이트
    ↓
auto/waf-blocklist-YYYYMMDDHHMMSS 브랜치 생성
    ↓
GitHub PR 생성 (goormSecurity/cloud-security-platform)
```

> HIGH 위험 IP가 없으면 빈 tfvars 파일로 PR이 생성됩니다.  
> (향후 개선: HIGH IP 0개이면 PR 생략하도록 수정 예정)
