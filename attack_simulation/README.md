# attack_simulation — WAF 로그 생성용 공격 시뮬레이터

자체 구축한 **인가된 테스트 대상(DVWA / 팀 ALB)** 에 공격 트래픽을 발생시켜,
앞단 WAF가 탐지/차단 로그를 남기도록 유도하는 도구입니다.
이 로그가 분석 엔진 · AI 보고서 · Grafana · 컴플라이언스의 입력 데이터가 됩니다.

> ⚠️ 본 도구는 팀이 직접 구축한 테스트 서버에만 사용합니다. 외부 시스템 대상 사용 금지.

## 실행

추가 설치 없이 표준 라이브러리만으로 동작합니다 (Python 3.8+).

```bash
# 1) 안 보내고 어떤 요청이 나갈지 먼저 확인
python attack_runner.py --dry-run

# 2) 전체 공격 1회씩 전송
python attack_runner.py

# 3) 특정 유형만
python attack_runner.py --category sqli xss

# 4) 부하/비용 조절 (각 패턴 3회, 0.5초 간격)
python attack_runner.py --count 3 --delay 0.5

# 5) 대상 변경 (CloudFront 붙으면 그 주소로)
python attack_runner.py --target http://<새 주소>
```

## 공격 유형

| category | 내용 | 겨냥하는 WAF 룰(예시) |
|---|---|---|
| `sqli` | SQL Injection (boolean / union / stacked) | AWSManagedRulesSQLiRuleSet |
| `xss` | Cross-Site Scripting (script / img / svg) | AWSManagedRulesCommonRuleSet |
| `path_traversal` | 경로 탐색 / LFI (`../../etc/passwd`) | CommonRuleSet (GenericLFI) |
| `command_injection` | OS 명령 주입 (`;cat`, `\|whoami`) | CommonRuleSet |
| `scanner_ua` | 스캐너 User-Agent 위장 (sqlmap, nikto) | AmazonIpReputation / 커스텀 룰 |

> 실제로 무엇이 BLOCK 되고 무엇이 COUNT/ALLOW 되는지는 **팀 WAF 설정**에 달려 있습니다.
> 어떤 매니지드 룰이 어떤 모드로 켜져 있는지에 따라 결과가 달라지므로, 첫 실행 결과로 역으로 확인합니다.

## WAF 로그와 매칭하는 법 (핵심)

모든 요청에 고유 마커를 박습니다:
- HTTP 헤더 `X-Attack-Sim: <asid>`
- 쿼리 파라미터 `asid=<asid>`

전송 기록은 `output/sent_attacks.jsonl` 에 남습니다(asid, 보낸 시각, URL, 응답코드).
→ S3의 WAF 로그에서 이 `asid` 로 검색하면 "내가 보낸 공격 ↔ WAF 판정"을 1:1로 대응시킬 수 있습니다.

```bash
# 예: 버킷에서 로그 받아와서 특정 asid 찾기
aws s3 ls s3://aws-waf-logs-cloud-sec-dev/ --recursive | tail
```

## 팀 공유 체크리스트

- [ ] `python attack_runner.py` 실행 → 응답코드 확인 (403 다수면 차단 동작 중)
- [ ] S3에 WAF 로그가 실제로 쌓이는지 확인
- [ ] **로그가 안 쌓이면** → WAF가 CloudFront에 붙어있는데 ALB 주소로 직접 때려 우회된 것일 수 있음. 인프라 팀과 WAF 연결 지점 확인 필요
- [ ] 실제 로그 샘플 5~10줄을 팀에 공유 → 분석/AI/컴플라이언스 팀 작업 시작

## 주의

- ZAP active scan 같은 대량 스캔 전에 이 스크립트로 **파이프라인부터 검증**하세요.
  대량 트래픽은 WAF 요청 과금 · 데이터 전송 비용을 빠르게 올립니다.
- `output/` 은 `.gitignore` 대상입니다. 전송 기록(실제 트래픽 흔적)은 커밋하지 마세요.
