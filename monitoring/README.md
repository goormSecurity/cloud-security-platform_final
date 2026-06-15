@'
# WAF 분석 결과 시각화 (Grafana)

수민님 분석 엔진(`analyzer/`)이 생성한 JSON 결과물을 Grafana 대시보드로 시각화합니다.

## 구성

- **Grafana**: http://localhost:3000 (admin / admin123!)
- **Loki**: 로그 스트리밍용 (현재 미사용, 추후 확장 대비)
- **JSON Server (Flask)**: analyzer JSON을 HTTP API로 제공

## 데이터 흐름

analyzer/output/analysis_*.json
  -> (복사)
monitoring/data/analysis_*.json
  -> (Flask json_server.py가 HTTP API로 노출)
http://localhost:5000/{summary, top-ips, rule-hits, time-buckets, attack-types, action-counts}
  -> (Grafana JSON API 데이터소스)
Grafana 대시보드

## 폴더 구조

monitoring/
- dashboards/security_dashboard.json   # Grafana 대시보드 정의
- data/                                 # analyzer JSON 결과 복사 위치 (gitignore)
- docker-compose.yml                    # Grafana + Loki 컨테이너 정의
- json_server.py                        # Flask API 서버
- README.md

## 실행 방법

### 사전 준비
- Docker Desktop 실행 중
- Python 3.x 가상환경
- analyzer 결과물 (../analyzer/output/analysis_*.json)

### 1. analyzer 결과 복사
    mkdir data
    copy ..\analyzer\output\analysis_*.json .\data\

### 2. JSON 서버 실행 (별도 터미널)
    pip install flask flask-cors
    python json_server.py

서버가 5000번 포트에서 실행됩니다.

### 3. Grafana 실행
    docker-compose up -d

### 4. Grafana에서 데이터소스 등록
1. http://localhost:3000 접속 (admin / admin123!)
2. Connections > Data sources > Add new data source
3. JSON API 선택
4. 입력값
   - Name: WAF Analysis
   - URL: http://host.docker.internal:5000
5. Save and test 클릭하여 OK 확인

### 5. 대시보드 import
1. 좌측 메뉴 > Dashboards > New > Import
2. dashboards/security_dashboard.json 업로드
3. 데이터소스 매핑: WAF Analysis 선택
4. Import 클릭

## 패널 구성

| 번호 | 제목 | 차트 | API 경로 |
 
| 1 | 시간대별 공격 추이 | Time series | /time-buckets |
| 2 | WAF 룰별 탐지 건수 | Bar chart | /rule-hits |
| 3 | 공격 유형 분포 | Pie chart | /attack-types |
| 4 | Action 비율 | Pie chart | /action-counts |

## 의존성

analyzer 모듈이 생성하는 다음 형식의 JSON을 사용합니다.

- summary.action_counts: ALLOW/BLOCK/COUNT 카운트
- summary.attack_type_counts: 공격 유형별 카운트
- rule_hits: WAF 룰별 탐지 건수
- time_buckets: 시간대별 요청 수 (hour, count)

## 종료 방법

    docker-compose down

JSON 서버는 Ctrl+C로 종료합니다.
'@ | Out-File -FilePath README.md -Encoding utf8