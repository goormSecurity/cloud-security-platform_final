# ai — AI 보안 보고서 생성기

Ollama 로컬 LLM과 LangChain LCEL 파이프라인을 사용하여 WAF 분석 결과를 한국어 Markdown 보안 보고서로 변환합니다.  
외부 API 없이 로컬에서 실행되어 데이터 유출 없이 설명 가능한 AI 분석을 제공합니다.

---

## 파일 구조

```
ai/
├── report_generator.py      # LangChain 파이프라인 + 보고서 생성 메인
├── prompts.py               # 시스템 프롬프트 + 사용자 프롬프트 템플릿
├── generate_analysis_json.py # AI 보고서 → compliance/input/ai_analysis.json 변환기
├── requirements.txt         # langchain-ollama, langchain-core
├── output/                  # 생성된 Markdown 보고서 저장 위치
│   └── report_YYYYMMDD_HHMMSS.md
└── tests/
    └── test_report_generator.py
```

---

## 사전 요구사항

**Ollama 설치 및 모델 준비**

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows: https://ollama.com/download 에서 설치

# 모델 다운로드 (약 4.7 GB, 최초 1회)
ollama pull llama3.1:8b

# Ollama 서버 실행 확인
ollama list   # llama3.1:8b 가 목록에 있어야 함
```

> **Windows 한글 경로 이슈**: 사용자 이름이 한글이면 `OLLAMA_MODELS` 환경변수 설정 필요
> ```powershell
> $env:OLLAMA_MODELS = "C:\ollama\models"
> ```
> `run_local.ps1` 실행 시 자동으로 적용됩니다.

---

## 실행 방법

```bash
# 최신 analysis_*.json을 읽어 보고서 생성 (Ollama 서버 실행 중이어야 함)
python ai/report_generator.py

# 특정 분석 파일 지정
python ai/report_generator.py --input output/analysis_20260623_200000.json

# 다른 모델 사용
python ai/report_generator.py --model llama3.2:3b
```

**출력:** `ai/output/report_YYYYMMDD_HHMMSS.md`

```bash
# AI 보고서 → 컴플라이언스 JSON 변환
python ai/generate_analysis_json.py

# 특정 파일 지정
python ai/generate_analysis_json.py \
  --analysis output/analysis_20260623_200000.json \
  --md ai/output/report_20260623_200336.md
```

**출력:** `compliance/input/ai_analysis.json`

---

## LangChain 파이프라인 구성

```
ChatOllama(llama3.1:8b)
    ↑
ChatPromptTemplate(system_prompt + user_prompt)
    ↑
분석 JSON → FACTS 블록 추출 (build_facts_block)
    ↓
StrOutputParser
    ↓
Markdown 보고서 (6개 섹션 검증)
```

**LCEL 파이프라인 코드:**
```python
chain = prompt | ChatOllama(model="llama3.1:8b") | StrOutputParser()
report = chain.invoke({"facts": facts_block})
```

---

## 보고서 구조 (6개 섹션)

| 섹션 | 내용 | 데이터 소스 |
|---|---|---|
| 1. 공격 현황 요약 | 총 요청 수, 고위험 IP 수, 차단율 | FACTS (사실만) |
| 2. 주요 공격 유형 | SQLi·XSS 등 탐지 건수 및 분류 | FACTS (사실만) |
| 3. 위험 IP 분석 | 상위 IP의 요청 패턴, CTI 점수 | FACTS (사실만) |
| 4. WAF 탐지 결과 | rule_hits, action_counts | FACTS (사실만) |
| 5. 정책 개선 제안 | Block 전환 권고, IP 차단 제안 | AI 추론 허용 |
| 6. 운영자 검토 사항 | 즉시 조치 필요 항목 | AI 추론 허용 |

> 섹션 1~4는 FACTS에 없는 수치를 절대 생성하지 않도록 프롬프트에 명시됩니다 (할루시네이션 방지).

---

## ai_analysis.json 스키마 (컴플라이언스 연동)

`generate_analysis_json.py`가 생성하는 파일로, `compliance/build_data.py`가 소비합니다.

```json
{
  "generated_at": "ISO 8601",
  "owasp": "OWASP Top 10:2021 A03 Injection",
  "analyzer_judgment": "재검토 필요",
  "detection_basis": "총 N건 요청 중 최고위험 IP ...",
  "confidence": "보통",
  "risk": {
    "summary": "위험도 60점 (MEDIUM), 고위험 IP 0개",
    "false_positive": "낮음",
    "false_negative": "높음",
    "compliance_impact": "중간",
    "ops_impact": "낮음",
    "final_score": 3,
    "needs_review": true,
    "needs_action": false
  },
  "recommendations": [
    { "item": "WAF Block 전환", "text": "...", "trigger": "ISMS 2.11" }
  ],
  "final_opinion": "..."
}
```
