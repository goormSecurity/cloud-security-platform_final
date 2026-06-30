import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
MAX_GENERATION_ATTEMPTS = 3


# 섹션 존재 여부는 핵심 키워드로 확인 (소형 모델의 사소한 제목 변형 허용)
REQUIRED_SECTIONS = [
    "WAF 보안 분석 보고서",
    "공격 현황 요약",
    "주요 공격 유형",
    "위험 IP 분석",
    "WAF 탐지 결과",
    "정책 개선 제안",
    "운영자 검토 사항",
]


def load_json(input_path: Path) -> Dict[str, Any]:
    """
    Analyzer가 생성한 JSON 파일을 읽는다.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"입력 JSON 파일을 찾을 수 없습니다: {input_path}")

    with input_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def flatten_json(data: Any, prefix: str = "") -> List[str]:
    """
    JSON 데이터를 LLM에 전달하기 쉬운 key=value 형태의 사실 목록으로 변환한다.
    """
    lines = []

    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            lines.extend(flatten_json(value, new_prefix))

    elif isinstance(data, list):
        if not data:
            lines.append(f"{prefix}=[]")
        else:
            for idx, item in enumerate(data):
                new_prefix = f"{prefix}[{idx}]"
                lines.extend(flatten_json(item, new_prefix))

    else:
        lines.append(f"{prefix}={data}")

    return lines


def build_facts_block(data: Dict[str, Any]) -> tuple[str, str]:
    """
    보고서 작성에 필요한 핵심 통계를 FACTS 블록과 허용 숫자 목록으로 변환한다.
    Returns: (facts_text, allowed_numbers_text)
    """
    lines: List[str] = []

    def add(key: str, val: Any) -> None:
        lines.append(f"- {key}={val}")

    summary = data.get("summary") or {}

    add("total_requests", summary.get("total_requests", 0))
    add("unique_ips",     summary.get("unique_ips", 0))
    add("high_risk_ips",  summary.get("high_risk_ips", 0))
    add("block_rate",     summary.get("block_rate", 0.0))
    add("generated_at",   data.get("generated_at", "unknown"))

    for action, cnt in (summary.get("action_counts") or {}).items():
        add(f"action_counts.{action}", cnt)

    for atype, cnt in (summary.get("attack_type_counts") or {}).items():
        add(f"attack_type_counts.{atype}", cnt)

    for rule, cnt in (data.get("rule_hits") or {}).items():
        add(f"rule_hits.{rule}", cnt)

    top_ips = (data.get("top_ips") or [])[:10]
    for entry in top_ips:
        ip = entry.get("ip", "?")
        add(f"top_ip.{ip}.request_count", entry.get("request_count", 0))
        add(f"top_ip.{ip}.risk_level",    entry.get("risk_level", "UNKNOWN"))
        add(f"top_ip.{ip}.risk_score",    entry.get("risk_score", 0))
        add(f"top_ip.{ip}.country",       entry.get("country", "?"))
        add(f"top_ip.{ip}.attack_types",  entry.get("attack_types", []))
        add(f"top_ip.{ip}.block_rate",    entry.get("block_rate", 0.0))

    if not lines:
        return "분석 데이터가 비어 있음", "없음"

    facts_text = "\n".join(lines)

    # FACTS 블록에서 실제로 등장하는 숫자만 추출 → LLM에게 명시적으로 전달
    raw_numbers = extract_numbers_from_json(data)
    # 섹션 번호 1~6은 항상 허용
    allowed = sorted(raw_numbers | {"1", "2", "3", "4", "5", "6"},
                     key=lambda x: float(x) if x.replace(".", "").lstrip("-").isdigit() else 0)
    allowed_numbers_text = ", ".join(allowed) if allowed else "없음"

    return facts_text, allowed_numbers_text


def call_ollama_with_langchain(
    facts: str,
    allowed_numbers: str,
    model: str,
    ollama_base_url: str
) -> str:
    """
    LangChain을 사용해 Ollama의 Llama 모델을 호출한다.
    """
    llm = ChatOllama(
        model=model,
        base_url=ollama_base_url,
        temperature=0,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT_TEMPLATE),
    ])

    chain = prompt | llm | StrOutputParser()

    try:
        result = chain.invoke({
            "facts": facts,
            "allowed_numbers": allowed_numbers,
        })

        return result.strip()

    except Exception as e:
        error_text = str(e).lower()

        if (
            "connection refused" in error_text
            or "failed to connect" in error_text
            or "connecterror" in error_text
            or "all connection attempts failed" in error_text
            or "winerror 10061" in error_text
        ):
            print("Ollama 서버가 실행 중이 아닙니다.")
            print("ollama serve 또는 ollama run llama3.1:8b를 먼저 실행하세요.")
            sys.exit(1)

        if "not found" in error_text or ("model" in error_text and "not" in error_text):
            print(f"Ollama 모델을 찾을 수 없습니다: {model}")
            print(f"다음 명령어를 먼저 실행하세요: ollama pull {model}")
            sys.exit(1)

        print("LangChain을 통한 Ollama 호출 중 오류가 발생했습니다.")
        print(e)
        sys.exit(1)


def extract_ips_from_text(text: str) -> Set[str]:
    """
    문자열에서 IPv4 주소를 추출한다.
    """
    # Korean particles are Unicode word characters, so \b does not match in
    # text such as "203.0.113.10은". Use numeric boundaries instead.
    ip_pattern = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
    return set(re.findall(ip_pattern, text))


def extract_ips_from_json(data: Any) -> Set[str]:
    """
    JSON 전체에서 IP 주소를 추출한다.
    """
    json_text = json.dumps(data, ensure_ascii=False)
    return extract_ips_from_text(json_text)


def extract_numbers_from_json(data: Any) -> Set[str]:
    """
    JSON에 실제 존재하는 숫자들을 수집한다.
    문자열 안에 포함된 숫자도 함께 수집한다.
    """
    numbers = set()

    def walk(value: Any):
        if isinstance(value, dict):
            for v in value.values():
                walk(v)

        elif isinstance(value, list):
            for item in value:
                walk(item)

        elif isinstance(value, bool) or value is None:
            return

        elif isinstance(value, int):
            numbers.add(str(value))

        elif isinstance(value, float):
            numbers.add(str(value))

            if value.is_integer():
                numbers.add(str(int(value)))

        elif isinstance(value, str):
            found = re.findall(r"(?<![\d.])-?\d+(?:\.\d+)?(?![\d.])", value)
            numbers.update(found)

    walk(data)
    return numbers


def extract_numbers_from_report(report: str) -> Set[str]:
    """
    보고서에 등장하는 숫자를 수집한다.
    Markdown 섹션 번호 1~6은 보고서 형식상 허용한다.
    """
    numbers = set(re.findall(r"(?<![\d.])-?\d+(?:\.\d+)?(?![\d.])", report))

    allowed_section_numbers = {"1", "2", "3", "4", "5", "6"}
    numbers -= allowed_section_numbers

    return numbers


def clean_markdown(text: str) -> str:
    """
    모델이 ```markdown 코드블록으로 감싸는 경우 제거한다.
    """
    text = text.strip()

    if text.startswith("```markdown"):
        text = text.removeprefix("```markdown").strip()

    if text.startswith("```"):
        text = text.removeprefix("```").strip()

    if text.endswith("```"):
        text = text.removesuffix("```").strip()

    return text


def validate_required_sections(report: str) -> None:
    """
    보고서에 필수 섹션이 모두 포함되었는지 확인한다.
    """
    missing_sections = [
        section for section in REQUIRED_SECTIONS
        if section not in report
    ]

    if missing_sections:
        raise ValueError(
            "보고서 필수 섹션이 누락되었습니다: "
            + ", ".join(missing_sections)
        )


def validate_no_hallucinated_ips(report: str, data: Dict[str, Any]) -> None:
    """
    보고서에 원본 JSON에 없는 IP가 들어갔는지 검사한다.
    """
    json_ips = extract_ips_from_json(data)
    report_ips = extract_ips_from_text(report)

    extra_ips = report_ips - json_ips

    if extra_ips:
        raise ValueError(
            "보고서에 원본 JSON에 없는 IP가 포함되었습니다: "
            + ", ".join(sorted(extra_ips))
        )


def validate_no_hallucinated_numbers(report: str, data: Dict[str, Any]) -> None:
    """
    보고서에 원본 JSON에 없는 숫자가 들어갔는지 검사한다.
    """
    json_numbers = extract_numbers_from_json(data)
    report_numbers = extract_numbers_from_report(report)

    extra_numbers = report_numbers - json_numbers

    if extra_numbers:
        raise ValueError(
            "보고서에 원본 JSON에 없는 숫자가 포함되었습니다: "
            + ", ".join(sorted(extra_numbers))
        )


def validate_report(report: str, data: Dict[str, Any]) -> None:
    """
    보고서 전체 검증을 수행한다.
    """
    validate_required_sections(report)
    validate_no_hallucinated_ips(report, data)
    validate_no_hallucinated_numbers(report, data)


def save_report(report: str, output_dir: Path) -> Path:
    """
    Markdown 보고서를 output/report_YYYYMMDD_HHMMSS.md 형식으로 저장한다.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"report_{timestamp}.md"

    with output_path.open("w", encoding="utf-8") as f:
        f.write(report)

    return output_path


def generate_report(
    input_path: Path,
    output_dir: Path,
    model: str,
    ollama_base_url: str
) -> Path:
    """
    JSON 입력 파일을 읽고, LangChain + Ollama로 보고서를 생성한 뒤 검증 및 저장한다.
    """
    data = load_json(input_path)

    facts, allowed_numbers = build_facts_block(data)

    validation_error = None
    report = ""
    for attempt in range(MAX_GENERATION_ATTEMPTS):
        report = call_ollama_with_langchain(
            facts=facts,
            allowed_numbers=allowed_numbers,
            model=model,
            ollama_base_url=ollama_base_url
        )
        report = clean_markdown(report)

        try:
            validate_report(report, data)
            validation_error = None
            break
        except ValueError as error:
            validation_error = error
            if attempt < MAX_GENERATION_ATTEMPTS - 1:
                print(f"  [재시도 {attempt + 1}/{MAX_GENERATION_ATTEMPTS - 1}] {error}")

    if validation_error is not None:
        raise validation_error

    output_path = save_report(report, output_dir)

    return output_path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyzer JSON을 읽어 LangChain + Ollama 기반 WAF 보안 분석 Markdown 보고서를 생성합니다."
    )

    parser.add_argument(
        "--input",
        required=True,
        help="입력 JSON 파일 경로. 예: output/analysis_20260616_060954.json"
    )

    parser.add_argument(
        "--output-dir",
        default="output",
        help="보고서 저장 폴더. 기본값: output"
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama 모델명. 기본값: {DEFAULT_MODEL}"
    )

    parser.add_argument(
        "--ollama-base-url",
        default=DEFAULT_OLLAMA_BASE_URL,
        help=f"Ollama Base URL. 기본값: {DEFAULT_OLLAMA_BASE_URL}"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    try:
        output_path = generate_report(
            input_path=input_path,
            output_dir=output_dir,
            model=args.model,
            ollama_base_url=args.ollama_base_url
        )

    except FileNotFoundError as e:
        print(e)
        sys.exit(1)

    except json.JSONDecodeError:
        print("입력 파일이 올바른 JSON 형식이 아닙니다.")
        sys.exit(1)

    except ValueError as e:
        print("보고서 검증에 실패했습니다.")
        print(e)
        sys.exit(1)

    print("LangChain 기반 보고서 생성 완료")
    print(f"저장 위치: {output_path}")


if __name__ == "__main__":
    main()
