import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Optional

from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))
try:
    from config_loader import now_kst
except Exception:
    def now_kst(fmt=None):
        from datetime import timezone, timedelta
        t = datetime.now(timezone(timedelta(hours=9)))
        return t.strftime(fmt) if fmt else t.isoformat(timespec="seconds")


DEFAULT_MODEL = "qwen2.5:7b"
try:
    from config_loader import ollama_url as _ollama_url_fn
    DEFAULT_OLLAMA_BASE_URL = _ollama_url_fn()
except Exception:
    DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
MAX_GENERATION_ATTEMPTS = 3

REQUIRED_SECTIONS = [
    "WAF 보안 분석 보고서",
    "공격 현황 요약",
    "위험 IP 분석",
    "정책 개선 제안",
    "운영자 검토 사항",
]


# ── 데이터 로더 ──────────────────────────────────────────────────────

def _find_latest_file(pattern: str) -> Optional[Path]:
    dirs = [_ROOT / "output", _ROOT / "compliance" / "input"]
    files = []
    for d in dirs:
        if d.exists():
            files.extend(d.rglob(pattern))
    return sorted(files)[-1] if files else None


def load_json(path: Path) -> Dict[str, Any]:
    if not path or not path.exists():
        raise FileNotFoundError(f"파일 없음: {path}")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ── FACTS 블록 빌더 ───────────────────────────────────────────────────

def build_waf_facts(data: Dict[str, Any]) -> str:
    lines = []
    summary = data.get("summary", {})
    lines.append(f"- total_requests={summary.get('total_requests', 0)}")
    lines.append(f"- unique_ips={summary.get('unique_ips', 0)}")
    lines.append(f"- high_risk_ips={summary.get('high_risk_ips', 0)}")
    lines.append(f"- block_rate={summary.get('block_rate', 0)}")
    lines.append(f"- generated_at={data.get('generated_at', '')}")
    for action, cnt in (summary.get("action_counts") or {}).items():
        lines.append(f"- action_counts.{action}={cnt}")
    for atype, cnt in (summary.get("attack_type_counts") or {}).items():
        lines.append(f"- attack_type_counts.{atype}={cnt}")
    for rule, cnt in (data.get("rule_hits") or {}).items():
        lines.append(f"- rule_hits.{rule}={cnt}")
    for entry in (data.get("top_ips") or [])[:10]:
        ip = entry.get("ip", "?")
        lines.append(f"- top_ip.{ip}.request_count={entry.get('request_count', 0)}")
        lines.append(f"- top_ip.{ip}.risk_level={entry.get('risk_level', 'UNKNOWN')}")
        lines.append(f"- top_ip.{ip}.risk_score={entry.get('risk_score', 0)}")
        lines.append(f"- top_ip.{ip}.country={entry.get('country', '?')}")
        lines.append(f"- top_ip.{ip}.attack_types={entry.get('attack_types', [])}")
        lines.append(f"- top_ip.{ip}.block_rate={entry.get('block_rate', 0)}")
        ac = entry.get("action_counts", {})
        for a, c in ac.items():
            lines.append(f"- top_ip.{ip}.action.{a}={c}")
    return "\n".join(lines)


def build_prowler_facts(findings: List[Dict]) -> str:
    if not findings:
        return "- prowler=데이터없음"
    lines = []
    for item in findings:
        cid = item.get("check_id", "")
        status = item.get("status", "")
        sev = item.get("severity", "")
        ext = item.get("status_extended", "")
        lines.append(f"- prowler.{cid}.status={status} severity={sev} detail={ext}")
    fail = [i for i in findings if i.get("status") in ("FAIL", "WARN")]
    lines.append(f"- prowler.fail_count={len(fail)}")
    lines.append(f"- prowler.total_checks={len(findings)}")
    return "\n".join(lines)


def build_zap_facts(data: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"- zap.total_alerts={data.get('total_alerts', 0)}")
    rc = data.get("risk_counts", {})
    for level in ("High", "Medium", "Low", "Informational"):
        lines.append(f"- zap.risk.{level}={rc.get(level, 0)}")
    for alert in (data.get("alerts") or [])[:10]:
        name = alert.get("name") or alert.get("alert", "unknown")
        risk = alert.get("risk") or alert.get("risk_level", "")
        url  = alert.get("url", "")
        lines.append(f"- zap.alert.name={name} risk={risk} url={url}")
    return "\n".join(lines)


def build_fpfn_facts(data: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"- fpfn.overall_verdict={data.get('overall_verdict', '')}")
    lines.append(f"- fpfn.summary={data.get('summary', '')}")
    fn = data.get("false_negative", {})
    lines.append(f"- fpfn.fn_count={fn.get('fn_count', 0)}")
    lines.append(f"- fpfn.fn_rate={fn.get('fn_rate', 0)}")
    lines.append(f"- fpfn.fn_total_patterns={fn.get('total_attack_patterns', 0)}")
    lines.append(f"- fpfn.improvable_by_block={fn.get('improvable_by_block_mode', 0)}")
    lines.append(f"- fpfn.current_detection_rate={fn.get('current_detection_rate', '')}")
    lines.append(f"- fpfn.block_mode_detection_rate={fn.get('block_mode_detection_rate', '')}")
    for item in (fn.get("fn_items") or []):
        cat = item.get("category", "")
        name = item.get("name", "")
        action = item.get("waf_action", "")
        rule = item.get("matched_rule", "없음")
        lines.append(f"- fpfn.fn_item.{cat}.{name}=waf_action:{action} rule:{rule}")
    fp_log = data.get("false_positive_log", {})
    lines.append(f"- fpfn.fp_suspicion_count={fp_log.get('fp_suspicion_count', 0)}")
    for ip_item in (fp_log.get("potential_fp_ips") or []):
        ip = ip_item.get("ip", "?")
        lines.append(f"- fpfn.fp_ip.{ip}.blocked={ip_item.get('blocked', 0)} risk_score={ip_item.get('risk_score', 0)}")
    fp_test = data.get("false_positive_test", {})
    lines.append(f"- fpfn.fp_test.tested={fp_test.get('tested', 0)}")
    lines.append(f"- fpfn.fp_test.fp_count={fp_test.get('fp_count', 0)}")
    lines.append(f"- fpfn.fp_test.fp_rate={fp_test.get('fp_rate', 0)}")
    for rec in (data.get("recommendations") or []):
        lines.append(f"- fpfn.rec.type={rec.get('type','')} action={rec.get('action','')} priority={rec.get('priority','')}")
    return "\n".join(lines)


# ── 숫자·IP 추출 ──────────────────────────────────────────────────────

def extract_ips_from_text(text: str) -> Set[str]:
    return set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text))


def extract_numbers_from_json(data: Any) -> Set[str]:
    numbers: Set[str] = set()
    def walk(v):
        if isinstance(v, dict):
            for x in v.values(): walk(x)
        elif isinstance(v, list):
            for x in v: walk(x)
        elif isinstance(v, bool) or v is None:
            return
        elif isinstance(v, int):
            numbers.add(str(v))
        elif isinstance(v, float):
            numbers.add(str(v))
            if v.is_integer():
                numbers.add(str(int(v)))
        elif isinstance(v, str):
            numbers.update(re.findall(r"(?<![\d.])-?\d+(?:\.\d+)?(?![\d.])", v))
    walk(data)
    return numbers


def extract_numbers_from_report(report: str) -> Set[str]:
    nums = set(re.findall(r"(?<![\d.])-?\d+(?:\.\d+)?(?![\d.])", report))
    nums -= {"1", "2", "3", "4", "5", "6", "7", "8"}
    return nums


def build_allowed_numbers(*datasets) -> str:
    all_numbers: Set[str] = set()
    for data in datasets:
        if data:
            all_numbers |= extract_numbers_from_json(data)
    pct_numbers: Set[str] = set()
    for n in list(all_numbers):
        try:
            v = float(n)
            if 0 <= v <= 1:
                pct = round(v * 100, 1)
                pct_numbers.add(str(pct))
                pct_numbers.add(str(int(pct)))
                comp = round(100 - pct, 1)
                pct_numbers.add(str(comp))
                pct_numbers.add(str(int(comp)))
        except ValueError:
            pass
    allowed = sorted(
        all_numbers | pct_numbers | {"0", "100", "1", "2", "3", "4", "5", "6", "7", "8"},
        key=lambda x: float(x) if x.replace(".", "").lstrip("-").isdigit() else 0,
    )
    return ", ".join(allowed) if allowed else "없음"


# ── LangChain 호출 ────────────────────────────────────────────────────

def call_ollama_with_langchain(
    waf_facts: str,
    fpfn_facts: str,
    prowler_facts: str,
    zap_facts: str,
    allowed_numbers: str,
    model: str,
    ollama_base_url: str,
) -> str:
    llm = ChatOllama(
        model=model,
        base_url=ollama_base_url,
        temperature=0,
        timeout=900,
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT_TEMPLATE),
    ])
    chain = prompt | llm | StrOutputParser()
    try:
        return chain.invoke({
            "waf_facts": waf_facts,
            "fpfn_facts": fpfn_facts,
            "prowler_facts": prowler_facts,
            "zap_facts": zap_facts,
            "allowed_numbers": allowed_numbers,
        }).strip()
    except Exception as e:
        error_text = str(e).lower()
        if any(x in error_text for x in ("connection refused", "failed to connect", "connecterror",
                                          "all connection attempts failed", "winerror 10061")):
            print("Ollama 서버가 실행 중이 아닙니다.")
            sys.exit(1)
        if "not found" in error_text or ("model" in error_text and "not" in error_text):
            print(f"Ollama 모델을 찾을 수 없습니다: {model}")
            sys.exit(1)
        print(f"LangChain 호출 오류: {e}")
        sys.exit(1)


# ── 검증 ─────────────────────────────────────────────────────────────

def clean_markdown(text: str) -> str:
    text = text.strip()
    for prefix in ("```markdown", "```"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    if text.endswith("```"):
        text = text[:-3].strip()
    return text


def validate_report(report: str, all_data: List[Any]) -> None:
    missing = [s for s in REQUIRED_SECTIONS if s not in report]
    if missing:
        raise ValueError(f"필수 섹션 누락: {', '.join(missing)}")
    all_json_ips: Set[str] = set()
    all_json_nums: Set[str] = set()
    for d in all_data:
        if d:
            txt = json.dumps(d, ensure_ascii=False)
            all_json_ips |= extract_ips_from_text(txt)
            all_json_nums |= extract_numbers_from_json(d)
    extra_ips = extract_ips_from_text(report) - all_json_ips
    if extra_ips:
        raise ValueError(f"원본에 없는 IP: {', '.join(sorted(extra_ips))}")


def save_report(report: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = now_kst("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{ts}.md"
    path.write_text(report, encoding="utf-8")
    return path


# ── 메인 생성 함수 ────────────────────────────────────────────────────

def generate_report(
    input_path: Path,
    output_dir: Path,
    model: str,
    ollama_base_url: str,
) -> Path:
    waf_data = load_json(input_path)

    # 보조 데이터 로드 (없으면 None)
    fpfn_path    = _find_latest_file("fp_fn_*.json")
    zap_path     = _find_latest_file("zap_report_*.json")
    prowler_path = _ROOT / "compliance" / "input" / "prowler_report.json"

    fpfn_data    = load_json(fpfn_path)    if fpfn_path    else None
    zap_data     = load_json(zap_path)     if zap_path     else None
    prowler_raw  = load_json(prowler_path) if prowler_path.exists() else None
    prowler_list = prowler_raw if isinstance(prowler_raw, list) else []

    print(f"  [데이터 로드] WAF=OK  FP/FN={'OK' if fpfn_data else '없음'}  "
          f"ZAP={'OK' if zap_data else '없음'}  Prowler={'OK' if prowler_list else '없음'}")

    waf_facts     = build_waf_facts(waf_data)
    fpfn_facts    = build_fpfn_facts(fpfn_data) if fpfn_data else "- fpfn=데이터없음"
    prowler_facts = build_prowler_facts(prowler_list)
    zap_facts     = build_zap_facts(zap_data) if zap_data else "- zap=데이터없음"
    allowed_numbers = build_allowed_numbers(waf_data, fpfn_data, zap_data,
                                            {"prowler": prowler_list} if prowler_list else None)

    validation_error: Optional[ValueError] = None
    report = ""
    for attempt in range(MAX_GENERATION_ATTEMPTS):
        print(f"  [생성 {attempt + 1}/{MAX_GENERATION_ATTEMPTS}] 모델 호출 중...")
        report = call_ollama_with_langchain(
            waf_facts=waf_facts,
            fpfn_facts=fpfn_facts,
            prowler_facts=prowler_facts,
            zap_facts=zap_facts,
            allowed_numbers=allowed_numbers,
            model=model,
            ollama_base_url=ollama_base_url,
        )
        report = clean_markdown(report)
        try:
            validate_report(report, [waf_data, fpfn_data, zap_data, {"prowler": prowler_list}])
            validation_error = None
            print("  [검증 통과]")
            break
        except ValueError as error:
            validation_error = error
            print(f"  [검증 실패 {attempt + 1}/{MAX_GENERATION_ATTEMPTS}] {error}")

    if validation_error is not None:
        header = ("> **[자동 검증 경고]** 이 보고서는 데이터 검증을 통과하지 못했습니다."
                  " 수치 정확성을 반드시 수동으로 확인하세요.\n\n")
        report = header + report
        print(f"  [경고] 검증 실패 — 최선 결과로 저장: {validation_error}")

    return save_report(report, output_dir)


# ── CLI ───────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="WAF·Prowler·ZAP·FP/FN 통합 분석 → LangChain + Ollama 보안 보고서"
    )
    parser.add_argument("--input", required=True, help="WAF analysis JSON 경로")
    parser.add_argument("--output-dir", default="output")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--ollama-base-url", default=DEFAULT_OLLAMA_BASE_URL)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        path = generate_report(
            input_path=Path(args.input),
            output_dir=Path(args.output_dir),
            model=args.model,
            ollama_base_url=args.ollama_base_url,
        )
        print(f"보고서 저장: {path}")
    except FileNotFoundError as e:
        print(e); sys.exit(1)
    except json.JSONDecodeError:
        print("입력 파일이 올바른 JSON 형식이 아닙니다."); sys.exit(1)


if __name__ == "__main__":
    main()
