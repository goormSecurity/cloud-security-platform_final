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
    "종합 정책 개선 제안",
    "운영자 검토 사항",
]


# ── 데이터 로더 ──────────────────────────────────────────────────────

def _find_latest(pattern: str, *dirs) -> Optional[Path]:
    search_dirs = list(dirs) if dirs else [
        _ROOT / "output",
        _ROOT / "compliance" / "input",
    ]
    files = []
    for d in search_dirs:
        if d.exists():
            files.extend(d.rglob(pattern))
    return sorted(files)[-1] if files else None


def _load(path) -> Optional[Dict]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


# ── FACTS 블록 빌더 ───────────────────────────────────────────────────

def build_waf_facts(data: Dict) -> str:
    lines = []
    s = data.get("summary", {})
    lines += [
        f"- total_requests={s.get('total_requests', 0)}",
        f"- unique_ips={s.get('unique_ips', 0)}",
        f"- high_risk_ips={s.get('high_risk_ips', 0)}",
        f"- block_rate={s.get('block_rate', 0)}",
        f"- generated_at={data.get('generated_at', '')}",
    ]
    for k, v in (s.get("action_counts") or {}).items():
        lines.append(f"- action_counts.{k}={v}")
    for k, v in (s.get("attack_type_counts") or {}).items():
        lines.append(f"- attack_type_counts.{k}={v}")
    for k, v in (data.get("rule_hits") or {}).items():
        lines.append(f"- rule_hits.{k}={v}")
    for e in (data.get("top_ips") or [])[:10]:
        ip = e.get("ip", "?")
        lines += [
            f"- top_ip.{ip}.request_count={e.get('request_count', 0)}",
            f"- top_ip.{ip}.risk_level={e.get('risk_level', 'UNKNOWN')}",
            f"- top_ip.{ip}.risk_score={e.get('risk_score', 0)}",
            f"- top_ip.{ip}.country={e.get('country', '?')}",
            f"- top_ip.{ip}.attack_types={e.get('attack_types', [])}",
            f"- top_ip.{ip}.block_rate={e.get('block_rate', 0)}",
        ]
        for a, c in (e.get("action_counts") or {}).items():
            lines.append(f"- top_ip.{ip}.action.{a}={c}")
    return "\n".join(lines)


def build_fpfn_facts(data: Dict) -> str:
    if not data:
        return "- fpfn=데이터없음"
    lines = [
        f"- fpfn.overall_verdict={data.get('overall_verdict', '')}",
        f"- fpfn.summary={data.get('summary', '')}",
    ]
    fn = data.get("false_negative", {})
    lines += [
        f"- fpfn.fn_count={fn.get('fn_count', 0)}",
        f"- fpfn.fn_rate={fn.get('fn_rate', 0)}",
        f"- fpfn.total_patterns={fn.get('total_attack_patterns', 0)}",
        f"- fpfn.improvable_by_block={fn.get('improvable_by_block_mode', 0)}",
        f"- fpfn.current_detection_rate={fn.get('current_detection_rate', '')}",
        f"- fpfn.block_mode_detection_rate={fn.get('block_mode_detection_rate', '')}",
    ]
    for item in (fn.get("fn_items") or []):
        cat, name = item.get("category", ""), item.get("name", "")
        lines.append(f"- fpfn.fn.{cat}.{name}=action:{item.get('waf_action','')} rule:{item.get('matched_rule','없음')}")
    fp_log = data.get("false_positive_log", {})
    lines.append(f"- fpfn.fp_suspicion_count={fp_log.get('fp_suspicion_count', 0)}")
    for ip_item in (fp_log.get("potential_fp_ips") or []):
        ip = ip_item.get("ip", "?")
        lines.append(f"- fpfn.fp_ip.{ip}.blocked={ip_item.get('blocked', 0)} risk_score={ip_item.get('risk_score', 0)}")
    fp_test = data.get("false_positive_test", {})
    lines += [
        f"- fpfn.fp_test.tested={fp_test.get('tested', 0)}",
        f"- fpfn.fp_test.fp_count={fp_test.get('fp_count', 0)}",
        f"- fpfn.fp_test.fp_rate={fp_test.get('fp_rate', 0)}",
    ]
    for r in (data.get("recommendations") or []):
        lines.append(f"- fpfn.rec={r.get('action','')} priority={r.get('priority','')}")
    return "\n".join(lines)


def build_abtest_facts(data: Dict) -> str:
    if not data:
        return "- abtest=데이터없음"
    cur  = data.get("current_mode", {})
    prop = data.get("proposed_block_mode", {})
    lines = [
        f"- abtest.total_patterns={data.get('total_attack_patterns', 0)}",
        f"- abtest.current.block_rate={cur.get('block_rate', '0%')}",
        f"- abtest.current.detection_rate={cur.get('detection_rate', '0%')}",
        f"- abtest.proposed.block_rate={prop.get('block_rate', '0%')}",
        f"- abtest.proposed.detection_rate={prop.get('detection_rate', '0%')}",
    ]
    for k, v in (cur.get("actions") or {}).items():
        lines.append(f"- abtest.current.action.{k}={v}")
    for k, v in (prop.get("actions") or {}).items():
        lines.append(f"- abtest.proposed.action.{k}={v}")
    return "\n".join(lines)


def build_prowler_facts(findings: List[Dict]) -> str:
    if not findings:
        return "- prowler=데이터없음"
    lines = [
        f"- prowler.total_checks={len(findings)}",
        f"- prowler.fail_count={sum(1 for f in findings if f.get('status') in ('FAIL','WARN'))}",
        f"- prowler.pass_count={sum(1 for f in findings if f.get('status') == 'PASS')}",
    ]
    for item in findings:
        cid = item.get("check_id", "")
        lines.append(f"- prowler.{cid}=status:{item.get('status','')} severity:{item.get('severity','')} detail:{item.get('status_extended','')}")
    return "\n".join(lines)


def build_infra_facts(config_diff: Dict, s3_sec: Dict, enc: Dict, kms: Dict, objlock: Dict) -> str:
    lines = []
    # Config drift
    if config_diff:
        lines += [
            f"- config.recorder_status={config_diff.get('recorder_status', '')}",
            f"- config.drift_detected={config_diff.get('drift_detected', False)}",
            f"- config.resource_changes={len(config_diff.get('resource_changes', []))}",
            f"- config.status={config_diff.get('status', '')}",
        ]
    else:
        lines.append("- config=데이터없음")
    # S3 bucket security
    if s3_sec:
        lines += [
            f"- s3_security.overall={s3_sec.get('overall', '')}",
            f"- s3_security.total_buckets={s3_sec.get('total_buckets', 0)}",
            f"- s3_security.pass={s3_sec.get('pass', 0)}",
            f"- s3_security.warn={s3_sec.get('warn', 0)}",
            f"- s3_security.fail={s3_sec.get('fail', 0)}",
        ]
        for issue in (s3_sec.get("top_issues") or []):
            lines.append(f"- s3_security.issue={issue}")
        for b in (s3_sec.get("buckets") or []):
            bname = b.get("bucket", "?")
            lines.append(f"- s3_security.bucket.{bname}=verdict:{b.get('verdict','')} encryption:{b.get('encryption','')} versioning:{b.get('versioning','')}")
    else:
        lines.append("- s3_security=데이터없음")
    # Encryption
    if enc:
        lines.append(f"- s3_encryption.algorithm={enc.get('SSEAlgorithm', '')} status={enc.get('status', '')}")
    # KMS
    if kms:
        lines.append(f"- kms.key_state={kms.get('KeyState', '')} status={kms.get('status', '')}")
    # Object Lock
    if objlock:
        lines += [
            f"- object_lock.enabled={objlock.get('ObjectLockEnabled', '')}",
            f"- object_lock.mode={objlock.get('Mode', '')}",
            f"- object_lock.status={objlock.get('status', '')}",
        ]
    return "\n".join(lines) if lines else "- infra=데이터없음"


def build_zap_facts(data: Dict) -> str:
    if not data:
        return "- zap=데이터없음"
    rc = data.get("risk_counts", {})
    lines = [
        f"- zap.total_alerts={data.get('total_alerts', 0)}",
        f"- zap.high={rc.get('High', 0)}",
        f"- zap.medium={rc.get('Medium', 0)}",
        f"- zap.low={rc.get('Low', 0)}",
    ]
    for a in (data.get("alerts") or [])[:10]:
        name = a.get("name") or a.get("alert", "?")
        risk = a.get("risk", "")
        url  = (a.get("url") or "")[:80]
        lines.append(f"- zap.alert={name} risk={risk} url={url}")
    return "\n".join(lines)


def build_trivy_facts(data: Dict) -> str:
    if not data:
        return "- trivy=데이터없음"
    s = data.get("summary", {})
    lines = [
        f"- trivy.total_vulns={s.get('total_vulns', 0)}",
        f"- trivy.critical={s.get('critical', 0)}",
        f"- trivy.high={s.get('high', 0)}",
        f"- trivy.medium={s.get('medium', 0)}",
    ]
    for r in (data.get("images", {}).get("results") or []):
        img = r.get("image", "?")
        by_sev = r.get("by_severity", {})
        lines.append(f"- trivy.image.{img}=CRITICAL:{by_sev.get('CRITICAL',0)} HIGH:{by_sev.get('HIGH',0)}")
        for v in (r.get("top_vulns") or [])[:3]:
            cve_id  = v.get("id") or v.get("vulnerability_id", "")
            pkg_nm  = v.get("pkg") or v.get("pkg_name", "")
            fix_ver = v.get("fixed") or v.get("fixed_version", "")
            title   = v.get("title", "")
            lines.append(
                f"- trivy.cve={cve_id} severity={v.get('severity','')} "
                f"pkg={pkg_nm} installed={v.get('installed','')} fixed={fix_ver} title={title[:60]}"
            )
    iac = data.get("iac", {})
    lines.append(f"- trivy.iac_misconfigs={iac.get('total', 0)}")
    for k, v in (iac.get("by_severity") or {}).items():
        lines.append(f"- trivy.iac.{k}={v}")
    return "\n".join(lines)


def build_cloudtrail_facts(data) -> str:
    if not data:
        return "- cloudtrail=데이터없음"
    events = data if isinstance(data, list) else data.get("Events", data.get("events", []))
    if not events:
        return "- cloudtrail.events=0"
    lines = [f"- cloudtrail.total_events={len(events)}"]
    for e in events[:15]:
        name = e.get("eventName") or e.get("EventName", "")
        source = e.get("eventSource") or e.get("EventSource", "")
        time = e.get("eventTime") or e.get("EventTime", "")
        lines.append(f"- cloudtrail.event={name} source={source} time={time}")
    return "\n".join(lines)


# ── IP 추출 ───────────────────────────────────────────────────────────

def _extract_ips(text: str) -> Set[str]:
    return set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text))


# ── 핵심 지표 요약 (허용 숫자 목록 대체) ─────────────────────────────

def build_key_metrics(
    waf: Dict, fpfn: Optional[Dict], abtest: Optional[Dict],
    zap: Optional[Dict], trivy: Optional[Dict],
    prowler: List[Dict], cloudtrail_raw,
) -> str:
    """LLM에게 전달할 핵심 수치 요약 — 계정ID·CVE번호·ARN 오염 없이 통계만 전달"""
    lines = ["[핵심 보안 지표 — 보고서에서 반드시 이 숫자를 그대로 인용할 것]"]

    # WAF
    s = (waf or {}).get("summary", {})
    ac = s.get("action_counts", {})
    block = ac.get("BLOCK", 0)
    count = ac.get("COUNT", 0)
    allow = ac.get("ALLOW", 0)
    total = s.get("total_requests", 0)
    rate  = s.get("block_rate", 0)
    high  = s.get("high_risk_ips", 0)
    lines.append(f"WAF 총 요청: {total:,}건")
    lines.append(f"WAF 액션 — BLOCK: {block:,}건 / COUNT: {count:,}건 / ALLOW: {allow:,}건")
    lines.append(f"WAF 차단율: {rate * 100:.1f}%")
    lines.append(f"고위험 IP 수: {high}개")

    # FP/FN
    if fpfn:
        fn = fpfn.get("false_negative", {})
        lines.append(
            f"FP/FN — 미탐(FN): {fn.get('fn_count', 0)}건 "
            f"/ 미탐률: {fn.get('fn_rate', 0):.0%} "
            f"/ 총 패턴: {fn.get('total_attack_patterns', 0)}개 "
            f"/ Block 전환 즉시 차단 가능: {fn.get('improvable_by_block_mode', 0)}개"
        )
    else:
        lines.append("FP/FN: 데이터 없음")

    # A/B test
    if abtest:
        cur  = abtest.get("current_mode", {})
        prop = abtest.get("proposed_block_mode", {})
        lines.append(
            f"A/B 테스트 — 현재 차단율: {cur.get('block_rate','N/A')} "
            f"/ Block 전환 시: {prop.get('block_rate','N/A')}"
        )

    # ZAP
    if zap:
        rc = zap.get("risk_counts", {})
        lines.append(
            f"ZAP 웹 취약점: 전체 {zap.get('total_alerts', 0)}건 "
            f"(High {rc.get('High', 0)} / Medium {rc.get('Medium', 0)} / Low {rc.get('Low', 0)})"
        )
    else:
        lines.append("ZAP: 데이터 없음")

    # Trivy
    if trivy:
        ts  = trivy.get("summary", {})
        iac = trivy.get("iac", {})
        lines.append(
            f"Trivy 컨테이너 취약점: 전체 {ts.get('total_vulns', 0):,}건 "
            f"(CRITICAL {ts.get('critical', 0)} / HIGH {ts.get('high', 0)})"
        )
        lines.append(
            f"Trivy IaC 오설정: {iac.get('total', 0)}건 "
            f"(CRITICAL {iac.get('by_severity', {}).get('CRITICAL', 0)} "
            f"/ HIGH {iac.get('by_severity', {}).get('HIGH', 0)})"
        )
    else:
        lines.append("Trivy: 데이터 없음")

    # Prowler
    if prowler:
        fail = sum(1 for f in prowler if f.get("status") in ("FAIL", "WARN"))
        lines.append(f"Prowler: 전체 {len(prowler)}건, FAIL/WARN {fail}건")
    else:
        lines.append("Prowler: 데이터 없음")

    # CloudTrail
    events = cloudtrail_raw if isinstance(cloudtrail_raw, list) \
             else (cloudtrail_raw or {}).get("Events", (cloudtrail_raw or {}).get("events", []))
    lines.append(f"CloudTrail 이벤트: {len(events)}건")

    return "\n".join(lines)


# ── LangChain 호출 ────────────────────────────────────────────────────

def call_llm(facts: Dict[str, str], model: str, base_url: str) -> str:
    llm = ChatOllama(model=model, base_url=base_url, temperature=0, timeout=900)
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT_TEMPLATE),
    ])
    chain = prompt | llm | StrOutputParser()
    try:
        return chain.invoke(facts).strip()
    except Exception as e:
        err = str(e).lower()
        if any(x in err for x in ("connection refused", "failed to connect", "connecterror",
                                   "all connection attempts failed", "winerror 10061")):
            print("Ollama 서버가 실행 중이 아닙니다."); sys.exit(1)
        if "not found" in err or ("model" in err and "not" in err):
            print(f"모델 없음: {model}"); sys.exit(1)
        print(f"LangChain 오류: {e}"); sys.exit(1)


# ── 검증 ─────────────────────────────────────────────────────────────

def clean_markdown(text: str) -> str:
    text = text.strip()
    for prefix in ("```markdown", "```"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    if text.endswith("```"):
        text = text[:-3].strip()
    return text


def validate_report(report: str, all_data: List) -> None:
    missing = [s for s in REQUIRED_SECTIONS if s not in report]
    if missing:
        raise ValueError(f"필수 섹션 누락: {', '.join(missing)}")
    all_ips: Set[str] = set()
    for d in all_data:
        if d:
            all_ips |= _extract_ips(json.dumps(d, ensure_ascii=False))
    extra = _extract_ips(report) - all_ips
    if extra:
        raise ValueError(f"원본에 없는 IP: {', '.join(sorted(extra))}")


def save_report(report: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"report_{now_kst('%Y%m%d_%H%M%S')}.md"
    path.write_text(report, encoding="utf-8")
    return path


# ── 메인 생성 함수 ────────────────────────────────────────────────────

def generate_report(input_path: Path, output_dir: Path, model: str, ollama_base_url: str) -> Path:
    waf_data = json.loads(input_path.read_text(encoding="utf-8"))

    # 모든 보안 데이터 소스 로드
    fpfn_data      = _load(_find_latest("fp_fn_*.json"))
    abtest_data    = _load(_find_latest("ab_test_*.json"))
    zap_data       = _load(_find_latest("zap_report_*.json"))
    trivy_data     = _load(_ROOT / "compliance" / "input" / "trivy_report.json")
    prowler_raw    = _load(_ROOT / "compliance" / "input" / "prowler_report.json")
    config_diff    = _load(_ROOT / "compliance" / "input" / "config_diff.json")
    s3_sec         = _load(_ROOT / "compliance" / "input" / "s3_security.json")
    enc_data       = _load(_ROOT / "compliance" / "input" / "bucket_encryption.json")
    kms_data       = _load(_ROOT / "compliance" / "input" / "kms_key.json")
    objlock_data   = _load(_ROOT / "compliance" / "input" / "object_lock_config.json")
    cloudtrail_raw = _load(_ROOT / "compliance" / "input" / "cloudtrail_events.json")
    prowler_list   = prowler_raw if isinstance(prowler_raw, list) else []

    loaded = {
        "WAF": "OK", "FP/FN": "OK" if fpfn_data else "없음",
        "A/B Test": "OK" if abtest_data else "없음",
        "ZAP": "OK" if zap_data else "없음",
        "Trivy": "OK" if trivy_data else "없음",
        "Prowler": "OK" if prowler_list else "없음",
        "Config": "OK" if config_diff else "없음",
        "S3 Security": "OK" if s3_sec else "없음",
        "CloudTrail": "OK" if cloudtrail_raw else "없음",
    }
    print(f"  [데이터 로드] {' | '.join(f'{k}={v}' for k,v in loaded.items())}")

    # FACTS 블록 구성
    facts = {
        "waf_facts":        build_waf_facts(waf_data),
        "fpfn_facts":       build_fpfn_facts(fpfn_data),
        "abtest_facts":     build_abtest_facts(abtest_data),
        "prowler_facts":    build_prowler_facts(prowler_list),
        "infra_facts":      build_infra_facts(config_diff, s3_sec, enc_data, kms_data, objlock_data),
        "zap_facts":        build_zap_facts(zap_data),
        "trivy_facts":      build_trivy_facts(trivy_data),
        "cloudtrail_facts": build_cloudtrail_facts(cloudtrail_raw),
        "key_metrics":      build_key_metrics(
            waf_data, fpfn_data, abtest_data, zap_data, trivy_data,
            prowler_list, cloudtrail_raw,
        ),
    }

    all_data = [waf_data, fpfn_data, abtest_data, zap_data, trivy_data,
                prowler_raw, config_diff, s3_sec, cloudtrail_raw]

    validation_error: Optional[ValueError] = None
    report = ""
    for attempt in range(MAX_GENERATION_ATTEMPTS):
        print(f"  [생성 {attempt+1}/{MAX_GENERATION_ATTEMPTS}] 모델 호출 중...")
        report = clean_markdown(call_llm(facts, model, ollama_base_url))
        try:
            validate_report(report, all_data)
            validation_error = None
            print("  [검증 통과]")
            break
        except ValueError as e:
            validation_error = e
            print(f"  [검증 실패 {attempt+1}/{MAX_GENERATION_ATTEMPTS}] {e}")

    if validation_error:
        header = ("> **[자동 검증 경고]** 이 보고서는 데이터 검증을 통과하지 못했습니다."
                  " 수치 정확성을 반드시 수동으로 확인하세요.\n\n")
        report = header + report
        print(f"  [경고] 최선 결과로 저장: {validation_error}")

    return save_report(report, output_dir)


# ── CLI ───────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="종합 보안 분석 → LangChain + Ollama 보고서")
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
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(e); sys.exit(1)


if __name__ == "__main__":
    main()
