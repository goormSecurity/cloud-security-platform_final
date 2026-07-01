#!/usr/bin/env python3
"""
analyze_fp_fn.py — WAF 오탐(False Positive) / 미탐(False Negative) 분석

오탐(FP): 정상 요청인데 WAF가 차단한 경우
미탐(FN): 공격 요청인데 WAF가 통과시킨 경우

데이터 소스:
  - output/ab_test_*.json   : A/B 테스트 결과 (미탐 근거)
  - output/analysis_*.json  : 실 WAF 로그 분석 (오탐 근거)
  - output/waf_latest/      : 원시 WAF 로그 (상세 분석)
  - (선택) --target URL 지정 시 정상 요청 직접 전송하여 FP 테스트

출력:
  output/fp_fn_<timestamp>.json
"""
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "output"


def _load_latest(pattern: str):
    files = sorted(OUTPUT_DIR.glob(pattern))
    if not files:
        files = sorted((OUTPUT_DIR / "s3-results").rglob(pattern))
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None


# ── 미탐(FN) 분석: A/B 테스트에서 통과된 공격 ─────────────────────
def analyze_false_negatives(ab_data: dict) -> dict:
    fn_list = []

    cur = ab_data.get("current_mode", {})
    cur_detail = cur.get("detail", [])

    # 현재 모드에서 attack이 count/allow로 처리된 것 = 미탐
    for entry in cur_detail:
        action = entry.get("action", "")
        if action in ("count", "allow"):
            fn_list.append({
                "category":     entry.get("category", "unknown"),
                "name":         entry.get("name", ""),
                "uri":          entry.get("uri", ""),
                "waf_action":   action.upper(),
                "matched_rule": entry.get("matched_rule"),
                "fn_reason":    (
                    "COUNT 모드: 탐지됐으나 차단하지 않음"
                    if action == "count"
                    else "WAF 룰 미매칭: 완전 통과"
                ),
            })

    total_attacks = ab_data.get("total_attack_patterns", len(cur_detail))
    cur_actions   = cur.get("actions", {})
    fn_count      = cur_actions.get("count", 0) + cur_actions.get("allow", 0)

    # Block 모드 가정 시 잡힐 수 있는 것
    prop = ab_data.get("proposed_block_mode", {})
    prop_actions = prop.get("actions", {})
    improvable = prop_actions.get("block", 0) - cur_actions.get("block", 0)

    return {
        "total_attack_patterns": total_attacks,
        "fn_count":              fn_count,
        "fn_rate":               round(fn_count / total_attacks, 3) if total_attacks else 0,
        "fn_items":              fn_list,
        "improvable_by_block_mode": max(improvable, 0),
        "current_detection_rate":  cur.get("detection_rate", "N/A"),
        "block_mode_detection_rate": prop.get("detection_rate", "N/A"),
    }


# ── 오탐(FP) 분석: 정상 요청이 차단되는지 테스트 ──────────────────
NORMAL_REQUESTS = [
    # (이름, 경로+쿼리, 예상 응답: 차단되면 안 됨)
    ("일반 홈 접속",         "/",                                          {}),
    ("검색어 일반",          "/?q=hello+world",                            {}),
    ("한글 파라미터",        "/?name=안녕하세요",                           {}),
    ("숫자 ID",             "/?id=42",                                    {}),
    ("이메일 형식",          "/?email=test@example.com",                   {}),
    ("긴 문자열",           "/?desc=" + "a" * 200,                        {}),
    ("특수문자 일반",        "/?q=hello%20world%21",                       {}),
    ("User-Agent 일반",     "/",   {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}),
    ("Content-Type JSON",   "/api/health",                                {"Content-Type": "application/json"}),
    ("로그인 폼 정상",       "/?username=admin&password=P%40ssw0rd123",    {}),
]


def test_false_positives(target: str, timeout: int = 5) -> dict:
    fp_list   = []
    ok_list   = []
    skip_list = []

    for name, path, extra_headers in NORMAL_REQUESTS:
        url = target.rstrip("/") + path
        headers = {
            "User-Agent": "NormalBrowser/1.0 (FP-Test)",
            "X-FP-Test": "true",
            **extra_headers,
        }
        req = Request(url, headers=headers, method="GET")
        try:
            with urlopen(req, timeout=timeout) as resp:
                status = resp.status
                if status == 403:
                    fp_list.append({
                        "name":       name,
                        "url":        url,
                        "status":     status,
                        "fp_reason":  "HTTP 403 — WAF가 정상 요청 차단 (오탐 의심)",
                    })
                else:
                    ok_list.append({"name": name, "url": url, "status": status})
        except HTTPError as e:
            if e.code == 403:
                fp_list.append({
                    "name":      name,
                    "url":       url,
                    "status":    403,
                    "fp_reason": "HTTP 403 — WAF 차단 응답",
                })
            else:
                ok_list.append({"name": name, "url": url, "status": e.code})
        except (URLError, Exception) as e:
            skip_list.append({"name": name, "url": url, "reason": str(e)[:100]})
        time.sleep(0.3)

    tested = len(fp_list) + len(ok_list)
    return {
        "target":       target,
        "tested":       tested,
        "fp_count":     len(fp_list),
        "fp_rate":      round(len(fp_list) / tested, 3) if tested else 0,
        "fp_items":     fp_list,
        "ok_items":     ok_list,
        "skipped":      skip_list,
        "note":         (
            "FP 테스트는 ALB를 통해 실제 WAF를 거치는 경우에만 유효합니다."
            " 로컬 타겟이면 WAF를 우회하므로 모두 200 OK가 나올 수 있습니다."
        ),
    }


# ── WAF 로그에서 오탐 패턴 탐지 ────────────────────────────────────
def analyze_fp_from_waf_logs(analysis_data: dict) -> dict:
    """
    WAF 로그 분석 결과에서 오탐 가능성이 있는 IP/요청 패턴 추출.

    오탐 가능성 지표:
    - 차단(BLOCK)된 IP 중 risk_score가 낮은 경우 (< 30)
    - 공격 유형 없이 차단된 경우
    """
    potential_fp = []
    summary = analysis_data.get("summary", {})

    for ip in analysis_data.get("top_ips", []):
        block_rate = ip.get("block_rate", 0)
        risk_score = ip.get("risk_score", 0)
        attack_types = ip.get("attack_types", [])
        blocked = ip.get("action_counts", {}).get("BLOCK", 0)

        # 차단됐지만 공격 유형이 없고 위험 점수가 낮으면 오탐 의심
        if blocked > 0 and not attack_types and risk_score < 30:
            potential_fp.append({
                "ip":          ip.get("ip"),
                "country":     ip.get("country"),
                "blocked":     blocked,
                "risk_score":  risk_score,
                "attack_types": attack_types,
                "suspicion":   "공격 유형 없이 차단 — 오탐 가능성",
            })

    return {
        "potential_fp_ips":  potential_fp,
        "fp_suspicion_count": len(potential_fp),
        "note": "WAF 로그 기반 추정. 실제 확인은 해당 IP의 원시 요청 내용 검토 필요.",
    }


# ── 메인 ─────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="WAF 오탐/미탐 분석")
    p.add_argument("--target",   default=None, help="FP 테스트 대상 URL (선택)")
    p.add_argument("--ab-test",  default=None, help="ab_test JSON 경로 (생략 시 최신)")
    p.add_argument("--analysis", default=None, help="analysis JSON 경로 (생략 시 최신)")
    p.add_argument("--out",      default=None, help="출력 경로 (생략 시 output/fp_fn_*.json)")
    args = p.parse_args()

    now = datetime.now(timezone.utc)
    ts  = now.strftime("%Y%m%d_%H%M%S")
    out_path = Path(args.out) if args.out else OUTPUT_DIR / f"fp_fn_{ts}.json"

    print(f"\n[fp_fn] 오탐/미탐 분석 시작 — {now.strftime('%Y-%m-%d %H:%M:%S')}")

    # ── A/B 테스트 데이터 로드 ────────────────────────────────────
    if args.ab_test:
        ab_data = json.loads(Path(args.ab_test).read_text(encoding="utf-8"))
    else:
        ab_data = _load_latest("ab_test_*.json")

    if ab_data:
        print(f"[fp_fn] A/B 테스트 데이터 로드 완료")
        fn_result = analyze_false_negatives(ab_data)
        print(f"[fp_fn] 미탐(FN): {fn_result['fn_count']}건 / 전체 {fn_result['total_attack_patterns']}개 패턴")
        for item in fn_result["fn_items"]:
            print(f"         ✘ [{item['waf_action']}] {item['name']} — {item['fn_reason']}")
    else:
        print("[fp_fn] A/B 테스트 데이터 없음 — 미탐 분석 스킵")
        fn_result = {"fn_count": 0, "fn_items": [], "note": "ab_test 데이터 없음"}

    # ── WAF 로그 기반 오탐 탐지 ──────────────────────────────────
    if args.analysis:
        analysis_data = json.loads(Path(args.analysis).read_text(encoding="utf-8"))
    else:
        analysis_data = _load_latest("analysis_*.json")

    if analysis_data:
        fp_log_result = analyze_fp_from_waf_logs(analysis_data)
        print(f"[fp_fn] 오탐 의심 IP: {fp_log_result['fp_suspicion_count']}개")
    else:
        fp_log_result = {"fp_suspicion_count": 0, "note": "analysis 데이터 없음"}

    # ── 실제 정상 요청 FP 테스트 (타겟 지정 시) ──────────────────
    if args.target:
        print(f"[fp_fn] 정상 요청 FP 테스트 중... ({args.target})")
        fp_test_result = test_false_positives(args.target)
        print(f"[fp_fn] 오탐(FP): {fp_test_result['fp_count']}건 / {fp_test_result['tested']}건 테스트")
        for item in fp_test_result["fp_items"]:
            print(f"         ✘ [FP] {item['name']}: {item['fp_reason']}")
    else:
        fp_test_result = {"note": "--target 미지정으로 직접 FP 테스트 생략"}

    # ── 종합 판정 ─────────────────────────────────────────────────
    fn_rate = fn_result.get("fn_rate", 0)
    fp_count = fp_test_result.get("fp_count", 0)

    if fn_rate >= 0.5:
        overall = "위험"
        summary_msg = f"미탐률 {fn_rate:.0%} — WAF 룰 Block 전환 즉시 필요"
    elif fn_rate >= 0.2 or fp_count > 2:
        overall = "주의"
        summary_msg = f"미탐 {fn_result.get('fn_count',0)}건, 오탐 의심 {fp_count}건 — 룰 튜닝 권고"
    else:
        overall = "양호"
        summary_msg = "오탐/미탐 수준이 허용 범위 내"

    result = {
        "generated_at":       now.isoformat(),
        "overall_verdict":    overall,
        "summary":            summary_msg,
        "false_negative":     fn_result,
        "false_positive_log": fp_log_result,
        "false_positive_test": fp_test_result,
        "recommendations": _build_recommendations(fn_result, fp_log_result),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\n[fp_fn] 종합 판정: {overall} — {summary_msg}")
    print(f"[fp_fn] 결과 저장: {out_path}")
    return 0


def _build_recommendations(fn: dict, fp_log: dict) -> list:
    recs = []
    fn_items = fn.get("fn_items", [])

    count_mode_fns = [i for i in fn_items if i.get("waf_action") == "COUNT"]
    allow_fns      = [i for i in fn_items if i.get("waf_action") == "ALLOW"]

    if count_mode_fns:
        categories = list({i["category"] for i in count_mode_fns})
        recs.append({
            "type":   "미탐(FN) 개선",
            "action": f"WAF 룰 Block 전환: {', '.join(categories)}",
            "detail": (
                f"{len(count_mode_fns)}개 공격 패턴이 COUNT 모드로 탐지만 되고 차단되지 않음. "
                f"AWSManagedRules의 override_action을 none으로 변경하면 즉시 차단 가능."
            ),
            "priority": "높음",
        })

    if allow_fns:
        categories = list({i["category"] for i in allow_fns})
        recs.append({
            "type":   "미탐(FN) 개선",
            "action": f"신규 WAF 룰 추가 필요: {', '.join(categories)}",
            "detail": (
                f"{len(allow_fns)}개 공격 패턴이 WAF에 탐지되지 않음. "
                f"해당 카테고리에 맞는 managed rule 추가 또는 커스텀 룰 작성 필요."
            ),
            "priority": "높음",
        })

    if fp_log.get("fp_suspicion_count", 0) > 0:
        recs.append({
            "type":   "오탐(FP) 검토",
            "action": "차단된 정상 IP 화이트리스트 검토",
            "detail": (
                f"{fp_log['fp_suspicion_count']}개 IP가 공격 유형 없이 차단됨. "
                f"해당 IP의 원시 요청 내용 검토 후 필요시 WAF IP Set에서 제외."
            ),
            "priority": "보통",
        })

    if fn.get("improvable_by_block_mode", 0) > 0:
        recs.append({
            "type":   "WAF 설정 개선",
            "action": "Block 모드 전환으로 즉시 개선 가능",
            "detail": (
                f"현재 COUNT 모드인 룰을 Block으로 전환하면 "
                f"{fn['improvable_by_block_mode']}개 추가 공격 차단 가능. "
                f"A/B 테스트 결과 기반 권고."
            ),
            "priority": "높음",
        })

    return recs


if __name__ == "__main__":
    sys.exit(main())
