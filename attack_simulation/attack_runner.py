#!/usr/bin/env python3
"""
attack_runner.py — WAF 로그 생성용 공격 시뮬레이터

자체 구축한 인가된 테스트 대상(DVWA / 팀 ALB) 전용 도구.
SQLi / XSS / Path Traversal / Command Injection / Scanner-UA 패턴을
대상 서버로 전송해서, 앞단 WAF가 BLOCK/COUNT 로그를 남기도록 유도한다.

각 요청에는 고유 마커 헤더(X-Attack-Sim)와 쿼리 마커(asid)를 박는다.
→ WAF 로그(S3)에서 이 마커로 "내가 보낸 공격"을 정확히 찾아낼 수 있다.

표준 라이브러리만 사용 (clone 후 추가 설치 없이 바로 실행).

사용 예:
    python attack_runner.py --dry-run                # 안 보내고 목록만 출력
    python attack_runner.py                          # 전체 1회씩 전송
    python attack_runner.py --category sqli xss      # 특정 유형만
    python attack_runner.py --count 3 --delay 0.5    # 각 패턴 3회, 0.5초 간격
    python attack_runner.py --target http://<주소>   # 대상 변경(CloudFront 붙으면)
"""
import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

DEFAULT_TARGET = "http://cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com"
_SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT = os.path.join(_SCRIPT_DIR, "output", "sent_attacks.jsonl")

# 공격 카탈로그.
# 각 항목: (이름, HTTP 메서드, 경로(쿼리 포함, 값은 인코딩 전), 추가 헤더)
# 값은 전송 직전에 URL 인코딩한다.
ATTACKS = {
    "sqli": [
        ("sqli-boolean", "GET", "/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit", {}),
        ("sqli-union",   "GET", "/?id=1 UNION SELECT username,password FROM users-- -", {}),
        ("sqli-stacked", "GET", "/?id=1; DROP TABLE users-- -", {}),
    ],
    "xss": [
        ("xss-script", "GET", "/?q=<script>alert(1)</script>", {}),
        ("xss-img",    "GET", '/?search="><img src=x onerror=alert(1)>', {}),
        ("xss-svg",    "GET", "/?name=<svg/onload=alert(document.cookie)>", {}),
    ],
    "path_traversal": [
        ("lfi-passwd",  "GET", "/?file=../../../../etc/passwd", {}),
        ("lfi-encoded", "GET", "/?page=....//....//....//etc/passwd", {}),
    ],
    "command_injection": [
        ("cmdi-semicolon", "GET", "/?host=127.0.0.1;cat /etc/passwd", {}),
        ("cmdi-pipe",      "GET", "/?ip=127.0.0.1|whoami", {}),
    ],
    "scanner_ua": [
        # 경로는 평범하지만 User-Agent로 자동 스캐너를 흉내낸다.
        ("ua-sqlmap", "GET", "/", {"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}),
        ("ua-nikto",  "GET", "/", {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"}),
    ],
}


def build_url(target: str, path: str) -> str:
    """경로의 쿼리 값 부분만 안전하게 인코딩해서 전체 URL을 만든다."""
    if "?" in path:
        base, query = path.split("?", 1)
    else:
        base, query = path, ""
    if not query:
        return target + base
    encoded_pairs = []
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            encoded_pairs.append(f"{k}={quote(v, safe='')}")
        else:
            encoded_pairs.append(pair)
    return f"{target}{base}?{'&'.join(encoded_pairs)}"


def send_one(target, category, name, method, path, extra_headers, timeout):
    """공격 1건 전송. 결과 dict 반환(네트워크 실패도 결과로 기록)."""
    asid = f"{name}-{uuid.uuid4().hex[:8]}"          # 이 요청만의 고유 ID
    sep = "&" if "?" in path else "?"
    url = build_url(target, f"{path}{sep}asid={asid}")
    headers = {
        "User-Agent": "attack-sim/1.0",
        "X-Attack-Sim": asid,                         # WAF 로그에서 이 헤더로 추적
        "X-Attack-Category": category,
    }
    headers.update(extra_headers)

    record = {
        "asid": asid,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "name": name,
        "method": method,
        "url": url,
    }
    req = Request(url, method=method, headers=headers)
    started = time.perf_counter()
    try:
        with urlopen(req, timeout=timeout) as resp:
            record["status"] = resp.status
            record["waf_action"] = "ALLOWED_OR_COUNTED"   # 응답이 왔다 = 차단 안 됨
    except HTTPError as e:
        record["status"] = e.code
        # WAF 차단은 보통 403으로 떨어진다(설정에 따라 다름).
        record["waf_action"] = "LIKELY_BLOCKED" if e.code == 403 else f"HTTP_{e.code}"
    except URLError as e:
        record["status"] = None
        record["waf_action"] = "NETWORK_ERROR"
        record["error"] = str(e.reason)
    record["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return record


def main():
    parser = argparse.ArgumentParser(description="WAF 로그 생성용 공격 시뮬레이터")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="대상 베이스 URL")
    parser.add_argument("--category", nargs="*", choices=list(ATTACKS), help="전송할 유형(미지정 시 전체)")
    parser.add_argument("--count", type=int, default=1, help="패턴당 전송 횟수")
    parser.add_argument("--delay", type=float, default=0.3, help="요청 간 간격(초)")
    parser.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃(초)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="전송 기록 저장 경로(JSONL)")
    parser.add_argument("--dry-run", action="store_true", help="실제 전송 없이 목록만 출력")
    args = parser.parse_args()

    categories = args.category or list(ATTACKS)
    target = args.target.rstrip("/")

    print(f"[*] 대상      : {target}")
    print(f"[*] 유형      : {', '.join(categories)}")
    print(f"[*] 패턴당 횟수: {args.count}  /  간격: {args.delay}s")
    if args.dry_run:
        print("[*] DRY-RUN (실제 전송 안 함)\n")

    results = []
    for category in categories:
        for (name, method, path, extra_headers) in ATTACKS[category]:
            for _ in range(args.count):
                if args.dry_run:
                    sep = "&" if "?" in path else "?"
                    print(f"  - [{category:17}] {method} {build_url(target, path)}")
                    continue
                rec = send_one(target, category, name, method, path, extra_headers, args.timeout)
                results.append(rec)
                flag = {"LIKELY_BLOCKED": "BLOCK", "ALLOWED_OR_COUNTED": "PASS",
                        "NETWORK_ERROR": "ERR "}.get(rec["waf_action"], rec["waf_action"])
                print(f"  [{flag}] {category:17} {rec['name']:14} "
                      f"status={rec['status']} {rec['elapsed_ms']}ms  asid={rec['asid']}")
                time.sleep(args.delay)

    if args.dry_run or not results:
        return

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "a", encoding="utf-8") as f:
        for rec in results:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    blocked = sum(1 for r in results if r["waf_action"] == "LIKELY_BLOCKED")
    passed = sum(1 for r in results if r["waf_action"] == "ALLOWED_OR_COUNTED")
    errored = len(results) - blocked - passed
    print(f"\n[*] 전송 완료: 총 {len(results)}건 "
          f"(차단추정 {blocked} / 통과 {passed} / 오류 {errored})")
    print(f"[*] 기록 저장: {args.output}")
    print("[*] 다음: S3에서 WAF 로그 확인 → 위 asid 값으로 내 공격 매칭")


if __name__ == "__main__":
    sys.exit(main())
