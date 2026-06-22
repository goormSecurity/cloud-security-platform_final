#!/usr/bin/env python3
"""

    python pr_collector.py                 # 전체 PR (open+closed)
    python pr_collector.py --state closed  # 닫힌 PR만
    python pr_collector.py --merged-only   # 머지된 PR만 (변경관리 증적용 권장)
"""
import argparse
import json
import os
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEFAULT_REPO = "goormSecurity/cloud-security-platform"
API = "https://api.github.com"


FIELDS = [
    "pr_number", "pr_url", "state", "merged", "merged_at",
    "merge_commit_sha", "changed_files", "base_branch", "head_branch",
]


def gh_get(url, token):
    """GitHub API GET. JSON 반환."""
    req = Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pr-collector",
    })
    with urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_prs(repo, token, state):
    """레포의 PR을 페이지네이션으로 전부 가져온다 (요약 목록)."""
    prs, page = [], 1
    while True:
        url = f"{API}/repos/{repo}/pulls?state={state}&per_page=100&page={page}"
        batch = gh_get(url, token)
        if not batch:
            break
        prs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return prs


def to_record(pr_detail):
    """PR 상세 응답 → 지정된 9개 필드만 매핑."""
    return {
        "pr_number": pr_detail.get("number"),
        "pr_url": pr_detail.get("html_url"),
        "state": pr_detail.get("state"),                       # open / closed
        "merged": pr_detail.get("merged", False),
        "merged_at": pr_detail.get("merged_at"),               # null 가능
        "merge_commit_sha": pr_detail.get("merge_commit_sha"),
        "changed_files": pr_detail.get("changed_files"),       # 상세 조회에만 있음
        "base_branch": (pr_detail.get("base") or {}).get("ref"),
        "head_branch": (pr_detail.get("head") or {}).get("ref"),
    }


def main():
    p = argparse.ArgumentParser(description="GitHub PR 이력 → github_pr.json")
    p.add_argument("--repo", default=os.getenv("GITHUB_REPO", DEFAULT_REPO))
    p.add_argument("--state", default="all", choices=["all", "open", "closed"])
    p.add_argument("--merged-only", action="store_true", help="머지된 PR만 출력")
    p.add_argument("--output", default="github_pr.json")
    args = p.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("[!] GITHUB_TOKEN 이 없습니다. compliance/.env 에 넣어주세요.")
        return 1

    print(f"[*] 레포: {args.repo}  (state={args.state})")
    try:
        summaries = list_prs(args.repo, token, args.state)
    except HTTPError as e:
        if e.code == 401:
            print("[!] 401 인증 실패 — 토큰이 틀렸거나 만료됐습니다.")
        elif e.code == 404:
            print("[!] 404 — 레포 이름이 틀렸거나 토큰에 repo 권한이 없습니다.")
        else:
            print(f"[!] GitHub API 오류 {e.code}: {e.reason}")
        return 1
    except URLError as e:
        print(f"[!] 네트워크 오류: {e.reason}")
        return 1

    print(f"[*] PR {len(summaries)}건 발견 — 상세 조회 중...")
    records = []
    for s in summaries:
        # changed_files / merged 는 '상세' 응답에만 있어서 PR마다 개별 조회
        detail = gh_get(f"{API}/repos/{args.repo}/pulls/{s['number']}", token)
        rec = to_record(detail)
        if args.merged_only and not rec["merged"]:
            continue
        records.append(rec)
        flag = "MERGED" if rec["merged"] else rec["state"].upper()
        print(f"  [{flag:7}] #{rec['pr_number']} {rec['head_branch']} → {rec['base_branch']}")

    records.sort(key=lambda r: r["pr_number"] or 0)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)

    merged = sum(1 for r in records if r["merged"])
    print(f"\n[*] 저장: {args.output}  (총 {len(records)}건 / 머지 {merged}건)")
    return 0


if __name__ == "__main__":
    sys.exit(main())