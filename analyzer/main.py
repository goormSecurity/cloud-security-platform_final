"""
main.py — 분석 엔진 전체 실행

  python main.py                         # sample_logs/ 읽어서 분석
  python main.py --source tests/fixtures # 다른 폴더 지정
  python main.py --s3                    # S3에서 직접 읽기(운영, boto3 필요)
  python main.py --cti                   # 상위 IP를 AbuseIPDB로 추가 조회

결과: output/analysis_YYYYMMDD_HHMMSS.json  (일환/소연/병옥이 소비)
"""
import argparse
import json
import os
from datetime import datetime, timedelta, timezone

from config import Config
import waf_analyzer


def main():
    p = argparse.ArgumentParser(description="WAF 로그 분석 엔진")
    p.add_argument("--source", default=Config.LOCAL_LOG_DIR, help="로컬 로그 폴더")
    p.add_argument("--s3", action="store_true", help="S3에서 직접 읽기")
    p.add_argument("--cti", action="store_true", help="상위 IP CTI 조회 활성화")
    p.add_argument("--cti-top", type=int, default=10, help="CTI 조회할 상위 IP 수")
    args = p.parse_args()

    # 1) 로그 읽기
    if args.s3:
        print(f"[*] S3에서 읽기: s3://{Config.WAF_LOGS_BUCKET}")
        records = list(waf_analyzer.fetch_records_from_s3(Config.WAF_LOGS_BUCKET, Config.AWS_REGION))
    else:
        print(f"[*] 로컬에서 읽기: {args.source}")
        records = list(waf_analyzer.iter_records(args.source))

    if not records:
        print("[!] 로그를 못 찾았습니다. --source 경로 또는 S3 설정을 확인하세요.")
        return 1
    print(f"[*] 레코드 {len(records)}건 로드")

    # 2) 분석
    result = waf_analyzer.analyze(records)

    # 3) CTI 보강 (선택)
    if args.cti or Config.CTI_ENABLED:
        from cti_checker import CTIChecker
        cti = CTIChecker()
        if cti.enabled:
            print(f"[*] CTI 조회: 상위 {args.cti_top}개 IP")
            for ip_stats in result["top_ips"][:args.cti_top]:
                info = cti.check(ip_stats["ip"])
                if info:
                    ip_stats["cti"] = info
                    score, level = waf_analyzer.compute_risk(ip_stats, cti=info)
                    ip_stats["risk_score"], ip_stats["risk_level"] = score, level
            cti.save_cache()
            result["top_ips"].sort(key=lambda x: x["risk_score"], reverse=True)
            result["summary"]["high_risk_ips"] = sum(
                1 for x in result["top_ips"] if x["risk_level"] == "HIGH")
        else:
            print("[!] CTI 비활성(ABUSEIPDB_API_KEY 없음) — 건너뜀")

    # 4) JSON 출력
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(Config.OUTPUT_DIR, f"analysis_{datetime.now():%Y%m%d_%H%M%S}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # 5) Loki 스트리밍용 라이브 로그 작성 (Fluent Bit이 tail → Loki 전송)
    live_path = os.path.join(Config.OUTPUT_DIR, "live_waf.jsonl")
    written = 0
    now = datetime.now(timezone.utc)
    with open(live_path, "a", encoding="utf-8") as lf:
        for i, rec in enumerate(records):
            req = rec.get("httpRequest", {})
            # Loki는 7일 이상 오래된 타임스탬프를 거부 → 항상 현재 시각 기준으로 기록
            dt = now.replace(microsecond=0) - timedelta(seconds=len(records) - i)
            lf.write(json.dumps({
                "timestamp": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "action":    (rec.get("action") or "ALLOW").upper(),
                "clientIp":  req.get("clientIp", "-"),
                "uri":       (req.get("uri", "-") or "-")[:120],
                "country":   req.get("country", "-"),
            }, ensure_ascii=False) + "\n")
            written += 1
    print(f"[*] 라이브 로그 추가: {live_path} ({written}건)")

    s = result["summary"]
    print(f"\n[*] 요약: 총 {s['total_requests']}건 / IP {s['unique_ips']}개 / "
          f"차단율 {s['block_rate']:.0%} / 고위험 IP {s['high_risk_ips']}개")
    print(f"[*] 공격 유형: {s['attack_type_counts']}")
    print(f"[*] 결과 저장: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
