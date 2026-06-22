#!/usr/bin/env python3
"""
collect_waf_logs.py — S3에서 최신 WAF 로그 다운로드

WAF가 S3에 기록한 .log.gz 파일을 지정 시간 범위만큼 내려받아
analyzer/live_logs/ 에 저장한다. (WAF → S3 딜레이 약 5~10분)

사용 예:
  python scripts/collect_waf_logs.py              # 최근 1시간치
  python scripts/collect_waf_logs.py --hours 3    # 최근 3시간치
  python scripts/collect_waf_logs.py --hours 24   # 오늘 전체
"""
import argparse
import gzip
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUCKET   = "aws-waf-logs-cloud-sec-dev"
DEFAULT_PREFIX   = "AWSLogs/677673473281/WAFLogs/ap-northeast-2/cloud-sec-web-acl"
OUTPUT_DIR       = ROOT / "analyzer" / "live_logs"
DEFAULT_HOURS    = 1


def _boto3_client(service, region="ap-northeast-2"):
    try:
        import boto3
        return boto3.client(service, region_name=region)
    except ImportError:
        sys.exit("[collect_waf_logs] boto3가 필요합니다: pip install boto3")


def _date_prefixes(hours: int) -> list[str]:
    """수집 시간 범위에 해당하는 S3 prefix 목록 생성 (시간 단위)."""
    now = datetime.now(timezone.utc)
    prefixes = []
    for h in range(hours + 1):
        t = now - timedelta(hours=h)
        prefixes.append(
            f"{DEFAULT_PREFIX}/{t.year}/{t.month:02d}/{t.day:02d}/{t.hour:02d}/"
        )
    return list(set(prefixes))


def collect(bucket: str, hours: int, out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    s3 = _boto3_client("s3")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    print(f"[collect_waf_logs] 버킷: {bucket}")
    print(f"[collect_waf_logs] 수집 기간: {cutoff.strftime('%Y-%m-%d %H:%M')} UTC ~ 현재 ({hours}시간)")

    prefixes = _date_prefixes(hours)
    keys = []
    for prefix in prefixes:
        try:
            resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
            for obj in resp.get("Contents", []):
                if obj["LastModified"] >= cutoff and obj["Key"].endswith(".log.gz"):
                    keys.append(obj["Key"])
        except Exception as e:
            print(f"[collect_waf_logs] prefix 조회 실패 ({prefix}): {e}")

    if not keys:
        print(f"[collect_waf_logs] 최근 {hours}시간 내 새 로그 없음")
        print("  → WAF 로그는 트래픽 발생 후 5~10분 뒤 S3에 기록됩니다")
        print("  → attack_runner.py 실행 후 잠시 기다렸다가 다시 시도하세요")
        return 0

    print(f"[collect_waf_logs] 다운로드: {len(keys)}개 파일")
    total_events = 0
    all_events = []

    for key in sorted(keys):
        fname = Path(key).name.replace(".log.gz", ".json")
        local_gz = out_dir / Path(key).name
        try:
            s3.download_file(bucket, key, str(local_gz))
            with gzip.open(local_gz, "rt", encoding="utf-8") as f:
                events = [json.loads(line) for line in f if line.strip()]
            all_events.extend(events)
            total_events += len(events)
            local_gz.unlink()
            print(f"  [+] {Path(key).name} → {len(events)}건")
        except Exception as e:
            print(f"  [!] {key} 실패: {e}")

    # 단일 JSONL 파일로 저장 (analyzer가 읽을 수 있는 포맷)
    out_file = out_dir / f"live_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    with open(out_file, "w", encoding="utf-8") as f:
        for ev in all_events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"\n[collect_waf_logs] 저장: {out_file} (총 {total_events}건)")
    return total_events


def main():
    p = argparse.ArgumentParser(description="S3 WAF 로그 다운로드 → analyzer/live_logs/")
    p.add_argument("--bucket", default=DEFAULT_BUCKET)
    p.add_argument("--hours",  default=DEFAULT_HOURS, type=int, help="수집 시간 범위 (기본: 1시간)")
    p.add_argument("--out",    default=str(OUTPUT_DIR))
    args = p.parse_args()
    count = collect(args.bucket, args.hours, Path(args.out))
    if count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
