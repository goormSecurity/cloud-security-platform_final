#!/bin/bash
# EC2 자동 파이프라인 — cron으로 1시간마다 실행
# S3 WAF 로그 수집 → 분석 → live_waf.jsonl → Fluent Bit → Loki → Grafana 자동 반영

LOCK=/tmp/pipeline-auto.lock
LOG=/var/log/pipeline-auto.log
ROOT=/opt/cloud-security-platform

exec >> "$LOG" 2>&1
echo ""
echo "=== $(date '+%Y-%m-%d %H:%M:%S KST') 자동 파이프라인 시작 ==="

# 중복 실행 방지
if [ -f "$LOCK" ]; then
    echo "[!] 이미 실행 중 (PID=$(cat $LOCK)) — 스킵"
    exit 0
fi
echo $$ > "$LOCK"
trap 'rm -f "$LOCK"' EXIT

cd "$ROOT"

# 1) 코드 최신화 (CI push 후 자동 반영)
echo "[1/3] git pull..."
git pull --ff-only || echo "[!] git pull 실패 — 로컬 코드로 계속"

# 2) API 서버·Fluent Bit 재시작 (코드 변경 적용)
echo "[2/3] 컨테이너 재시작..."
docker restart json-api fluent-bit
sleep 3

# 3) WAF 분석 파이프라인: S3 실데이터, AI/공격시뮬 스킵 (빠른 분석용)
echo "[3/3] WAF 분석 파이프라인 실행 (S3 --live-hours 1)..."
python3 scripts/run_pipeline.py \
    --live --live-hours 1 \
    --skip-ai \
    --skip-attack-sim \
    --skip-ab-test

echo "=== $(date '+%Y-%m-%d %H:%M:%S KST') 완료 ==="
