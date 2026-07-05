#!/bin/bash
exec >> /var/log/user-data.log 2>&1
set -x

# 1. 패키지
yum update -y
yum install -y docker python3.11 python3.11-pip git

# 2. Docker
systemctl start docker
systemctl enable docker

# 2b. DLAMI에 NVIDIA 드라이버 사전 설치됨 — 상태만 확인
nvidia-smi && echo "[GPU] NVIDIA T4 준비 완료" || echo "[GPU] 드라이버 확인 필요"
usermod -aG docker ec2-user
curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 3. 리포지토리 클론 (public)
git clone https://github.com/goormSecurity/cloud-security-platform_final.git /opt/cloud-security-platform
cd /opt/cloud-security-platform

# 4. Python 3.11 의존성
python3.11 -m pip install -r requirements.txt

# 5. Playwright 브라우저 설치 (컴플라이언스 PDF 생성용)
dnf install -y nss atk at-spi2-atk cups-libs libXcomposite libXdamage libXext \
  libXfixes libXrandr pango alsa-lib gtk3 2>/dev/null || true
python3.11 -m playwright install chromium 2>/dev/null || true

# 6. Ollama 설치 — 0.0.0.0으로 바인딩 (외부 접근 허용)
curl -fsSL https://ollama.com/install.sh | sh
mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF
systemctl daemon-reload
systemctl enable ollama
systemctl start ollama

# Ollama 준비될 때까지 대기 (최대 60초)
for i in $(seq 1 12); do
  if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "[Ollama] 준비 완료 (${i}*5초)"
    break
  fi
  echo "[Ollama] 대기 중... ($i/12)"
  sleep 5
done
ollama pull qwen2.5:7b

# 7. SSM에서 시크릿 가져와 .env 생성
SSM_GITHUB=$(aws ssm get-parameter --name /cloud-sec/github_token \
  --with-decryption --query Parameter.Value --output text --region ap-northeast-2 2>/dev/null || echo "")
SSM_ABUSE=$(aws ssm get-parameter --name /cloud-sec/abuseipdb_api_key \
  --with-decryption --query Parameter.Value --output text --region ap-northeast-2 2>/dev/null || echo "")
SSM_SLACK=$(aws ssm get-parameter --name /cloud-sec/slack_webhook_url \
  --with-decryption --query Parameter.Value --output text --region ap-northeast-2 2>/dev/null || echo "")

printf 'AWS_DEFAULT_REGION=ap-northeast-2\nGITHUB_TOKEN=%s\nABUSEIPDB_API_KEY=%s\nSLACK_WEBHOOK_URL=%s\n' \
  "$SSM_GITHUB" "$SSM_ABUSE" "$SSM_SLACK" > /opt/cloud-security-platform/.env
chmod 600 /opt/cloud-security-platform/.env

# 8. Grafana + Loki + JSON API (repo의 docker-compose 사용)
mkdir -p /opt/cloud-security-platform/output
cd /opt/cloud-security-platform/monitoring
docker-compose up -d

# 9. cron 등록 — 매일 오전 9시 KST (0시 UTC)
echo "0 0 * * * ec2-user cd /opt/cloud-security-platform && python3.11 scripts/run_pipeline.py --live >> /var/log/pipeline.log 2>&1" >> /etc/crontab

echo "=== user-data 완료 ==="
