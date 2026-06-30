#!/bin/bash
exec >> /var/log/user-data.log 2>&1
set -x

# 1. 패키지
yum update -y
yum install -y docker python3.11 python3.11-pip git

# 2. Docker
systemctl start docker
systemctl enable docker
usermod -aG docker ec2-user
curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 3. 리포지토리 클론 (public)
git clone https://github.com/goormSecurity/cloud-security-platform.git /opt/cloud-security-platform
cd /opt/cloud-security-platform
git checkout feature/ec2-deploy

# 4. Python 3.11 의존성
python3.11 -m pip install -r requirements.txt

# 5. Playwright 브라우저 설치 (컴플라이언스 PDF 생성용)
python3.11 -m playwright install-deps chromium 2>/dev/null || true
python3.11 -m playwright install chromium 2>/dev/null || true

# 6. Ollama 설치 + 모델 다운로드 (t3.xlarge 16GB — llama3.1:8b 실행 가능)
curl -fsSL https://ollama.com/install.sh | sh
systemctl enable ollama
systemctl start ollama
sleep 30
ollama pull llama3.1:8b

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

# 8. Grafana + Loki
mkdir -p /opt/monitoring
cat > /opt/monitoring/docker-compose.yml << 'COMPOSE'
version: '3'
services:
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    restart: always
  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123!
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - loki
    restart: always
volumes:
  grafana-data:
COMPOSE
cd /opt/monitoring && docker-compose up -d

# 9. cron 등록 — 매일 오전 9시 KST (0시 UTC)
echo "0 0 * * * ec2-user cd /opt/cloud-security-platform && python3.11 scripts/run_pipeline.py --live >> /var/log/pipeline.log 2>&1" >> /etc/crontab

echo "=== user-data 완료 ==="
