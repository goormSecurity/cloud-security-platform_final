#!/usr/bin/env pwsh
# setup_ssm.ps1 — .env의 시크릿 값을 AWS SSM Parameter Store에 저장
# EC2 부팅 시 user_data가 이 값을 읽어 .env를 자동 생성함
#
# 사용법:
#   cd cloud-security-platform
#   .\scripts\setup_ssm.ps1

$region = "ap-northeast-2"
$prefix = "/cloud-sec"

function Put-SSMParam([string]$name, [string]$value, [string]$desc) {
    if (-not $value -or $value.Trim() -eq "") {
        Write-Host "  SKIP  $name (값 없음)" -ForegroundColor Yellow
        return
    }
    $result = aws ssm put-parameter `
        --name $name `
        --value $value `
        --type SecureString `
        --description $desc `
        --overwrite `
        --region $region 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK    $name" -ForegroundColor Green
    } else {
        Write-Host "  FAIL  $name : $result" -ForegroundColor Red
    }
}

# .env 읽기
$envFile = Join-Path (Split-Path $PSScriptRoot) ".env"
$envVars = @{}
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
            $parts = $line -split "=", 2
            $k = $parts[0].Trim()
            $v = $parts[1].Trim()
            if ($v -ne "") { $envVars[$k] = $v }
        }
    }
} else {
    Write-Host ".env 파일이 없습니다. 먼저 .env.example을 복사해서 값을 채워주세요." -ForegroundColor Red
    exit 1
}

Write-Host "`nSSM Parameter Store에 시크릿 저장 중..." -ForegroundColor Cyan
Write-Host "리전: $region`n"

Put-SSMParam "$prefix/github_token"      $envVars["GITHUB_TOKEN"]      "GitHub PAT — cloud-security-platform PR 자동 생성"
Put-SSMParam "$prefix/abuseipdb_api_key" $envVars["ABUSEIPDB_API_KEY"] "AbuseIPDB API 키 — IP 위험도 조회"
Put-SSMParam "$prefix/slack_webhook_url" $envVars["SLACK_WEBHOOK_URL"] "Discord/Slack Webhook URL — WAF 분석 알림"

Write-Host "`n완료. EC2 배포 후 부팅 시 자동으로 /opt/cloud-security-platform/.env가 생성됩니다." -ForegroundColor Cyan
Write-Host "저장된 파라미터 확인: aws ssm describe-parameters --region $region --query 'Parameters[?starts_with(Name, ``$prefix``)].Name'"
