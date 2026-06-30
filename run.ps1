<#
.SYNOPSIS
    Cloud Security Platform — 통합 실행 스크립트

.EXAMPLE
    .\run.ps1                    # EC2에서 파이프라인 실행 + 결과 로컬 동기화 (기본)
    .\run.ps1 -Local             # 로컬에서 직접 실행
    .\run.ps1 -Sync              # S3 결과만 로컬로 동기화
    .\run.ps1 -SkipAI            # AI 단계 스킵 (빠른 실행)
    .\run.ps1 -SkipAI -SkipZap   # 여러 단계 스킵
    .\run.ps1 -Sample            # 샘플 로그 사용 (인터넷 없이 테스트)
    .\run.ps1 -Open              # 완료 후 보고서 자동 열기
    .\run.ps1 -Local -Open       # 로컬 실행 + 보고서 열기
#>
param(
    [switch]$Local,              # EC2 대신 로컬에서 직접 실행
    [switch]$Sync,               # S3에서 결과물만 로컬로 내려받기
    [switch]$Open,               # 완료 후 HTML 보고서 자동 열기
    [switch]$SkipAI,             # AI 보고서 생성 스킵
    [switch]$SkipZap,            # OWASP ZAP 스킵
    [switch]$SkipPR,             # GitHub PR 자동 생성 스킵
    [switch]$Sample,             # 샘플 로그 사용 (S3 연결 불필요)
    [int]$LiveHours = 1          # S3 로그 수집 시간 범위 (기본 1시간)
)

Set-Location $PSScriptRoot
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$bucket  = "cloud-sec-audit-evidence-dev"
$region  = "ap-northeast-2"
$sshKey  = "$env:USERPROFILE\.ssh\cloud-sec-key2"
$syncDir = "output\s3-results"

# ── 공통: .env 로드 ──────────────────────────────────────────────────
function Load-Env {
    if (Test-Path ".env") {
        Get-Content ".env" | ForEach-Object {
            if ($_ -match "^\s*([^#][^=]+)=(.+)$") {
                Set-Item -Path "Env:$($Matches[1].Trim())" -Value $Matches[2].Trim() -ErrorAction SilentlyContinue
            }
        }
    }
}

# ── EC2 IP 취득 ──────────────────────────────────────────────────────
function Get-EC2IP {
    if ($env:ANALYSIS_IP) { return $env:ANALYSIS_IP }
    $ip = terraform -chdir=terraform output -raw analysis_public_ip 2>$null
    if ($LASTEXITCODE -eq 0 -and $ip) { return $ip.Trim() }
    Write-Host "  EC2 IP를 찾을 수 없습니다." -ForegroundColor Red
    Write-Host "  .env 에 ANALYSIS_IP=<IP> 를 추가하거나 terraform apply 를 먼저 실행하세요." -ForegroundColor Gray
    exit 1
}

# ── S3 결과물 동기화 ─────────────────────────────────────────────────
function Sync-Results {
    Write-Host "`n  S3 → 로컬 동기화 중..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path $syncDir | Out-Null
    aws s3 sync "s3://$bucket/pipeline-results/" $syncDir `
        --region $region --exclude "*" `
        --include "*.json" --include "*.html" --include "*.pdf" 2>&1 | ForEach-Object {
            if ($_ -match "download:") { Write-Host "  $_" -ForegroundColor Gray }
        }
    Write-Host "  동기화 완료 → $syncDir" -ForegroundColor Green

    if ($Open) {
        $report = Get-ChildItem $syncDir -Recurse -Filter "report.html" |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($report) { Write-Host "  보고서 열기: $($report.FullName)"; Start-Process $report.FullName }
        else { Write-Host "  HTML 보고서 없음 (컴플라이언스 단계가 성공해야 생성됩니다)" -ForegroundColor Yellow }
    }
}

# ── EC2 모드 ─────────────────────────────────────────────────────────
function Run-EC2 {
    $ip = Get-EC2IP
    Write-Host "  EC2: $ip" -ForegroundColor Gray

    $pArgs = if ($Sample) { "" } else { "--live --live-hours $LiveHours" }
    if ($SkipAI)  { $pArgs += " --skip-ai" }
    if ($SkipZap) { $pArgs += " --skip-zap" }
    if ($SkipPR)  { $pArgs += " --skip-pr" }

    Write-Host "  파이프라인 실행 중 (출력 스트리밍)...`n" -ForegroundColor Cyan
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o ServerAliveInterval=60 `
        -i $sshKey "ec2-user@$ip" `
        "cd /opt/cloud-security-platform && sudo python3.11 scripts/run_pipeline.py $pArgs 2>&1 | tee /tmp/pipeline-run.log"

    Sync-Results
}

# ── 로컬 모드 ────────────────────────────────────────────────────────
function Run-Local {
    if (-not $env:OLLAMA_MODELS) { $env:OLLAMA_MODELS = "C:\ollama\models" }

    $cmd = @("python", "-X", "utf8", "scripts/run_pipeline.py")
    if ($Sample)  { $cmd += @("--log-dir", "analyzer/sample_logs") }
    else          { $cmd += "--live"; $cmd += @("--live-hours", "$LiveHours") }
    if ($SkipAI)  { $cmd += "--skip-ai" }
    if ($SkipZap) { $cmd += "--skip-zap" }
    if ($SkipPR)  { $cmd += "--skip-pr" }

    & $cmd[0] $cmd[1..($cmd.Length - 1)]

    if ($Open) {
        $report = Get-ChildItem "compliance" -Filter "report.html" -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($report) { Start-Process $report.FullName }
    }
}

# ── 메인 ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "  Cloud Security Platform"
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""

Load-Env

if ($Sync)      { Sync-Results }
elseif ($Local) { Run-Local }
else            { Run-EC2 }
