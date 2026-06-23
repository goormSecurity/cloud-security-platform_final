<#
.SYNOPSIS
    로컬 환경에서 전체 파이프라인 실행 (AWS·GitHub 자격증명 자동 로드)

.DESCRIPTION
    기본값: S3 실시간 로그 기반 실행.
    AWS/GitHub 자격증명이 없는 항목은 자동으로 스킵됩니다.

.EXAMPLE
    .\run_local.ps1                              # 기본 실행 (S3 실시간 로그, 최근 1시간)
    .\run_local.ps1 -LiveHours 3                 # 최근 3시간 로그
    .\run_local.ps1 -Sample                      # 샘플 로그로 실행 (테스트용)
    .\run_local.ps1 -SkipZap -SkipAI            # ZAP·AI 단계 건너뜀
#>
param(
    [string]$Target    = "http://cloud-sec-alb-664622103.ap-northeast-2.elb.amazonaws.com",
    [switch]$SkipZap   = $false,
    [switch]$SkipAI    = $false,
    [switch]$SkipPR    = $false,
    [switch]$Sample    = $false,   # 샘플 로그 사용 (테스트 전용)
    [int]$LiveHours    = 1
)

Set-Location $PSScriptRoot
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Ollama 한글 경로 우회 (유지원 → C:\ollama\models)
if (-not $env:OLLAMA_MODELS) { $env:OLLAMA_MODELS = "C:\ollama\models" }

# ── .env 로드 ──────────────────────────────────────────────────────────
if (Test-Path ".env") {
    Write-Host "[env] .env 로드 중..."
    Get-Content ".env" | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
            $key   = $Matches[1].Trim()
            $value = $Matches[2].Trim()
            if ($value -ne "" -and -not [Environment]::GetEnvironmentVariable($key)) {
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
                $env:dummy = $null   # PS5 doesn't have inline env set
                Set-Item -Path "Env:$key" -Value $value
            }
        }
    }
} else {
    Write-Host "[env] .env 없음 — AWS/GitHub 스킵 예상"
    Write-Host "      .env.example 을 복사하여 .env 를 만들고 키를 채워주세요."
}

# ── 파이프라인 커맨드 빌드 ────────────────────────────────────────────
$cmd = @("python", "-X", "utf8", "scripts/run_pipeline.py")

if ($Sample) { $cmd += @("--log-dir", "analyzer/sample_logs") }
else         { $cmd += "--live"; $cmd += @("--live-hours", "$LiveHours") }
if ($Target)  { $cmd += @("--target", $Target) }
if ($SkipZap) { $cmd += "--skip-zap" }
if ($SkipAI)  { $cmd += "--skip-ai"  }
if ($SkipPR)  { $cmd += "--skip-pr"  }

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "  Cloud Security Platform — 로컬 파이프라인 실행"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""

& $cmd[0] $cmd[1..($cmd.Length-1)]
