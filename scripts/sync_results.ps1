#!/usr/bin/env pwsh
# sync_results.ps1 — S3 audit-evidence 버킷에서 파이프라인 결과물을 로컬로 동기화
#
# 사용법:
#   .\scripts\sync_results.ps1              # 전체 결과물 동기화
#   .\scripts\sync_results.ps1 -Date 2026/06/30   # 특정 날짜만 동기화
#   .\scripts\sync_results.ps1 -Open        # 동기화 후 최신 보고서 열기

param(
    [string]$Date = "",
    [switch]$Open
)

$bucket  = "cloud-sec-audit-evidence-dev"
$region  = "ap-northeast-2"
$rootDir = Join-Path $PSScriptRoot ".."
$localDir = Join-Path $rootDir "output" "s3-results"

$s3Prefix = if ($Date) { "s3://$bucket/pipeline-results/$Date/" } `
            else       { "s3://$bucket/pipeline-results/" }

Write-Host "S3 결과물 동기화 중..." -ForegroundColor Cyan
Write-Host "  소스: $s3Prefix"
Write-Host "  대상: $localDir`n"

aws s3 sync $s3Prefix $localDir `
    --region $region `
    --exclude "*" `
    --include "*.json" `
    --include "*.html" `
    --include "*.pdf"

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n동기화 실패. AWS 자격증명 및 버킷 접근 권한을 확인하세요." -ForegroundColor Red
    exit 1
}

Write-Host "`n동기화 완료." -ForegroundColor Green

# 최신 파일 목록 출력
$files = Get-ChildItem $localDir -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 10
if ($files) {
    Write-Host "`n최신 결과물:"
    $files | ForEach-Object {
        Write-Host "  $($_.FullName.Replace($rootDir, '.'))" -ForegroundColor Gray
    }
}

# -Open 플래그: 최신 HTML 보고서 자동 열기
if ($Open) {
    $latestHtml = Get-ChildItem $localDir -Recurse -Filter "report.html" |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestHtml) {
        Write-Host "`n보고서 열기: $($latestHtml.FullName)" -ForegroundColor Cyan
        Start-Process $latestHtml.FullName
    } else {
        Write-Host "`nHTML 보고서가 없습니다." -ForegroundColor Yellow
    }
}
