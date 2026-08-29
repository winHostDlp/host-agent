#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sentry DLP 에이전트(서비스 + Task Scheduler 작업)를 제거합니다.
#>

$ServiceName = "SentryDLPService"
$TaskName    = "SentryUserAgent"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[~] $msg" -ForegroundColor Yellow }

# Task Scheduler 작업 제거
Write-Step "Task Scheduler 작업 제거: $TaskName"
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-OK "완료"

# Windows 서비스 중지 및 제거
Write-Step "서비스 중지: $ServiceName"
sc.exe stop $ServiceName 2>$null | Out-Null
Start-Sleep -Seconds 2

Write-Step "서비스 제거: $ServiceName"
sc.exe delete $ServiceName 2>$null | Out-Null
Write-OK "완료"

Write-Host ""
Write-OK "Sentry DLP 에이전트 제거 완료"
