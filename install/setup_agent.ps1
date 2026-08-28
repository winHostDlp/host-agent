#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sentry DLP 에이전트를 Windows 서비스 + Task Scheduler 작업으로 등록합니다.

.DESCRIPTION
    1. SentryDLPService  — Windows 서비스 (자동 시작, 크래시 재시작)
       Session 0에서 실행: SMTP 프록시, HTTP 모니터, FileGuard
    2. SentryUserAgent   — Task Scheduler 작업 (로그온 트리거, 최고 권한)
       사용자 세션에서 실행: 클립보드 훅, Outlook 훅, 알림 팝업

.PARAMETER PythonExe
    Python 실행 파일 경로. 기본값은 스크립트 실행 시 자동 탐지.

.PARAMETER AgentDir
    에이전트 루트 디렉토리. 기본값: 스크립트의 상위 디렉토리.

.PARAMETER ForCurrentUserOnly
    $true 시 Task Scheduler 작업을 현재 사용자에게만 등록.
    $false(기본) 시 모든 사용자에게 적용 (NT AUTHORITY\Users 그룹).

.EXAMPLE
    .\setup_agent.ps1
    .\setup_agent.ps1 -PythonExe "C:\Python313\python.exe"
    .\setup_agent.ps1 -ForCurrentUserOnly $true
#>

param(
    [string]$PythonExe         = "",
    [string]$AgentDir          = "",
    [bool]  $ForCurrentUserOnly = $false
)

$ServiceName  = "SentryDLPService"
$TaskName     = "SentryUserAgent"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err ([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Red; exit 1 }
function Write-Warn([string]$msg) { Write-Host "[~] $msg" -ForegroundColor Yellow }

# ── 경로 결정 ─────────────────────────────────────────────────────────────────

if (-not $AgentDir) {
    $AgentDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
$AgentDir = (Resolve-Path $AgentDir).Path

if (-not $PythonExe) {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue)?.Source
}
if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    Write-Err "Python을 찾을 수 없습니다. -PythonExe 파라미터로 경로를 지정하세요."
}

$ServiceScript = Join-Path $AgentDir "sentry_service.py"
$UserScript    = Join-Path $AgentDir "sentry_user_agent.py"

foreach ($f in @($ServiceScript, $UserScript)) {
    if (-not (Test-Path $f)) { Write-Err "파일 없음: $f" }
}

Write-Step "AgentDir  : $AgentDir"
Write-Step "PythonExe : $PythonExe"

# ── pywin32 설치 확인 ─────────────────────────────────────────────────────────

Write-Step "pywin32 설치 확인"
$pywin32Check = & $PythonExe -c "import win32serviceutil; print('ok')" 2>&1
if ($pywin32Check -ne "ok") {
    Write-Warn "pywin32 미설치 → 지금 설치합니다"
    & $PythonExe -m pip install pywin32 -q
    & $PythonExe -c "import win32serviceutil" 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Err "pywin32 설치 실패. 수동으로 설치하세요: pip install pywin32" }
    # post-install 스크립트 실행 (DLL 등록)
    $postInstall = "$env:SystemRoot\System32\pythonXX.dll"
    & $PythonExe -c "import pywin32_bootstrap" 2>$null | Out-Null
}
Write-OK "pywin32 확인"

# ── 내장 드라이브 기준 파일 생성 ──────────────────────────────────────────────
# USB가 꽂히지 않은 상태에서 현재 로컬 드라이브를 내장으로 저장.
# 이 파일을 기준으로 이후 추가되는 드라이브를 이동식으로 판단한다.

Write-Step "이 PC의 내장 드라이브 기준 파일 생성 (config/internal_drives.local.json)"
Write-Warn "  이동식 저장장치(USB, 외장 HDD 등)가 모두 제거된 상태인지 확인하세요."
Write-Warn "  Windows가 FIXED로 인식하는 외장 SSD도 반드시 제거하세요."
Write-Warn "  현재 FIXED 드라이브만 내장 기준으로 기록합니다."
$internalDrivesScript = @"
import win32api, win32file, win32con, json, os, pathlib
def iter_drives():
    bitmask = win32api.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(ord('A') + i) + ':'
            try:
                dtype = win32file.GetDriveType(letter + chr(92))
                yield letter, dtype
            except Exception:
                pass
drives = list(iter_drives())
removable = [l for l, t in drives if t == win32con.DRIVE_REMOVABLE]
if removable:
    raise RuntimeError('이동식 드라이브를 모두 제거한 뒤 다시 실행하세요: ' + str(removable))
# ponytail: GetDriveType은 FIXED로 보고되는 외장 디스크를 구분하지 못한다.
# 자동 교정이 필요하면 Win32_DiskDrive BusType 매핑으로 교체한다.
internal = [l for l, t in drives if t == win32con.DRIVE_FIXED]
out = pathlib.Path(r'$AgentDir\config\internal_drives.local.json')
system_drive = os.environ.get('SystemDrive', '').upper()
if not internal or not system_drive or system_drive not in internal:
    raise RuntimeError('시스템 드라이브를 포함한 안전한 내장 드라이브 기준을 만들지 못했습니다.')
tmp = out.with_suffix(out.suffix + '.tmp')
tmp.write_text(json.dumps({'internal_drives': internal, '_comment': '이 PC의 로컬 기준. Git에 올리지 마세요. 이동식 저장장치를 모두 제거한 상태에서 생성했습니다.'}, ensure_ascii=False, indent=2), encoding='utf-8')
tmp.replace(out)
print('OK internal_drives.local=' + str(internal))
"@
$result = & $PythonExe -c $internalDrivesScript 2>&1
if ($result -match "^OK") {
    Write-OK "내장 드라이브 기준 저장: $result"
} else {
    Write-Err "내장 드라이브 기준 생성 실패. 안전을 위해 FileGuard를 설치하지 않습니다: $result"
}

# ════════════════════════════════════════════════════════════════════════════════
# 1. Windows 서비스 등록 (SentryDLPService)
# ════════════════════════════════════════════════════════════════════════════════

Write-Step "Windows 서비스 등록: $ServiceName"

# 기존 서비스 제거
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    sc.exe stop   $ServiceName 2>$null | Out-Null
    sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
    Write-Warn "기존 서비스 제거됨"
}

# 서비스 설치 (pywin32 방식)
& $PythonExe $ServiceScript --startup=auto install 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "서비스 설치 실패. 로그를 확인하세요."
}

# ── 크래시 복구 설정 (첫 번째·두 번째 실패 → 1분 후 재시작, 이후 → 5분) ────

sc.exe failure $ServiceName reset= 86400 `
    actions= restart/60000/restart/60000/restart/300000 | Out-Null
Write-OK "크래시 재시작 정책 설정 완료"

# ── 서비스 시작 ────────────────────────────────────────────────────────────────

Write-Step "서비스 시작"
sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-OK "서비스 실행 중 ✓"
} else {
    Write-Warn "서비스 상태: $($svc.Status) — 로그를 확인하세요: $AgentDir\logs\service.log"
}

# ════════════════════════════════════════════════════════════════════════════════
# 2. Task Scheduler 작업 등록 (SentryUserAgent)
# ════════════════════════════════════════════════════════════════════════════════

Write-Step "Task Scheduler 작업 등록: $TaskName"

# 기존 작업 제거
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Warn "기존 Task Scheduler 작업 제거됨 (없으면 무시)"

$action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "`"$UserScript`"" `
    -WorkingDirectory $AgentDir

# 로그온 트리거
$trigger = New-ScheduledTaskTrigger -AtLogOn

if ($ForCurrentUserOnly) {
    $principal = New-ScheduledTaskPrincipal `
        -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive `
        -RunLevel Highest
} else {
    $principal = New-ScheduledTaskPrincipal `
        -GroupId "BUILTIN\Users" `
        -RunLevel Highest
}

$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -ExecutionTimeLimit (New-TimeSpan -Days 365) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName   $TaskName `
    -Action     $action `
    -Trigger    $trigger `
    -Principal  $principal `
    -Settings   $settings `
    -Description "Sentry DLP 유저 에이전트 — 클립보드·Outlook 감시" `
    | Out-Null

Write-OK "Task Scheduler 작업 등록 완료"

# 현재 사용자 세션에서 즉시 시작
Write-Step "유저 에이전트 즉시 실행"
Start-Process -FilePath $PythonExe `
    -ArgumentList "`"$UserScript`"" `
    -WorkingDirectory $AgentDir `
    -WindowStyle Hidden
Start-Sleep -Seconds 1
Write-OK "유저 에이전트 백그라운드 실행 중"

# ── 완료 요약 ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-OK "설치 완료"
Write-Host "  서비스 : $ServiceName (자동 시작, 크래시 재시작)"
Write-Host "  작업   : $TaskName (로그온 트리거)"
Write-Host "  로그   : $AgentDir\logs\"
Write-Host ""
Write-Host "채널 활성화: config\channel_policy.json 에서 enabled: true 로 변경 후"
Write-Host "  sc stop/start $ServiceName  또는 재부팅"
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
