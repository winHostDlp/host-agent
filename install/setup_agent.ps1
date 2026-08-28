<#
.SYNOPSIS
    Sentry DLP 사용자 에이전트를 현재 계정의 Task Scheduler 작업으로 등록합니다.

.DESCRIPTION
    SentryUserAgent — Task Scheduler 작업 (로그온 트리거, 현재 사용자 제한 권한)
    사용자 세션에서 클립보드 훅, Outlook 훅, FileGuard, HTTPS 웹 프록시,
    알림 팝업을 실행합니다. LocalSystem 서비스와 다중 사용자 그룹 작업은
    이 설치기에서 지원하지 않습니다.

.PARAMETER PythonExe
    Python 실행 파일 경로. 기본값은 스크립트 실행 시 자동 탐지.

.PARAMETER AgentDir
    에이전트 루트 디렉토리. 기본값: 스크립트의 상위 디렉토리.

.EXAMPLE
    .\setup_agent.ps1
    .\setup_agent.ps1 -PythonExe "C:\Python313\python.exe"
#>

param(
    [string]$PythonExe = "",
    [string]$AgentDir  = ""
)

$ErrorActionPreference = "Stop"

$TaskName = "SentryUserAgent"

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
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        $PythonExe = $pythonCommand.Source
    }
}
if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    Write-Err "Python을 찾을 수 없습니다. -PythonExe 파라미터로 경로를 지정하세요."
}
$PythonExe = (Resolve-Path $PythonExe).Path
$PythonWExe = Join-Path (Split-Path -Parent $PythonExe) "pythonw.exe"
if (-not (Test-Path $PythonWExe)) {
    Write-Err "콘솔 창 없는 사용자 작업 실행에 필요한 pythonw.exe가 없습니다: $PythonWExe"
}
$PythonWExe = (Resolve-Path $PythonWExe).Path

$UserScript = Join-Path $AgentDir "sentry_user_agent.py"

if (-not (Test-Path $UserScript)) {
    Write-Err "파일 없음: $UserScript"
}

Write-Step "AgentDir  : $AgentDir"
Write-Step "PythonExe : $PythonExe"
Write-Step "PythonWExe: $PythonWExe"

# ── 런타임 의존성 확인 ────────────────────────────────────────────────────────
# 설치 스크립트는 선택한 Python 환경을 임의로 변경하지 않는다. 누락된 모듈은
# 프로젝트 전용 venv에 requirements.txt를 설치한 뒤 다시 실행해야 한다.

Write-Step "Host Agent 런타임 의존성 확인"
$moduleNames = "requests,yaml,win32api,win32clipboard,win32con,win32file,win32gui,win32process,pythoncom,win32com,docx,fitz,openpyxl,pptx,striprtf,olefile,mitmproxy"
$dependencyCheckScript = @"
import importlib
import sys

modules = '$moduleNames'.split(',')
missing = []
for module in modules:
    try:
        importlib.import_module(module)
    except Exception:
        missing.append(module)

if missing:
    print('missing_or_broken=' + ','.join(missing))
    sys.exit(1)
print('OK dependencies')
"@
$dependencyResult = & $PythonExe -c $dependencyCheckScript 2>&1
$dependencyExitCode = $LASTEXITCODE
if ($dependencyExitCode -ne 0) {
    Write-Err "필수 모듈이 누락되었거나 로드되지 않습니다: $dependencyResult`n전역 Python에 자동 설치하지 않습니다. 다음처럼 프로젝트 전용 venv를 만든 뒤 다시 실행하세요:`n  & `"$PythonExe`" -m venv `"$AgentDir\.venv`"`n  & `"$AgentDir\.venv\Scripts\python.exe`" -m pip install -r `"$AgentDir\requirements.txt`"`n  .\install\setup_agent.ps1 -PythonExe `"$AgentDir\.venv\Scripts\python.exe`""
}
Write-OK "런타임 의존성 확인"

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
# Task Scheduler 작업 등록 (SentryUserAgent)
# ════════════════════════════════════════════════════════════════════════════════

Write-Step "Task Scheduler 작업 등록: $TaskName"

# 기존 작업 제거
Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Warn "기존 Task Scheduler 작업 제거됨 (없으면 무시)"

$action = New-ScheduledTaskAction `
    -Execute $PythonWExe `
    -Argument "`"$UserScript`"" `
    -WorkingDirectory $AgentDir

# 로그온 트리거
$trigger = New-ScheduledTaskTrigger -AtLogOn

$principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

Register-ScheduledTask `
    -TaskName   $TaskName `
    -Action     $action `
    -Trigger    $trigger `
    -Principal  $principal `
    -Settings   $settings `
    -Description "Sentry DLP 유저 에이전트 — 클립보드·Outlook·USB·HTTPS 업로드 감시" `
    | Out-Null

Write-OK "Task Scheduler 작업 등록 완료"

# 등록된 작업으로 현재 사용자 세션에서 즉시 시작
Write-Step "등록된 Task Scheduler 작업으로 유저 에이전트 시작"
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 1
$task = Get-ScheduledTask -TaskName $TaskName
if ($task.State -eq "Running") {
    Write-OK "유저 에이전트 작업 실행 중"
} else {
    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Err "유저 에이전트 시작 실패: State=$($task.State), LastTaskResult=$($taskInfo.LastTaskResult) — $AgentDir\logs\user_agent.log를 확인하세요."
}

# ── 완료 요약 ─────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-OK "설치 완료"
Write-Host "  서비스 : 미설치 (R009 발표 범위 밖의 SMTP/HTTP 시스템 채널 제외)"
Write-Host "  작업   : $TaskName (로그온 트리거)"
Write-Host "  로그   : $AgentDir\logs\"
Write-Host ""
Write-Host "설정 변경 후 사용하는 실행 계층을 재시작하세요:"
Write-Host "  사용자 채널(Clipboard/Outlook/FileGuard/WebProxy):"
Write-Host "    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "    Start-ScheduledTask -TaskName $TaskName"
Write-Host "  재시작 후 logs\user_agent.log에서 실제 채널 시작 상태를 확인하세요."
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
