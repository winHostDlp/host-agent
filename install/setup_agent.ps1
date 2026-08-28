#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sentry DLP 에이전트를 Windows 서비스 + Task Scheduler 작업으로 등록합니다.

.DESCRIPTION
    1. SentryDLPService  — 선택 설치 Windows 서비스 (자동 시작, 크래시 재시작)
       Session 0에서 실행: SMTP 프록시, HTTP 모니터
    2. SentryUserAgent   — Task Scheduler 작업 (로그온 트리거, 현재 사용자 제한 권한)
       사용자 세션에서 실행: 클립보드 훅, Outlook 훅, FileGuard,
       HTTPS 웹 프록시, 알림 팝업

.PARAMETER PythonExe
    Python 실행 파일 경로. 기본값은 스크립트 실행 시 자동 탐지.

.PARAMETER AgentDir
    에이전트 루트 디렉토리. 기본값: 스크립트의 상위 디렉토리.

.PARAMETER ForCurrentUserOnly
    $true 시 Task Scheduler 작업을 현재 사용자에게만 등록.
    $false 시 모든 사용자에게 적용 (NT AUTHORITY\Users 그룹).
    발표용 기본값은 사용자별 Outlook·HKCU 프록시·CA와 일치하도록 $true.

.PARAMETER InstallSystemService
    SMTP/HTTP 시스템 채널용 LocalSystem 서비스를 추가 설치합니다. 기본은 미설치.
    관리자만 수정할 수 있는 보호 경로의 AgentDir/Python에서만 사용하세요.

.EXAMPLE
    .\setup_agent.ps1
    .\setup_agent.ps1 -PythonExe "C:\Python313\python.exe"
    .\setup_agent.ps1 -InstallSystemService
#>

param(
    [string]$PythonExe         = "",
    [string]$AgentDir          = "",
    [bool]  $ForCurrentUserOnly = $true,
    [switch]$InstallSystemService
)

$ErrorActionPreference = "Stop"

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

$ServiceScript = Join-Path $AgentDir "sentry_service.py"
$UserScript    = Join-Path $AgentDir "sentry_user_agent.py"

foreach ($f in @($ServiceScript, $UserScript)) {
    if (-not (Test-Path $f)) { Write-Err "파일 없음: $f" }
}

Write-Step "AgentDir  : $AgentDir"
Write-Step "PythonExe : $PythonExe"
Write-Step "PythonWExe: $PythonWExe"

# ── 런타임 의존성 확인 ────────────────────────────────────────────────────────
# 설치 스크립트는 선택한 Python 환경을 임의로 변경하지 않는다. 누락된 모듈은
# 프로젝트 전용 venv에 requirements.txt를 설치한 뒤 다시 실행해야 한다.

Write-Step "Host Agent 런타임 의존성 확인"
$moduleNames = "requests,yaml,win32api,win32clipboard,win32con,win32file,win32gui,win32process,win32serviceutil,pythoncom,win32com,docx,fitz,openpyxl,pptx,striprtf,olefile,mitmproxy,aiosmtpd,aiosmtplib"
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
# 1. Windows 서비스 등록 (SentryDLPService)
# ════════════════════════════════════════════════════════════════════════════════

if ($InstallSystemService) {
    $programFilesRoot = (Resolve-Path $env:ProgramFiles).Path.TrimEnd('\') + '\'
    if (-not $AgentDir.StartsWith($programFilesRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Err "LocalSystem 서비스는 관리자 보호 경로에서만 설치할 수 있습니다. AgentDir을 $programFilesRoot 아래로 복사하고 ACL을 확인하세요."
    }
    if (-not $PythonExe.StartsWith($programFilesRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Err "LocalSystem 서비스용 Python도 관리자 보호 경로에 있어야 합니다: $programFilesRoot"
    }

    Write-Step "Windows 서비스 등록: $ServiceName"

    # 기존 서비스 제거 후 marked-for-deletion 상태가 끝날 때까지 제한 시간 대기
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        sc.exe stop $ServiceName 2>$null | Out-Null
        $existing = $null
        sc.exe delete $ServiceName 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Err "기존 서비스 삭제 요청 실패: sc.exe exit $LASTEXITCODE"
        }
        $deleteDeadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 500
            $remainingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        } while ($remainingService -and [DateTime]::UtcNow -lt $deleteDeadline)
        if ($remainingService) {
            Write-Err "기존 서비스가 20초 안에 삭제되지 않았습니다. 관련 서비스 관리 창을 닫고 다시 실행하세요."
        }
        Write-Warn "기존 서비스 제거 완료"
    }

    # 서비스 설치 (pywin32 방식)
    & $PythonExe $ServiceScript --startup=auto install 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Err "서비스 설치 실패. 로그를 확인하세요."
    }

# ── 크래시 복구 설정 (첫 번째·두 번째 실패 → 1분 후 재시작, 이후 → 5분) ────

    sc.exe failure $ServiceName reset= 86400 `
        actions= restart/60000/restart/60000/restart/300000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "서비스 크래시 재시작 정책 설정 실패: sc.exe exit $LASTEXITCODE"
    }
    Write-OK "크래시 재시작 정책 설정 완료"

# ── 서비스 시작 ────────────────────────────────────────────────────────────────

Write-Step "서비스 시작"
    sc.exe start $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "서비스 시작 요청 실패: sc.exe exit $LASTEXITCODE"
    }
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq "Running") {
        Write-OK "서비스 실행 중 ✓"
    } else {
        Write-Err "서비스 상태: $($svc.Status) — 로그를 확인하세요: $AgentDir\logs\service.log"
    }
} else {
    Write-Warn "발표용 기본 설정: SMTP/HTTP LocalSystem 서비스 설치를 건너뜁니다."
    Write-Warn "필요하면 보호된 Program Files 배포본에서 -InstallSystemService를 명시하세요."
}

# ════════════════════════════════════════════════════════════════════════════════
# 2. Task Scheduler 작업 등록 (SentryUserAgent)
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

if ($ForCurrentUserOnly) {
    $principal = New-ScheduledTaskPrincipal `
        -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
        -LogonType Interactive `
        -RunLevel Limited
} else {
    $principal = New-ScheduledTaskPrincipal `
        -GroupId "BUILTIN\Users" `
        -RunLevel Limited
}

$settings = New-ScheduledTaskSettingsSet `
    -Hidden `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
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
if ($InstallSystemService) {
    Write-Host "  서비스 : $ServiceName (자동 시작, 크래시 재시작)"
} else {
    Write-Host "  서비스 : 미설치 (SMTP/HTTP 시스템 채널 제외)"
}
Write-Host "  작업   : $TaskName (로그온 트리거)"
Write-Host "  로그   : $AgentDir\logs\"
Write-Host ""
Write-Host "설정 변경 후 사용하는 실행 계층을 재시작하세요:"
if ($InstallSystemService) {
    Write-Host "  시스템 채널(SMTP/HTTP): sc.exe stop $ServiceName; sc.exe start $ServiceName"
}
Write-Host "  사용자 채널(Clipboard/Outlook/FileGuard/WebProxy):"
Write-Host "    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "    Start-ScheduledTask -TaskName $TaskName"
Write-Host "  재시작 후 logs\user_agent.log에서 실제 채널 시작 상태를 확인하세요."
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
