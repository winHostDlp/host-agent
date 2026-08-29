# Sentry Host Agent - HTTPS MITM proxy setup
# Must run as Administrator (for Root CA install).
#
# Steps:
#   0) verify mitmproxy in the selected project virtual environment
#   1) generate mitmproxy CA if missing
#   2) trust CA in Windows Root store
#   3) set system proxy 127.0.0.1:<Port>
#
# Example:
#   .\install\setup_proxy.ps1 -Port 8082

param(
    [int]    $Port      = 8082,
    [string] $PythonExe = (Join-Path (Split-Path $PSScriptRoot -Parent) ".venv\Scripts\python.exe")
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([int]$N, [string]$Msg)
    Write-Host ""
    Write-Host "[$N] $Msg" -ForegroundColor Cyan
}
function Write-OK {
    param([string]$Msg)
    Write-Host "    OK  $Msg" -ForegroundColor Green
}
function Write-Warn {
    param([string]$Msg)
    Write-Host "    WARN  $Msg" -ForegroundColor Yellow
}
function Write-Err {
    param([string]$Msg)
    Write-Host "    ERR  $Msg" -ForegroundColor Red
}

function Notify-ProxyChange {
    $code = @'
using System;
using System.Runtime.InteropServices;
public class SentryWinINet {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);
    public static void NotifyChange() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
'@
    try {
        if (-not ([System.Management.Automation.PSTypeName]"SentryWinINet").Type) {
            Add-Type -TypeDefinition $code
        }
        [SentryWinINet]::NotifyChange()
    } catch {
        # optional - browsers pick up registry on restart
    }
}

# Preserve a caller-provided relative venv path across UAC's working-directory change.
if (-not [System.IO.Path]::IsPathRooted($PythonExe)) {
    $PythonExe = [System.IO.Path]::GetFullPath(
        (Join-Path (Get-Location).Path $PythonExe)
    )
} elseif (Test-Path -LiteralPath $PythonExe -PathType Leaf) {
    $PythonExe = (Resolve-Path -LiteralPath $PythonExe).Path
}

# --- Admin check (auto-elevate via UAC prompt) ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges (UAC)..." -ForegroundColor Yellow
    $argList = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$PSCommandPath`""
        "-Port", "$Port"
        "-PythonExe", "`"$PythonExe`""
    )
    try {
        $p = Start-Process -FilePath "powershell.exe" `
            -Verb RunAs `
            -ArgumentList $argList `
            -WorkingDirectory (Split-Path $PSCommandPath -Parent) `
            -PassThru -Wait
        exit $p.ExitCode
    } catch {
        Write-Err "UAC elevation was cancelled or failed."
        Write-Host "  Right-click PowerShell -> Run as administrator, then re-run this script."
        exit 1
    }
}

# --- 0. project virtual environment / mitmproxy ---
Write-Step 0 "Check project virtual environment and mitmproxy"
if (-not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
    Write-Err "Project Python not found: $PythonExe"
    Write-Host "  Create .venv and install requirements before running this script."
    exit 1
}
$mitmdumpPath = Join-Path (Split-Path $PythonExe -Parent) "mitmdump.exe"
if (-not (Test-Path -LiteralPath $mitmdumpPath -PathType Leaf)) {
    Write-Err "mitmdump.exe is not installed in the selected Python environment."
    Write-Host "  Run: & `"$PythonExe`" -m pip install -r requirements.txt"
    exit 1
}
& $PythonExe -c "import mitmproxy" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Err "The selected Python environment cannot import mitmproxy."
    exit 1
}
Write-OK "mitmproxy verified: $mitmdumpPath"

# --- 1. CA generate ---
Write-Step 1 "Generate mitmproxy CA certificate"

$mitmDir  = Join-Path $env:USERPROFILE ".mitmproxy"
$certFile = Join-Path $mitmDir "mitmproxy-ca-cert.cer"
$pemFile  = Join-Path $mitmDir "mitmproxy-ca-cert.pem"

if (Test-Path $certFile) {
    Write-OK "CA already exists: $certFile"
} else {
    Write-Host "    Running mitmdump briefly to create CA (wait 5 sec)..."
    $proc = Start-Process -FilePath $mitmdumpPath `
        -ArgumentList @("--mode", "regular", "--set", "termlog_verbosity=warn") `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 5
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $certFile) {
        Write-OK "CA created: $certFile"
    } elseif (Test-Path $pemFile) {
        # Prefer certutil -encodepem / DER for store. mitmproxy ships .cer already usually.
        # Convert PEM to CER-ish: certutil -encode is base64; use -addstore on .pem can work if PEM.
        Copy-Item $pemFile $certFile -Force
        Write-OK "Using PEM as CER path: $certFile"
    } else {
        Write-Err "CA file not created. Check folder: $mitmDir"
        exit 1
    }
}

# Prefer .pem for certutil if .cer is missing or broken
$storeCert = $certFile
if (-not (Test-Path $storeCert) -and (Test-Path $pemFile)) {
    $storeCert = $pemFile
}

# --- 2. Trust CA ---
Write-Step 2 "Install CA into Windows Root store"

$existing = & certutil -verifystore Root "mitmproxy" 2>&1 | Out-String
if ($existing -match "mitmproxy") {
    Write-OK "CA already in Root store"
} else {
    & certutil -addstore Root $storeCert
    if ($LASTEXITCODE -ne 0) {
        Write-Err "certutil -addstore failed. Check admin rights."
        exit 1
    }
    Write-OK "CA installed into Root store"
}

# --- 3. System proxy (HKCU) ---
Write-Step 3 "Set system proxy to 127.0.0.1:$Port"

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regPath -Name "ProxyEnable"   -Value 1
Set-ItemProperty -Path $regPath -Name "ProxyServer"   -Value "127.0.0.1:$Port"
Set-ItemProperty -Path $regPath -Name "ProxyOverride" -Value "localhost;127.0.0.1;<local>"
Notify-ProxyChange
Write-OK "Proxy enabled for Chrome/Edge (WinINet)"

# --- 4. Block QUIC (UDP 443) via Windows Firewall ---
# Chrome 104+ ignores the QuicAllowed=0 policy. QUIC uses UDP port 443 to bypass TCP proxies.
# Blocking outbound UDP 443 forces Chrome/Edge to fall back to HTTPS/TCP -> routed through proxy.
Write-Step 4 "Block QUIC (UDP 443) via Windows Firewall to force HTTPS/TCP through proxy"

$ruleName = "SentryDLP - Block QUIC UDP 443"
$existing = netsh advfirewall firewall show rule name=$ruleName 2>&1 | Out-String
if ($existing -match "규칙 이름|Rule Name") {
    Write-OK "Firewall rule already exists: $ruleName"
} else {
    netsh advfirewall firewall add rule `
        name=$ruleName `
        protocol=UDP `
        dir=out `
        remoteport=443 `
        action=block | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Firewall rule added: Block outbound UDP 443 (QUIC)"
    } else {
        Write-Warn "Failed to add firewall rule. Chrome may still use QUIC."
    }
}
Write-Host "    NOTE: Restart Chrome/Edge for this to take effect."

# --- 5. Firefox note ---
Write-Step 5 "Firefox note"
Write-Warn "Firefox uses its own cert store. Import CA manually if needed:"
Write-Host "    Cert file: $storeCert"
Write-Host "    about:preferences#privacy -> Certificates -> Authorities -> Import"
Write-Host "    about:preferences#general  -> Network Settings -> Manual proxy 127.0.0.1:$Port"
Write-Host "    To disable QUIC in Firefox: about:config -> network.http.http3.enabled = false"

# --- 6. Done ---
Write-Step 6 "Next"
Write-Host "    web_proxy is enabled in config\channel_policy.json"
Write-Host "    Start agent: python main_agent.py"
Write-Host "    Then test: upload a file to Google Drive / Gmail"
Write-Host ""
Write-OK "Setup complete. Restart Chrome/Edge before testing."
