"""Read-only Windows presentation readiness check for Sentry Host Agent."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODEL_VERSION = "koelectra-dlp-v7"
STRUCTURED_FILE_MODULES = {
    "DOCX": "docx",
    "PDF": "fitz",
    "XLSX": "openpyxl",
    "PPTX": "pptx",
    "RTF": "striprtf",
    "HWP": "olefile",
}
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core_comm.drive_baseline import LOCAL_BASELINE_PATH, load_internal_drives


@dataclass(frozen=True)
class Check:
    name: str
    ready: bool
    detail: str


def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError):
        return False


def _valid_base_url(value: Any, *, require_remote: bool) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlparse(value.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return False
    if not require_remote:
        return True

    host = parsed.hostname.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not (address.is_loopback or address.is_unspecified)


def _get_json(
    url: str,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    response = requests.get(url, timeout=timeout, headers=headers)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("JSON object expected")
    return data


def _outlook_running() -> bool:
    try:
        import win32com.client

        win32com.client.GetActiveObject("Outlook.Application")
        return True
    except Exception:
        return False


def _proxy_status(expected_port: int) -> tuple[bool, bool]:
    try:
        import winreg

        from network_hook.proxy_cert import ProxyCert

        proxy = ProxyCert()
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_READ,
        ) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        expected = f"127.0.0.1:{expected_port}"
        return proxy.is_installed(), bool(enabled) and str(server).strip() == expected
    except Exception:
        return False, False


def _powershell_boolean(script: str, timeout: float = 5.0) -> bool:
    """Run one fixed read-only Windows PowerShell check and parse its boolean output."""
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        lines = [line.strip().lower() for line in result.stdout.splitlines() if line.strip()]
        return result.returncode == 0 and bool(lines) and lines[-1] == "true"
    except Exception:
        return False


def _user_agent_task_running() -> bool:
    return _powershell_boolean(
        "$task = Get-ScheduledTask -TaskName 'SentryUserAgent' -ErrorAction Stop; "
        "Write-Output ([bool]($task.State -eq 'Running'))"
    )


def _proxy_listener_running(port: int) -> bool:
    if not 1 <= port <= 65535:
        return False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.75):
            return True
    except OSError:
        return False


def _quic_firewall_rule_active() -> bool:
    return _powershell_boolean(
        "$rules = @(Get-NetFirewallRule -DisplayName 'SentryDLP - Block QUIC UDP 443' "
        "-ErrorAction Stop | Where-Object { $_.Enabled -eq 'True' -and "
        "$_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }); "
        "$ok = $false; foreach ($rule in $rules) { "
        "$ports = @($rule | Get-NetFirewallPortFilter); "
        "if ($ports | Where-Object { ($_.Protocol -eq 'UDP' -or $_.Protocol -eq 17) "
        "-and $_.RemotePort -eq '443' }) { $ok = $true } }; Write-Output $ok"
    )


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}은 JSON object여야 합니다")
    return data


def _section(mapping: dict[str, Any], name: str) -> dict[str, Any]:
    value = mapping.get(name)
    return value if isinstance(value, dict) else {}


def _channel_check(name: str, requirements: list[tuple[bool, str]]) -> Check:
    missing = [label for ready, label in requirements if not ready]
    return Check(
        name,
        not missing,
        "준비됨" if not missing else "필요: " + ", ".join(missing),
    )


def collect_checks(project_root: Path = PROJECT_ROOT) -> list[Check]:
    """Inspect configuration and runtime prerequisites without changing them."""
    scenario_names = ["CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE"]
    try:
        settings = yaml.safe_load(
            (project_root / "config" / "settings.yaml").read_text(encoding="utf-8")
        )
        policy = _load_json(project_root / "config" / "channel_policy.json")
        paste_policy = _load_json(project_root / "config" / "paste_policy.json")
        patterns = _load_json(project_root / "config" / "regex_patterns.json")
        if not isinstance(settings, dict):
            raise ValueError("settings.yaml은 mapping이어야 합니다")
    except Exception as exc:
        detail = f"설정 로드 실패: {type(exc).__name__}"
        return [Check("CONFIG", False, detail)] + [Check(name, False, detail) for name in scenario_names]

    server = _section(settings, "server")
    logging_cfg = _section(settings, "logging")
    ai_url = server.get("ai_base_url", "")
    dashboard_url = server.get("dashboard_url", "")
    token = server.get("dashboard_token", "")
    send_immediately = logging_cfg.get("send_immediately") is True
    try:
        timeout = max(0.5, min(float(server.get("request_timeout_sec", 10)), 15.0))
    except (TypeError, ValueError):
        timeout = 10.0

    ai_url_ok = _valid_base_url(ai_url, require_remote=False)
    dashboard_url_ok = _valid_base_url(dashboard_url, require_remote=True)
    token_ok = isinstance(token, str) and bool(token.strip())

    ai_online = False
    ai_detail = "실제 AI URL이 필요합니다(mock 모드 불가)"
    if ai_url_ok:
        try:
            health = _get_json(ai_url.rstrip("/") + "/", timeout)
            reported_model = health.get("model_version") or health.get("engine")
            ai_online = (
                health.get("status") == "running"
                and reported_model == EXPECTED_MODEL_VERSION
            )
            if health.get("status") != "running":
                ai_detail = "AI 서버는 응답했지만 모델이 준비되지 않음"
            elif reported_model != EXPECTED_MODEL_VERSION:
                ai_detail = (
                    f"모델 버전 불일치(필요: {EXPECTED_MODEL_VERSION}, "
                    f"응답: {str(reported_model)[:100] or '없음'})"
                )
            else:
                ai_detail = f"모델 준비됨 ({EXPECTED_MODEL_VERSION})"
        except Exception as exc:
            ai_detail = f"AI 연결 실패: {type(exc).__name__}"

    dashboard_online = False
    dashboard_detail = "Windows PC에서 접속 가능한 원격 URL이 필요합니다"
    if dashboard_url_ok:
        try:
            health = _get_json(dashboard_url.rstrip("/") + "/health", timeout)
            dashboard_online = health.get("status") == "ok"
            dashboard_detail = "원격 대시보드 연결됨" if dashboard_online else "대시보드 health 응답 이상"
        except Exception as exc:
            dashboard_detail = f"대시보드 연결 실패: {type(exc).__name__}"

    dashboard_token_verified = False
    dashboard_token_detail = "dashboard_token이 비어 있음"
    if token_ok and dashboard_url_ok and dashboard_online:
        try:
            agent_check = _get_json(
                dashboard_url.rstrip("/") + "/api/v1/agent-check",
                timeout,
                headers={"X-Agent-Token": token.strip()},
            )
            dashboard_token_verified = (
                agent_check.get("status") == "ok"
                and agent_check.get("agent_token") == "accepted"
            )
            dashboard_token_detail = (
                "Web R009 인증 확인됨(값은 출력하지 않음)"
                if dashboard_token_verified
                else "Web Agent 인증 확인 응답 이상"
            )
        except Exception as exc:
            dashboard_token_detail = f"Web Agent 인증 실패: {type(exc).__name__}"
    elif token_ok:
        dashboard_token_detail = "대시보드 연결 후 토큰 일치 확인 필요"

    checks = [
        Check("AI_SERVER", ai_url_ok and ai_online, ai_detail),
        Check("DASHBOARD", dashboard_url_ok and dashboard_online, dashboard_detail),
        Check(
            "DASHBOARD_TOKEN",
            dashboard_token_verified,
            dashboard_token_detail,
        ),
        Check(
            "SEND_IMMEDIATELY",
            send_immediately,
            "탐지 즉시 전송" if send_immediately else "logging.send_immediately: true가 필요함",
        ),
    ]

    baseline_ok = False
    baseline_detail = "로컬 기준 없음"
    try:
        drives = load_internal_drives(project_root / "config" / LOCAL_BASELINE_PATH.name)
        baseline_ok = True
        baseline_detail = f"로컬 기준 정상({len(drives)}개 드라이브)"
    except Exception as exc:
        baseline_detail = f"사용 불가: {type(exc).__name__}; install/setup_agent.ps1 재실행 필요"
    checks.append(Check("LOCAL_DRIVE_BASELINE", baseline_ok, baseline_detail))

    windows = sys.platform == "win32"
    user_agent_running = windows and _user_agent_task_running()
    checks.append(
        Check(
            "USER_AGENT_TASK",
            user_agent_running,
            "SentryUserAgent 예약 작업 실행 중"
            if user_agent_running
            else "SentryUserAgent 예약 작업 State=Running 필요",
        )
    )
    clipboard_win32 = all(
        _module_available(name)
        for name in ("win32api", "win32clipboard", "win32con", "win32gui", "win32process")
    )
    usb_win32 = all(_module_available(name) for name in ("win32api", "win32con", "win32file"))
    outlook_win32 = all(_module_available(name) for name in ("pythoncom", "win32com.client"))
    mitmproxy = _module_available("mitmproxy")
    missing_file_modules = [
        label
        for label, module in STRUCTURED_FILE_MODULES.items()
        if not _module_available(module)
    ]
    structured_files_ready = not missing_file_modules
    checks.append(
        Check(
            "FILE_EXTRACTORS",
            structured_files_ready,
            "구조화 파일 추출 모듈 준비됨"
            if structured_files_ready
            else "누락: " + ", ".join(missing_file_modules) + "; requirements.txt 설치 필요",
        )
    )
    regex_ready = isinstance(patterns.get("patterns"), list) and bool(patterns["patterns"])
    inspect_list_ready = (
        isinstance(paste_policy.get("inspect_list"), list) and bool(paste_policy["inspect_list"])
    )
    common = (
        ai_url_ok
        and ai_online
        and dashboard_url_ok
        and dashboard_online
        and dashboard_token_verified
        and send_immediately
    )

    outlook_cfg = _section(policy, "outlook")
    file_guard_cfg = _section(policy, "file_guard")
    outlook_enabled = outlook_cfg.get("enabled") is True
    outlook_active = windows and outlook_win32 and outlook_enabled and _outlook_running()
    web_cfg = _section(policy, "web_proxy")
    web_enabled = web_cfg.get("enabled") is True
    try:
        proxy_port = int(web_cfg.get("proxy_port", 8082))
    except (TypeError, ValueError):
        proxy_port = 0
    cert_ready, proxy_ready = (
        _proxy_status(proxy_port)
        if windows and web_enabled and mitmproxy and 1 <= proxy_port <= 65535
        else (False, False)
    )
    proxy_listener_ready = (
        windows and web_enabled and _proxy_listener_running(proxy_port)
    )
    quic_rule_ready = windows and web_enabled and _quic_firewall_rule_active()
    checks.extend(
        [
            Check(
                "WEB_PROXY_LISTENER",
                proxy_listener_ready,
                f"127.0.0.1:{proxy_port} 리스닝 확인"
                if proxy_listener_ready
                else f"127.0.0.1:{proxy_port} 프록시 리스너 필요",
            ),
            Check(
                "QUIC_FIREWALL",
                quic_rule_ready,
                "Outbound UDP/443 차단 규칙 활성"
                if quic_rule_ready
                else "SentryDLP QUIC Outbound UDP/443 차단 규칙 필요",
            ),
        ]
    )

    checks.extend(
        [
            _channel_check(
                "CLIPBOARD",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
                    (user_agent_running, "실행 중인 SentryUserAgent"),
                    (clipboard_win32, "pywin32 클립보드 모듈"),
                    (regex_ready, "regex_patterns"),
                    (inspect_list_ready, "paste_policy.inspect_list"),
                ],
            ),
            _channel_check(
                "USB_COPY",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
                    (user_agent_running, "실행 중인 SentryUserAgent"),
                    (usb_win32, "pywin32 USB 모듈"),
                    (structured_files_ready, "구조화 파일 추출 모듈"),
                    (regex_ready, "regex_patterns"),
                    (file_guard_cfg.get("enabled") is True, "file_guard.enabled"),
                    (baseline_ok, "internal_drives.local.json"),
                ],
            ),
            _channel_check(
                "EMAIL_ATTACHMENT",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
                    (user_agent_running, "실행 중인 SentryUserAgent"),
                    (outlook_win32, "pywin32 Outlook 모듈"),
                    (structured_files_ready, "구조화 파일 추출 모듈"),
                    (outlook_enabled, "outlook.enabled"),
                    (outlook_active, "실행 중인 Outlook"),
                ],
            ),
            _channel_check(
                "WEB_UPLOAD",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
                    (user_agent_running, "실행 중인 SentryUserAgent"),
                    (web_enabled, "web_proxy.enabled"),
                    (mitmproxy, "mitmproxy"),
                    (structured_files_ready, "구조화 파일 추출 모듈"),
                    (cert_ready, "mitmproxy CA"),
                    (proxy_ready, "Windows 시스템 프록시"),
                    (proxy_listener_ready, "실행 중인 WebProxy 리스너"),
                    (quic_rule_ready, "QUIC Outbound UDP/443 차단 규칙"),
                    (
                        isinstance(web_cfg.get("inspect_domains"), list)
                        and bool(web_cfg["inspect_domains"]),
                        "inspect_domains",
                    ),
                ],
            ),
            _channel_check(
                "CLOUD_DRIVE",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
                    (user_agent_running, "실행 중인 SentryUserAgent"),
                    (web_enabled, "web_proxy.enabled"),
                    (mitmproxy, "mitmproxy"),
                    (structured_files_ready, "구조화 파일 추출 모듈"),
                    (cert_ready, "mitmproxy CA"),
                    (proxy_ready, "Windows 시스템 프록시"),
                    (proxy_listener_ready, "실행 중인 WebProxy 리스너"),
                    (quic_rule_ready, "QUIC Outbound UDP/443 차단 규칙"),
                    (
                        isinstance(web_cfg.get("drive_domains"), list)
                        and bool(web_cfg["drive_domains"]),
                        "drive_domains",
                    ),
                    (
                        isinstance(web_cfg.get("drive_upload_patterns"), list)
                        and bool(web_cfg["drive_upload_patterns"]),
                        "drive_upload_patterns",
                    ),
                ],
            ),
        ]
    )
    return checks


def main() -> int:
    checks = collect_checks()
    print("Sentry Host Agent 시연 사전 점검(읽기 전용)")
    for check in checks:
        print(f"[{'PASS' if check.ready else 'FAIL'}] {check.name}: {check.detail}")
    print("[INFO] MESSENGER: 독립 훅이 아니라 메신저 프로세스의 Ctrl+V를 CLIPBOARD 채널로 검사합니다.")
    print("[INFO] PRINT: 현재 Host Agent에서 지원하지 않습니다.")
    print(
        f"[INFO] PREFLIGHT_SCOPE: exit 0은 {EXPECTED_MODEL_VERSION}과 로컬 준비 조건을 확인한 결과이며, "
        "실제 Windows 채널 E2E 완료 증거가 아닙니다."
    )
    print("[INFO] DASHBOARD_TOKEN: Web R009 보호 API로 값의 일치를 확인하며 토큰 자체는 출력하지 않습니다.")
    print(
        "[INFO] PROXY_RUNTIME: CA·레지스트리·로컬 TCP 리스너·Outbound UDP/443 "
        "QUIC 차단 규칙을 자동 확인합니다. 실제 브라우저 업로드 요청은 별도로 시연하세요."
    )
    print(
        "[INFO] USB_SAFETY: FIXED 외장 저장장치를 제거해 기준을 만들고, 내장 드라이브나 문자가 바뀌면 "
        "기준을 다시 생성하세요. BLOCK은 대상 파일 사후 삭제이므로 실제 삭제 성공을 별도로 확인해야 합니다."
    )

    scenario_names = {"CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE"}
    return 0 if all(check.ready for check in checks if check.name in scenario_names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
