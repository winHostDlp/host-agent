"""Read-only Windows presentation readiness check for Sentry Host Agent."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
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


def _get_json(url: str, timeout: float) -> dict[str, Any]:
    response = requests.get(url, timeout=timeout)
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
            ai_online = health.get("status") == "running" and bool(health.get("engine"))
            ai_detail = (
                f"모델 준비됨 ({health.get('engine')})"
                if ai_online
                else "AI 서버는 응답했지만 모델이 준비되지 않음"
            )
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

    checks = [
        Check("AI_SERVER", ai_url_ok and ai_online, ai_detail),
        Check("DASHBOARD", dashboard_url_ok and dashboard_online, dashboard_detail),
        Check(
            "DASHBOARD_TOKEN",
            token_ok,
            "설정됨(값은 출력하지 않음; 서버 일치 여부는 실제 이벤트로 확인)"
            if token_ok
            else "dashboard_token이 비어 있음",
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
    clipboard_win32 = all(
        _module_available(name)
        for name in ("win32api", "win32clipboard", "win32con", "win32gui", "win32process")
    )
    usb_win32 = all(_module_available(name) for name in ("win32api", "win32con", "win32file"))
    outlook_win32 = all(_module_available(name) for name in ("pythoncom", "win32com.client"))
    mitmproxy = _module_available("mitmproxy")
    regex_ready = isinstance(patterns.get("patterns"), list) and bool(patterns["patterns"])
    inspect_list_ready = (
        isinstance(paste_policy.get("inspect_list"), list) and bool(paste_policy["inspect_list"])
    )
    common = ai_url_ok and ai_online and dashboard_url_ok and dashboard_online and token_ok and send_immediately

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

    checks.extend(
        [
            _channel_check(
                "CLIPBOARD",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
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
                    (usb_win32, "pywin32 USB 모듈"),
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
                    (outlook_win32, "pywin32 Outlook 모듈"),
                    (outlook_enabled, "outlook.enabled"),
                    (outlook_active, "실행 중인 Outlook"),
                ],
            ),
            _channel_check(
                "WEB_UPLOAD",
                [
                    (common, "AI·대시보드 연결"),
                    (windows, "Windows 실행"),
                    (web_enabled, "web_proxy.enabled"),
                    (mitmproxy, "mitmproxy"),
                    (cert_ready, "mitmproxy CA"),
                    (proxy_ready, "Windows 시스템 프록시"),
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
                    (web_enabled, "web_proxy.enabled"),
                    (mitmproxy, "mitmproxy"),
                    (cert_ready, "mitmproxy CA"),
                    (proxy_ready, "Windows 시스템 프록시"),
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

    scenario_names = {"CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE"}
    return 0 if all(check.ready for check in checks if check.name in scenario_names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
