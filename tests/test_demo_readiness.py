from __future__ import annotations

import importlib.util
import json
import sys
import threading
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest
import yaml

from core_comm.drive_baseline import DriveBaselineError, load_internal_drives
from scripts import demo_preflight


def test_drive_baseline_is_machine_local_and_requires_system_drive(tmp_path, monkeypatch):
    monkeypatch.setenv("SystemDrive", "C:")
    local = tmp_path / "internal_drives.local.json"
    local.write_text(json.dumps({"internal_drives": ["c:", "D:"]}), encoding="utf-8")

    assert load_internal_drives(local) == {"C:", "D:"}

    local.write_text(json.dumps({"internal_drives": ["D:"]}), encoding="utf-8")
    with pytest.raises(DriveBaselineError, match="시스템 드라이브 C:"):
        load_internal_drives(local)


def test_legacy_tracked_baseline_is_never_used(tmp_path, monkeypatch):
    monkeypatch.setenv("SystemDrive", "C:")
    (tmp_path / "internal_drives.json").write_text(
        json.dumps({"internal_drives": ["C:"]}), encoding="utf-8"
    )

    with pytest.raises(DriveBaselineError, match="setup_agent.ps1"):
        load_internal_drives(tmp_path / "internal_drives.local.json")


def test_drive_baseline_refuses_when_system_drive_is_unknown(tmp_path, monkeypatch):
    monkeypatch.delenv("SystemDrive", raising=False)
    local = tmp_path / "internal_drives.local.json"
    local.write_text(json.dumps({"internal_drives": ["C:"]}), encoding="utf-8")

    with pytest.raises(DriveBaselineError, match="SystemDrive"):
        load_internal_drives(local)


def test_setup_agent_is_ps51_safe_and_starts_registered_user_task():
    setup = (
        Path(__file__).resolve().parents[1] / "install" / "setup_agent.ps1"
    ).read_text(encoding="utf-8")

    assert "?.Source" not in setup
    assert "pip install pywin32" not in setup
    assert "requirements.txt" in setup
    assert "Start-ScheduledTask -TaskName $TaskName" in setup
    assert "Start-Process -FilePath $PythonExe" not in setup
    assert "Stop-ScheduledTask -TaskName $TaskName" in setup
    assert "[bool]  $ForCurrentUserOnly = $true" in setup
    assert "[switch]$InstallSystemService" in setup
    assert "-Execute $PythonWExe" in setup
    assert "-RunLevel Limited" in setup
    assert "-RunLevel Highest" not in setup
    assert "-AllowStartIfOnBatteries" in setup
    assert "-DontStopIfGoingOnBatteries" in setup
    assert "marked-for-deletion" in setup
    assert '$ErrorActionPreference = "Stop"' in setup


def _load_usb_guard_with_win32_stubs(monkeypatch):
    win32api = ModuleType("win32api")
    win32con = ModuleType("win32con")
    win32file = ModuleType("win32file")
    win32con.DRIVE_REMOVABLE = 2
    win32con.DRIVE_FIXED = 3
    monkeypatch.setitem(sys.modules, "win32api", win32api)
    monkeypatch.setitem(sys.modules, "win32con", win32con)
    monkeypatch.setitem(sys.modules, "win32file", win32file)

    module_path = Path(__file__).resolve().parents[1] / "usb_minifilter" / "usb_guard_usermode.py"
    spec = importlib.util.spec_from_file_location("usb_guard_readiness_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_file_guard_refuses_to_construct_without_safe_baseline(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    monkeypatch.setattr(
        usb_guard,
        "load_internal_drives",
        Mock(side_effect=DriveBaselineError("setup_agent.ps1 재실행")),
    )

    with pytest.raises(DriveBaselineError, match="setup_agent.ps1"):
        usb_guard.UsbGuardUserMode(
            rule_filter=Mock(),
            payload_builder=Mock(),
            api_client=Mock(),
            event_logger=Mock(),
            file_inspector=Mock(),
        )


def _write_ready_project(root: Path, token: str) -> None:
    config = root / "config"
    config.mkdir()
    (config / "settings.yaml").write_text(
        yaml.safe_dump(
            {
                "server": {
                    "ai_base_url": "https://ai.example",
                    "dashboard_url": "http://192.168.0.39:8000",
                    "dashboard_token": token,
                    "request_timeout_sec": 2,
                },
                "logging": {"send_immediately": True},
            }
        ),
        encoding="utf-8",
    )
    (config / "channel_policy.json").write_text(
        json.dumps(
            {
                "outlook": {"enabled": True},
                "file_guard": {"enabled": True},
                "web_proxy": {
                    "enabled": True,
                    "inspect_domains": ["mail.example"],
                    "drive_domains": ["drive.example"],
                    "drive_upload_patterns": ["/upload"],
                },
            }
        ),
        encoding="utf-8",
    )
    (config / "paste_policy.json").write_text(
        json.dumps({"inspect_list": ["chrome.exe"]}), encoding="utf-8"
    )
    (config / "regex_patterns.json").write_text(
        json.dumps({"patterns": [{"id": "rrn", "regex": "[0-9]+"}]}), encoding="utf-8"
    )
    (config / "internal_drives.local.json").write_text(
        json.dumps({"internal_drives": ["C:"]}), encoding="utf-8"
    )


class _Response:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _mock_user_runtime(
    monkeypatch,
    *,
    task: bool = True,
    listener: bool = True,
    quic: bool = True,
) -> None:
    monkeypatch.setattr(demo_preflight, "_user_agent_task_running", lambda: task)
    monkeypatch.setattr(demo_preflight, "_proxy_listener_running", lambda port: listener)
    monkeypatch.setattr(demo_preflight, "_quic_firewall_rule_active", lambda: quic)


def test_preflight_reports_all_implemented_scenarios_without_exposing_token(
    tmp_path, monkeypatch
):
    token = "do-not-print-this-token"
    _write_ready_project(tmp_path, token)
    monkeypatch.setenv("SystemDrive", "C:")
    monkeypatch.setattr(demo_preflight.sys, "platform", "win32")
    monkeypatch.setattr(demo_preflight, "_module_available", lambda name: True)
    monkeypatch.setattr(demo_preflight, "_proxy_status", lambda port: (True, True))
    monkeypatch.setattr(demo_preflight, "_outlook_running", lambda: True)
    _mock_user_runtime(monkeypatch)

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            assert headers is None
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "http://192.168.0.39:8000/health":
            assert headers is None
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            assert headers == {"X-Agent-Token": token}
            return _Response({"status": "ok", "agent_token": "accepted"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_get)

    checks = demo_preflight.collect_checks(tmp_path)
    scenarios = {
        check.name: check.ready
        for check in checks
        if check.name in {"CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE"}
    }

    assert scenarios == {
        "CLIPBOARD": True,
        "USB_COPY": True,
        "EMAIL_ATTACHMENT": True,
        "WEB_UPLOAD": True,
        "CLOUD_DRIVE": True,
    }
    assert token not in "\n".join(check.detail for check in checks)

    def fake_wrong_model_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v6"})
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            return _Response({"status": "ok", "agent_token": "accepted"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_wrong_model_get)
    wrong_model_checks = {
        check.name: check for check in demo_preflight.collect_checks(tmp_path)
    }
    assert wrong_model_checks["AI_SERVER"].ready is False
    assert "koelectra-dlp-v7" in wrong_model_checks["AI_SERVER"].detail
    assert all(
        wrong_model_checks[name].ready is False
        for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
    )


def test_preflight_rejects_dashboard_token_mismatch_without_exposing_token(
    tmp_path, monkeypatch
):
    token = "configured-but-rejected-token"
    _write_ready_project(tmp_path, token)
    monkeypatch.setenv("SystemDrive", "C:")
    monkeypatch.setattr(demo_preflight.sys, "platform", "win32")
    monkeypatch.setattr(demo_preflight, "_module_available", lambda name: True)
    monkeypatch.setattr(demo_preflight, "_proxy_status", lambda port: (True, True))
    monkeypatch.setattr(demo_preflight, "_outlook_running", lambda: True)
    _mock_user_runtime(monkeypatch)

    class _UnauthorizedResponse(_Response):
        def raise_for_status(self):
            raise RuntimeError("unauthorized")

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            assert headers == {"X-Agent-Token": token}
            return _UnauthorizedResponse({})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_get)
    checks = {check.name: check for check in demo_preflight.collect_checks(tmp_path)}

    assert checks["DASHBOARD_TOKEN"].ready is False
    assert token not in checks["DASHBOARD_TOKEN"].detail
    assert all(
        checks[name].ready is False
        for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
    )


def test_preflight_rejects_mock_ai_loopback_dashboard_and_missing_baseline(
    tmp_path, monkeypatch
):
    _write_ready_project(tmp_path, "configured-token")
    settings_path = tmp_path / "config" / "settings.yaml"
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    settings["server"]["ai_base_url"] = ""
    settings["server"]["dashboard_url"] = "http://127.0.0.1:8000"
    settings["logging"]["send_immediately"] = False
    settings_path.write_text(yaml.safe_dump(settings), encoding="utf-8")
    (tmp_path / "config" / "internal_drives.local.json").unlink()
    monkeypatch.setattr(demo_preflight.sys, "platform", "win32")
    _mock_user_runtime(monkeypatch, task=False, listener=False, quic=False)
    monkeypatch.setattr(
        demo_preflight.requests,
        "get",
        Mock(side_effect=AssertionError("invalid URLs must not be requested")),
    )

    checks = {check.name: check for check in demo_preflight.collect_checks(tmp_path)}

    assert checks["AI_SERVER"].ready is False
    assert checks["DASHBOARD"].ready is False
    assert checks["SEND_IMMEDIATELY"].ready is False
    assert checks["LOCAL_DRIVE_BASELINE"].ready is False
    assert all(
        checks[name].ready is False
        for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
    )


def test_preflight_requires_structured_file_extractors_for_file_scenarios(
    tmp_path, monkeypatch
):
    _write_ready_project(tmp_path, "configured-token")
    monkeypatch.setenv("SystemDrive", "C:")
    monkeypatch.setattr(demo_preflight.sys, "platform", "win32")
    monkeypatch.setattr(
        demo_preflight,
        "_module_available",
        lambda name: name != "docx",
    )
    monkeypatch.setattr(demo_preflight, "_proxy_status", lambda port: (True, True))
    monkeypatch.setattr(demo_preflight, "_outlook_running", lambda: True)
    _mock_user_runtime(monkeypatch)

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            return _Response({"status": "ok", "agent_token": "accepted"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_get)
    checks = {check.name: check for check in demo_preflight.collect_checks(tmp_path)}

    assert checks["FILE_EXTRACTORS"].ready is False
    assert "DOCX" in checks["FILE_EXTRACTORS"].detail
    assert checks["CLIPBOARD"].ready is True
    assert all(
        checks[name].ready is False
        for name in ("USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
    )


def test_preflight_requires_running_user_task_proxy_listener_and_quic_rule(
    tmp_path, monkeypatch
):
    token = "runtime-check-token"
    _write_ready_project(tmp_path, token)
    monkeypatch.setenv("SystemDrive", "C:")
    monkeypatch.setattr(demo_preflight.sys, "platform", "win32")
    monkeypatch.setattr(demo_preflight, "_module_available", lambda name: True)
    monkeypatch.setattr(demo_preflight, "_proxy_status", lambda port: (True, True))
    monkeypatch.setattr(demo_preflight, "_outlook_running", lambda: True)

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            return _Response({"status": "ok", "agent_token": "accepted"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_get)
    _mock_user_runtime(monkeypatch, task=False, listener=True, quic=True)
    task_stopped = {
        check.name: check for check in demo_preflight.collect_checks(tmp_path)
    }
    assert task_stopped["USER_AGENT_TASK"].ready is False
    assert all(
        task_stopped[name].ready is False
        for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
    )

    _mock_user_runtime(monkeypatch, task=True, listener=False, quic=False)
    proxy_stopped = {
        check.name: check for check in demo_preflight.collect_checks(tmp_path)
    }
    assert all(
        proxy_stopped[name].ready is True
        for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT")
    )
    assert proxy_stopped["WEB_PROXY_LISTENER"].ready is False
    assert proxy_stopped["QUIC_FIREWALL"].ready is False
    assert proxy_stopped["WEB_UPLOAD"].ready is False
    assert proxy_stopped["CLOUD_DRIVE"].ready is False


def _load_main_agent_without_windows_modules(monkeypatch):
    clipboard_package = ModuleType("clipboard_ctrl")
    clipboard_package.__path__ = []
    network_package = ModuleType("network_hook")
    network_package.__path__ = []
    monkeypatch.setitem(sys.modules, "clipboard_ctrl", clipboard_package)
    monkeypatch.setitem(sys.modules, "network_hook", network_package)

    stubs = {
        "clipboard_ctrl.clipboard_hook": {"ClipboardHook": object},
        "clipboard_ctrl.notifier": {
            "notify_blocked": lambda *args, **kwargs: None,
            "notify_review": lambda *args, **kwargs: None,
        },
        "clipboard_ctrl.paste_inspector": {"PasteInspector": object},
        "clipboard_ctrl.rule_filter": {"RuleFilter": object},
        "network_hook.file_inspector": {"FileInspector": object},
        "network_hook.proxy_cert": {"ProxyCert": object},
    }
    for module_name, attributes in stubs.items():
        module = ModuleType(module_name)
        for name, value in attributes.items():
            setattr(module, name, value)
        monkeypatch.setitem(sys.modules, module_name, module)

    module_path = Path(__file__).resolve().parents[1] / "main_agent.py"
    spec = importlib.util.spec_from_file_location("main_agent_signal_test", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_registers_process_signals_only_on_main_thread(monkeypatch):
    main_agent = _load_main_agent_without_windows_modules(monkeypatch)
    monkeypatch.setattr(main_agent, "load_settings", lambda: {"agent": {}})
    monkeypatch.setattr(main_agent, "load_channel_policy", lambda: {})
    monkeypatch.setattr(main_agent, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_agent, "RuleFilter", lambda path: object())
    monkeypatch.setattr(main_agent, "build_event_logger", lambda settings: object())
    monkeypatch.setattr(
        main_agent,
        "build_api_client",
        lambda settings: type("Api", (), {"is_mock": True})(),
    )
    monkeypatch.setattr(main_agent, "build_payload_builder", lambda settings: object())
    monkeypatch.setattr(main_agent, "FileInspector", lambda: object())
    monkeypatch.setattr(main_agent, "_start_channels", lambda *args: None)
    register_signal = Mock()
    monkeypatch.setattr(main_agent.signal, "signal", register_signal)

    stop_event = threading.Event()
    stop_event.set()
    errors = []

    def run_in_service_thread():
        try:
            main_agent.run(mode="system", stop_event=stop_event)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=run_in_service_thread)
    worker.start()
    worker.join(timeout=3)

    assert worker.is_alive() is False
    assert errors == []
    register_signal.assert_not_called()

    main_agent.run(mode="system", stop_event=stop_event)
    assert register_signal.call_count == 2


def test_preflight_output_marks_messenger_as_clipboard_and_print_unsupported(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        demo_preflight,
        "collect_checks",
        lambda: [
            demo_preflight.Check(name, True, "준비됨")
            for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
        ],
    )

    assert demo_preflight.main() == 0
    output = capsys.readouterr().out
    assert "MESSENGER: 독립 훅이 아니라" in output
    assert "CLIPBOARD 채널" in output
    assert "PRINT: 현재 Host Agent에서 지원하지 않습니다" in output
    assert "exit 0" in output
    assert "E2E 완료 증거가 아닙니다" in output
    assert "보호 API로 값의 일치를 확인" in output
    assert "로컬 TCP 리스너" in output
    assert "QUIC" in output
    assert "FIXED 외장 저장장치" in output
    assert "사후 삭제" in output
