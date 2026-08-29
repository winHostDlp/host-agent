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

from scripts import demo_preflight


def test_setup_agent_is_ps51_safe_and_requires_explicit_start():
    setup = (
        Path(__file__).resolve().parents[1] / "install" / "setup_agent.ps1"
    ).read_text(encoding="utf-8")

    assert "?.Source" not in setup
    assert "pip install pywin32" not in setup
    assert "requirements.txt" in setup
    assert "Start-ScheduledTask -TaskName $TaskName" in setup
    assert "[switch]$StartAgent" in setup
    assert "if ($StartAgent)" in setup
    assert "Disable-ScheduledTask -TaskName $TaskName" in setup
    assert '$task.State -ne "Disabled"' in setup
    assert "비활성화 확인 실패로 등록을 취소" in setup
    assert "Enable-ScheduledTask -TaskName $TaskName" in setup
    assert "Start-Process -FilePath $PythonExe" not in setup
    assert "Stop-ScheduledTask -TaskName $TaskName" in setup
    assert "-Execute $PythonWExe" in setup
    assert "-RunLevel Limited" in setup
    assert "-RunLevel Highest" not in setup
    assert "-AllowStartIfOnBatteries" in setup
    assert "-DontStopIfGoingOnBatteries" in setup
    assert "#Requires -RunAsAdministrator" not in setup
    assert "InstallSystemService" not in setup
    assert "SentryDLPService" not in setup
    assert "sc.exe" not in setup
    assert "GroupId" not in setup
    assert "win32serviceutil" not in setup
    assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in setup
    assert "-MultipleInstances IgnoreNew" in setup
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


def test_file_guard_monitors_removable_drives_but_never_fixed_drives(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    guard = usb_guard.UsbGuardUserMode(
        rule_filter=Mock(),
        payload_builder=Mock(),
        api_client=Mock(),
        event_logger=Mock(),
        file_inspector=Mock(),
    )

    assert guard._is_external("E:", usb_guard.win32con.DRIVE_REMOVABLE) is True
    assert guard._is_external("D:", usb_guard.win32con.DRIVE_FIXED) is False


def _write_ready_project(root: Path, token: str) -> None:
    config = root / "config"
    config.mkdir()
    (config / "settings.yaml").write_text(
        yaml.safe_dump(
            {
                "server": {
                    "ai_base_url": "https://ai.example",
                    "ai_token": token,
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
    token = "do-not-print-this-token-32-bytes-minimum"
    _write_ready_project(tmp_path, "tracked-placeholder-token-32-bytes")
    monkeypatch.setenv("AI_API_TOKEN", token)
    monkeypatch.setenv("AGENT_API_TOKEN", token)
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
        if url == "https://ai.example/api/v1/agent-check":
            assert headers == {"Authorization": f"Bearer {token}"}
            return _Response({"status": "ok", "ai_token": "accepted"})
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
    token = "configured-but-rejected-token-32-bytes"
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
        if url == "https://ai.example/api/v1/agent-check":
            return _Response({"status": "ok", "ai_token": "accepted"})
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


def test_preflight_rejects_non_ascii_ai_token_before_agent_check(
    tmp_path, monkeypatch
):
    non_ascii_token = "가" * 32
    _write_ready_project(tmp_path, non_ascii_token)
    settings_path = tmp_path / "config" / "settings.yaml"
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    settings["server"]["dashboard_token"] = "dashboard-token-32-characters-minimum"
    settings_path.write_text(yaml.safe_dump(settings), encoding="utf-8")

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "https://ai.example/api/v1/agent-check":
            raise AssertionError("invalid AI token must not be sent")
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            return _Response({"status": "ok", "agent_token": "accepted"})
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_get)
    checks = {check.name: check for check in demo_preflight.collect_checks(tmp_path)}

    assert checks["AI_TOKEN"].ready is False
    assert "ASCII" in checks["AI_TOKEN"].detail


def test_preflight_rejects_short_dashboard_token_before_agent_check(
    tmp_path, monkeypatch
):
    ai_token = "ai-token-that-is-at-least-32-characters"
    _write_ready_project(tmp_path, ai_token)
    settings_path = tmp_path / "config" / "settings.yaml"
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    settings["server"]["dashboard_token"] = "short"
    settings_path.write_text(yaml.safe_dump(settings), encoding="utf-8")

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "https://ai.example/api/v1/agent-check":
            return _Response({"status": "ok", "ai_token": "accepted"})
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
        if url == "http://192.168.0.39:8000/api/v1/agent-check":
            raise AssertionError("short dashboard token must not be sent")
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr(demo_preflight.requests, "get", fake_get)
    checks = {check.name: check for check in demo_preflight.collect_checks(tmp_path)}

    assert checks["DASHBOARD_TOKEN"].ready is False
    assert "32자 이상 ASCII" in checks["DASHBOARD_TOKEN"].detail


def test_preflight_rejects_mock_ai_loopback_dashboard_and_disabled_delivery(
    tmp_path, monkeypatch
):
    _write_ready_project(tmp_path, "configured-token-32-bytes-minimum")
    settings_path = tmp_path / "config" / "settings.yaml"
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    settings["server"]["ai_base_url"] = ""
    settings["server"]["dashboard_url"] = "http://127.0.0.1:8000"
    settings["logging"]["send_immediately"] = False
    settings_path.write_text(yaml.safe_dump(settings), encoding="utf-8")
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
    assert all(
        checks[name].ready is False
        for name in ("CLIPBOARD", "USB_COPY", "EMAIL_ATTACHMENT", "WEB_UPLOAD", "CLOUD_DRIVE")
    )


def test_preflight_requires_structured_file_extractors_for_file_scenarios(
    tmp_path, monkeypatch
):
    _write_ready_project(tmp_path, "configured-token-32-bytes-minimum")
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
        if url == "https://ai.example/api/v1/agent-check":
            return _Response({"status": "ok", "ai_token": "accepted"})
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
    token = "runtime-check-token-32-bytes-minimum"
    _write_ready_project(tmp_path, token)
    monkeypatch.setenv("SystemDrive", "C:")
    monkeypatch.setattr(demo_preflight.sys, "platform", "win32")
    monkeypatch.setattr(demo_preflight, "_module_available", lambda name: True)
    monkeypatch.setattr(demo_preflight, "_proxy_status", lambda port: (True, True))
    monkeypatch.setattr(demo_preflight, "_outlook_running", lambda: True)

    def fake_get(url, timeout, headers=None):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "https://ai.example/api/v1/agent-check":
            return _Response({"status": "ok", "ai_token": "accepted"})
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


def test_main_agent_merges_ignored_local_settings_and_prefers_env_token(
    tmp_path,
    monkeypatch,
):
    main_agent = _load_main_agent_without_windows_modules(monkeypatch)
    config = tmp_path / "config"
    config.mkdir()
    (config / "settings.yaml").write_text(
        yaml.safe_dump(
            {
                "server": {
                    "ai_base_url": "https://tracked.example",
                    "ai_token": "tracked-token",
                    "request_timeout_sec": 10,
                },
                "agent": {"department": "Tracked"},
            }
        ),
        encoding="utf-8",
    )
    (config / "settings.local.yaml").write_text(
        yaml.safe_dump(
            {
                "server": {"ai_base_url": "https://local.example"},
                "agent": {"department": "Local"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(main_agent, "PROJECT_ROOT", tmp_path)
    monkeypatch.setenv("AI_API_TOKEN", "environment-token-32-bytes-minimum")
    captured = {}

    class CapturingApiClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(main_agent, "ApiClient", CapturingApiClient)

    settings = main_agent.load_settings()
    main_agent.build_api_client(settings)

    assert settings["server"]["ai_base_url"] == "https://local.example"
    assert settings["server"]["request_timeout_sec"] == 10
    assert settings["agent"]["department"] == "Local"
    assert captured["token"] == "environment-token-32-bytes-minimum"


def test_runtime_identity_checks_bind_task_and_listener_to_current_project(
    monkeypatch,
):
    expected = (
        Path(r"C:\project\.venv\Scripts\pythonw.exe"),
        Path(r"C:\project\sentry_user_agent.py"),
        Path(r"C:\project"),
    )
    scripts = []
    monkeypatch.setattr(demo_preflight, "_expected_user_agent_paths", lambda: expected)
    monkeypatch.setattr(
        demo_preflight,
        "_powershell_boolean",
        lambda script, timeout=5.0: scripts.append(script) or True,
    )

    assert demo_preflight._user_agent_task_running() is True
    assert demo_preflight._proxy_listener_running(8082) is True

    task_script, listener_script = scripts
    for fragment in (
        "$task.State -eq 'Running'",
        "$task.Principal.UserId -ieq $currentUser",
        "$action.Execute -ieq $expectedExe",
        "$actualArgs -ieq $expectedScript",
        "$action.WorkingDirectory -ieq $expectedDir",
    ):
        assert fragment in task_script
    for fragment in (
        "Get-NetTCPConnection",
        "OwningProcess",
        "Win32_Process",
        "$process.ExecutablePath -ieq $expectedExe",
        "$process.CommandLine",
    ):
        assert fragment in listener_script


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
    assert "FIXED 외장 SSD" in output
    assert "DRIVE_REMOVABLE" in output
    assert "사후 삭제" in output
