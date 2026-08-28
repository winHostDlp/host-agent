from __future__ import annotations

import importlib.util
import json
import sys
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

    def fake_get(url, timeout):
        if url == "https://ai.example/":
            return _Response({"status": "running", "engine": "koelectra-dlp-v7"})
        if url == "http://192.168.0.39:8000/health":
            return _Response({"status": "ok"})
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
