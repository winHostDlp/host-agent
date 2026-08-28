"""Host Agent ↔ AI/Dashboard integration contract regression tests.

These tests intentionally avoid importing pywin32-dependent modules so they can
run in CI on non-Windows hosts.
"""

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
import requests

import core_comm.review_notifier as review_notifier
from core_comm.analysis_events import (
    make_network_decision_handler,
    record_analysis_result,
)
from core_comm.api_client import ApiClient
from core_comm.clipboard_analysis import run_clipboard_analysis
from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore
from core_comm.payload_builder import AnalysisPayload, AnalysisResult, ResponseParser
from core_comm.review_notifier import build_review_notice
from network_hook.http_monitor import HttpMonitor
from network_hook.outlook_hook import _build_sink, _handle_item_send
from network_hook.smtp_proxy import _DLPHandler
from network_hook.web_proxy import _DLPAddon


def _analysis_payload() -> AnalysisPayload:
    return AnalysisPayload(
        request_id="event-contract-1",
        timestamp="2026-08-27T00:00:00+00:00",
        channel="clipboard",
        process="test.exe",
        user_id="tester",
        text="contract test",
        matched_patterns=[],
        metadata={"max_severity": "high", "pattern_ids": ["rrn"]},
    )


def _valid_ai_response(**overrides):
    response = {
        "event_id": "event-contract-1",
        "decision": "allow",
        "confidence_score": 0.12,
        "model_version": "koelectra-dlp-v7",
        "latency_ms": 14.5,
        "reason": "문맥상 비기밀",
    }
    response.update(overrides)
    return response


def _response_without(field):
    response = _valid_ai_response()
    response.pop(field)
    return response


@pytest.mark.parametrize(
    ("error", "reason_fragment"),
    [
        (requests.Timeout(), "타임아웃"),
        (requests.ConnectionError("connection refused"), "connection refused"),
    ],
)
def test_ai_transport_failures_are_fail_open(monkeypatch, error, reason_fragment):
    def raise_error(*args, **kwargs):
        raise error

    monkeypatch.setattr("core_comm.api_client.requests.post", raise_error)

    result = ApiClient("http://ai.example", timeout=2.5).analyze(_analysis_payload())

    assert result.action == "allow"
    assert result.confidence_score == 0.0
    assert result.model_version == "unavailable"
    assert result.analysis_failed is True
    assert "Fail-Open 허용" in result.reason
    assert reason_fragment in result.reason


def test_ai_http_5xx_is_fail_open(monkeypatch):
    response = Mock()
    response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
    monkeypatch.setattr("core_comm.api_client.requests.post", lambda *args, **kwargs: response)

    result = ApiClient("http://ai.example").analyze(_analysis_payload())

    assert result.action == "allow"
    assert result.confidence_score == 0.0
    assert result.analysis_failed is True
    assert "500 Server Error" in result.reason


@pytest.mark.parametrize(
    "raw_response",
    [
        [],
        _response_without("event_id"),
        _valid_ai_response(event_id="different-event"),
        _response_without("decision"),
        _valid_ai_response(decision="unknown"),
        _response_without("confidence_score"),
        _valid_ai_response(confidence_score="0.2"),
        _valid_ai_response(confidence_score=float("nan")),
        _valid_ai_response(confidence_score=1.1),
        _response_without("model_version"),
        _response_without("latency_ms"),
        _valid_ai_response(latency_ms=-1),
        _valid_ai_response(reason=["invalid"]),
    ],
)
def test_invalid_ai_response_is_fail_open(monkeypatch, raw_response):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = raw_response
    monkeypatch.setattr("core_comm.api_client.requests.post", lambda *args, **kwargs: response)

    result = ApiClient("http://ai.example").analyze(_analysis_payload())

    assert result.action == "allow"
    assert result.confidence_score == 0.0
    assert result.model_version == "unavailable"
    assert result.analysis_failed is True
    assert "Fail-Open 허용" in result.reason


@pytest.mark.parametrize(
    "raw_response",
    [
        _response_without("decision"),
        _valid_ai_response(decision="unexpected"),
        _response_without("confidence_score"),
        _valid_ai_response(confidence_score="high"),
    ],
)
def test_response_parser_rejects_semantically_invalid_contract(raw_response):
    with pytest.raises(ValueError):
        ResponseParser.parse(raw_response, "event-contract-1")


def test_response_parser_accepts_complete_valid_contract():
    result = ResponseParser.parse(_valid_ai_response(), "event-contract-1")

    assert result.request_id == "event-contract-1"
    assert result.action == "allow"
    assert result.confidence_score == 0.12
    assert result.model_version == "koelectra-dlp-v7"
    assert result.latency_ms == 14.5


@pytest.mark.parametrize(
    "channel",
    ["outlook", "smtp", "http", "clipboard", "web_mail", "drive_upload", "file_guard"],
)
def test_normal_ai_allow_is_recorded_for_every_current_channel(channel):
    event_logger = Mock()
    result = AnalysisResult(
        request_id="event-allow-1",
        confidence_score=0.12,
        action="allow",
        reason="문맥상 비기밀",
        model_version="koelectra-dlp-v7",
        latency_ms=14,
    )

    record_analysis_result(
        event_logger,
        result,
        channel=channel,
        process_name="test-process",
        hits=[{"id": "email"}],
        text="allowed content",
        event_id=result.request_id,
        detection_type="HYBRID",
    )

    logged = event_logger.log.call_args.kwargs
    assert logged["channel"] == channel
    assert logged["action"] == "allowed"
    assert logged["extra"]["ai_score"] == 0.12
    assert logged["extra"]["model_version"] == "koelectra-dlp-v7"


@pytest.mark.parametrize(
    ("channel", "label"),
    [
        ("outlook", "Outlook 메일 전송"),
        ("smtp", "SMTP 메일 전송"),
        ("http", "HTTP 업로드"),
        ("web_mail", "웹메일 업로드"),
        ("drive_upload", "클라우드 드라이브 업로드"),
        ("file_guard", "USB 파일 복사"),
    ],
)
def test_review_notice_is_available_for_non_clipboard_channels(channel, label):
    notice = build_review_notice(
        channel,
        "target.example",
        [{"id": "rrn", "name": "주민등록번호"}],
    )

    assert label in notice.body
    assert "허용" in notice.body
    assert "보안 이벤트로 기록" in notice.body
    assert "주민등록번호" in notice.body


def test_clipboard_review_notice_preserves_wording():
    notice = build_review_notice(
        "clipboard",
        "chrome.exe",
        [{"id": "rrn", "name": "주민등록번호"}],
    )

    assert notice.title == "Sentry DLP — 보안 경고"
    assert notice.heading == "민감정보 의심 항목이 감지되었습니다"
    assert "붙여넣기는 허용됩니다" in notice.body
    assert "대상 프로그램 : chrome.exe" in notice.body


def test_review_notification_dispatch_is_non_blocking(monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, *, target, args, daemon, name):
            self.target = target
            self.args = args
            self.daemon = daemon
            self.name = name

        def start(self):
            started.append(self)

    monkeypatch.setattr(review_notifier.threading, "Thread", FakeThread)

    review_notifier.notify_review(
        "web_mail",
        "https://mail.example/upload",
        [{"id": "email", "name": "이메일"}],
    )

    assert len(started) == 1
    assert started[0].daemon is True
    assert started[0].name == "DLPReviewNotifier"
    assert "웹메일 업로드" in started[0].args[0].body


def test_review_notification_thread_start_failure_is_best_effort(monkeypatch):
    class FailingThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("thread unavailable")

    monkeypatch.setattr(review_notifier.threading, "Thread", FailingThread)

    # A UI-thread failure must not escape into a review/allow caller.
    assert review_notifier.notify_review(
        "web_mail",
        "https://mail.example/upload",
        [{"id": "email", "name": "이메일"}],
    ) is None


@pytest.mark.parametrize(
    ("channel", "expected"),
    [
        ("clipboard", "CLIPBOARD"),
        ("drive_upload", "CLOUD_DRIVE"),
    ],
)
def test_dashboard_payload_uses_dedicated_channels_and_model_version(
    monkeypatch, tmp_path, channel, expected
):
    monkeypatch.setattr("core_comm.event_logger._get_host_ip", lambda: "127.0.0.1")
    event_logger = EventLogger(
        LocalEventStore(tmp_path),
        agent_id="agent-contract",
        user_id="tester",
        department="Security",
    )

    payload = event_logger._build_log_payload(
        channel=channel,
        action="review",
        process_name="chrome.exe",
        hits=[{"id": "rrn", "name": "주민등록번호", "severity": "critical"}],
        text="sensitive",
        extra={
            "ai_score": 0.42,
            "model_version": "koelectra-dlp-v7",
            "url": "https://drive.example/upload",
        },
    )

    assert payload["leak_channel"] == expected
    assert payload["model_version"] == "koelectra-dlp-v7"
    assert payload["action_taken"] == "WARNED"


def test_dashboard_payload_maps_normal_allow_to_allowed(monkeypatch, tmp_path):
    monkeypatch.setattr("core_comm.event_logger._get_host_ip", lambda: "127.0.0.1")
    event_logger = EventLogger(LocalEventStore(tmp_path))

    payload = event_logger._build_log_payload(
        channel="clipboard",
        action="allowed",
        process_name="chrome.exe",
        hits=[{"id": "email"}],
        text="allowed content",
        extra={"ai_score": 0.1, "model_version": "koelectra-dlp-v7"},
    )

    assert payload["action_taken"] == "ALLOWED"


def test_ai_error_flows_through_event_record_to_dashboard_payload(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "core_comm.api_client.requests.post",
        Mock(side_effect=requests.ConnectionError("connection refused")),
    )
    monkeypatch.setattr("core_comm.event_logger._get_host_ip", lambda: "127.0.0.1")
    analysis_payload = _analysis_payload()
    result = ApiClient("http://ai.example").analyze(analysis_payload)
    event_logger = EventLogger(LocalEventStore(tmp_path))

    record_analysis_result(
        event_logger,
        result,
        channel="clipboard",
        process_name="chrome.exe",
        hits=[{"id": "rrn"}],
        text="sensitive",
        event_id=analysis_payload.request_id,
        detection_type="HYBRID",
    )

    record = json.loads((tmp_path / "events.jsonl").read_text(encoding="utf-8"))
    dashboard_payload = event_logger._build_log_payload_from_record(record)
    assert dashboard_payload["action_taken"] == "ALLOWED"
    assert dashboard_payload["model_version"] == "unavailable"
    assert dashboard_payload["event_id"] == analysis_payload.request_id
    assert "connection refused" in dashboard_payload["decision_reason"]
    assert "Fail-Open 허용" in dashboard_payload["decision_reason"]


def _run_clipboard_worker(
    action="allow",
    *,
    builder=None,
    analyze=None,
    event_logger=None,
    release=None,
    blocked=None,
    review=None,
):
    payload_builder = builder or Mock()
    if builder is None:
        payload_builder.build.return_value = SimpleNamespace(request_id="clipboard-event-1")

    analyze_callback = analyze or Mock(
        return_value=AnalysisResult(
            request_id="clipboard-event-1",
            confidence_score=0.3,
            action=action,
            reason="contract test",
            model_version="koelectra-dlp-v7",
        )
    )
    api_client = SimpleNamespace(is_mock=False, analyze=analyze_callback)
    log_sink = event_logger or Mock()
    release_callback = release or Mock(return_value=True)
    block_callback = blocked or Mock()
    review_callback = review or Mock()

    run_clipboard_analysis(
        text="sensitive clipboard content",
        process_name="chrome.exe",
        hits=[{"id": "rrn"}],
        payload_builder=payload_builder,
        api_client=api_client,
        event_logger=log_sink,
        release_paste=release_callback,
        notify_blocked=block_callback,
        notify_review=review_callback,
        logger=Mock(),
    )
    return release_callback, block_callback, review_callback


def test_clipboard_review_releases_once_before_popup():
    order = []
    release = Mock(side_effect=lambda: order.append("release"))
    review = Mock(side_effect=lambda process, hits: order.append("review"))

    release, blocked, review = _run_clipboard_worker(
        "review",
        release=release,
        review=review,
    )

    release.assert_called_once_with()
    blocked.assert_not_called()
    review.assert_called_once()
    assert order == ["release", "review"]


def test_clipboard_allow_releases_once_without_notifications():
    release, blocked, review = _run_clipboard_worker("allow")

    release.assert_called_once_with()
    blocked.assert_not_called()
    review.assert_not_called()


def test_clipboard_confirmed_block_does_not_release():
    release, blocked, review = _run_clipboard_worker("block")

    release.assert_not_called()
    blocked.assert_called_once()
    review.assert_not_called()


@pytest.mark.parametrize(
    "failure_stage",
    ["build", "analyze", "event_log", "review_notify", "release"],
)
def test_clipboard_worker_exceptions_attempt_release_exactly_once(failure_stage):
    builder = Mock()
    builder.build.return_value = SimpleNamespace(request_id="clipboard-event-1")
    analyze = Mock(
        return_value=AnalysisResult(
            request_id="clipboard-event-1",
            confidence_score=0.3,
            action="review",
            reason="contract test",
            model_version="koelectra-dlp-v7",
        )
    )
    event_logger = Mock()
    release = Mock(return_value=True)
    blocked = Mock()
    review = Mock()

    error = RuntimeError(failure_stage)
    if failure_stage == "build":
        builder.build.side_effect = error
    elif failure_stage == "analyze":
        analyze.side_effect = error
    elif failure_stage == "event_log":
        event_logger.log.side_effect = error
    elif failure_stage == "review_notify":
        review.side_effect = error
    elif failure_stage == "release":
        release.side_effect = error

    _run_clipboard_worker(
        builder=builder,
        analyze=analyze,
        event_logger=event_logger,
        release=release,
        blocked=blocked,
        review=review,
    )

    release.assert_called_once_with()


@pytest.mark.parametrize("failure_stage", ["event_log", "block_notify"])
def test_clipboard_ai_block_survives_side_effect_failures(failure_stage):
    event_logger = Mock()
    release = Mock(return_value=True)
    blocked = Mock()
    if failure_stage == "event_log":
        event_logger.log.side_effect = RuntimeError("event log unavailable")
    else:
        blocked.side_effect = RuntimeError("notifier unavailable")

    _run_clipboard_worker(
        "block",
        event_logger=event_logger,
        release=release,
        blocked=blocked,
    )

    release.assert_not_called()
    blocked.assert_called_once()


def _failing_side_effect_handler(action, channel):
    builder = Mock()
    builder.build.return_value = SimpleNamespace(request_id=f"{channel}-decision-1")
    api_client = SimpleNamespace(
        is_mock=False,
        analyze=Mock(
            return_value=AnalysisResult(
                request_id=f"{channel}-decision-1",
                confidence_score=0.9 if action == "block" else 0.3,
                action=action,
                reason="contract decision",
                model_version="koelectra-dlp-v7",
            )
        ),
    )
    event_logger = Mock()
    event_logger.log.side_effect = RuntimeError("event store unavailable")
    return make_network_decision_handler(
        channel=channel,
        event_logger=event_logger,
        api_client=api_client,
        payload_builder=builder,
        notify_blocked=Mock(side_effect=RuntimeError("blocked popup unavailable")),
        notify_review=Mock(side_effect=RuntimeError("review popup unavailable")),
        logger=Mock(),
    )


@pytest.mark.parametrize("failure_stage", ["build", "analyze"])
def test_network_handler_pipeline_exception_is_recorded_fail_open(failure_stage):
    builder = Mock()
    builder.build.return_value = SimpleNamespace(request_id="network-fail-open-1")
    api_client = SimpleNamespace(is_mock=False, analyze=Mock())
    if failure_stage == "build":
        builder.build.side_effect = RuntimeError("payload failed")
    else:
        api_client.analyze.side_effect = RuntimeError("analysis failed")
    event_logger = Mock()
    handler = make_network_decision_handler(
        channel="http",
        event_logger=event_logger,
        api_client=api_client,
        payload_builder=builder,
        notify_blocked=Mock(),
        notify_review=Mock(),
        logger=Mock(),
    )

    decision = handler("sensitive", [{"id": "rrn"}], "http_upload")

    assert decision == "allow"
    logged = event_logger.log.call_args.kwargs
    assert logged["action"] == "allowed"
    assert logged["extra"]["model_version"] == "unavailable"
    assert logged["extra"]["event_id"]
    assert "Fail-Open 허용" in logged["extra"]["reason"]


def test_http_review_reinjects_packet():
    packet = SimpleNamespace(
        payload=b"POST /upload HTTP/1.1\r\nContent-Disposition: form-data",
        dst_addr="203.0.113.10",
        dst_port=80,
    )
    sender = SimpleNamespace(send=Mock())
    monitor = HttpMonitor(
        inspect_ports=[80],
        inspect=lambda text: [{"id": "rrn"}],
        on_blocked=lambda summary, hits, process: "review",
        fi_extract=lambda data, name: None,
    )
    monitor._parse_multipart_text = lambda payload: "sensitive text"

    monitor._handle_packet(packet, sender)

    sender.send.assert_called_once_with(packet)


@pytest.mark.parametrize(
    ("decision", "expected_send_count"),
    [("block", 0), ("review", 1), ("allow", 1)],
)
def test_http_decision_survives_event_and_notifier_failures(
    decision, expected_send_count
):
    packet = SimpleNamespace(
        payload=b"POST /upload HTTP/1.1\r\nContent-Disposition: form-data",
        dst_addr="203.0.113.10",
        dst_port=80,
    )
    sender = SimpleNamespace(send=Mock())
    monitor = HttpMonitor(
        inspect_ports=[80],
        inspect=lambda text: [{"id": "rrn"}],
        on_blocked=_failing_side_effect_handler(decision, "http"),
        fi_extract=lambda data, name: None,
    )
    monitor._parse_multipart_text = lambda payload: "sensitive text"

    monitor._handle_packet(packet, sender)

    assert sender.send.call_count == expected_send_count


def _outlook_mail_item(save=None):
    recipient = SimpleNamespace(Address="outside@example.com")
    recipients = SimpleNamespace(Count=1, Item=lambda index: recipient)
    return SimpleNamespace(
        Class=43,
        Recipients=recipients,
        Save=save or Mock(),
        Move=Mock(),
        Application=SimpleNamespace(
            Session=SimpleNamespace(GetDefaultFolder=Mock())
        ),
    )


@pytest.mark.parametrize("decision", ["review", "allow", None, "unknown"])
def test_outlook_non_block_decisions_do_not_cancel_or_move(monkeypatch, decision):
    monkeypatch.setattr("network_hook.outlook_hook._collect_text", lambda *args: "sensitive")
    item = _outlook_mail_item()

    cancelled = _handle_item_send(
        item=item,
        internal_domains=frozenset({"internal.example"}),
        on_blocked=lambda summary, hits, process: decision,
        inspect=lambda text: [{"id": "rrn"}],
        file_inspector_extract=lambda data, name: None,
    )

    assert cancelled is False
    item.Save.assert_not_called()
    item.Move.assert_not_called()
    item.Application.Session.GetDefaultFolder.assert_not_called()


def test_outlook_block_saves_draft_and_requests_cancel(monkeypatch):
    monkeypatch.setattr("network_hook.outlook_hook._collect_text", lambda *args: "sensitive")
    item = _outlook_mail_item()

    cancelled = _handle_item_send(
        item=item,
        internal_domains=frozenset({"internal.example"}),
        on_blocked=lambda summary, hits, process: "block",
        inspect=lambda text: [{"id": "rrn"}],
        file_inspector_extract=lambda data, name: None,
    )

    assert cancelled is True
    item.Save.assert_called_once_with()
    item.Move.assert_not_called()


def test_outlook_block_still_cancels_when_draft_save_fails(monkeypatch):
    monkeypatch.setattr("network_hook.outlook_hook._collect_text", lambda *args: "sensitive")
    item = _outlook_mail_item(save=Mock(side_effect=RuntimeError("inline reply")))

    cancelled = _handle_item_send(
        item=item,
        internal_domains=frozenset({"internal.example"}),
        on_blocked=lambda summary, hits, process: "block",
        inspect=lambda text: [{"id": "rrn"}],
        file_inspector_extract=lambda data, name: None,
    )

    assert cancelled is True
    item.Save.assert_called_once_with()


def test_outlook_sink_returns_cancel_value_and_fails_open(monkeypatch):
    monkeypatch.setattr("network_hook.outlook_hook._collect_text", lambda *args: "sensitive")
    item = _outlook_mail_item()
    block_sink = _build_sink(
        frozenset({"internal.example"}),
        lambda summary, hits, process: "block",
        lambda text: [{"id": "rrn"}],
        lambda data, name: None,
    )()

    assert block_sink.OnItemSend(item, False) is True

    def raise_during_inspection(text):
        raise RuntimeError("inspection failed")

    fail_open_sink = _build_sink(
        frozenset({"internal.example"}),
        lambda summary, hits, process: "block",
        raise_during_inspection,
        lambda data, name: None,
    )()

    assert fail_open_sink.OnItemSend(_outlook_mail_item(), False) is False


def test_outlook_non_mail_item_is_not_cancelled():
    item = SimpleNamespace(Class=26)

    cancelled = _handle_item_send(
        item=item,
        internal_domains=frozenset({"internal.example"}),
        on_blocked=lambda summary, hits, process: "block",
        inspect=lambda text: [{"id": "rrn"}],
        file_inspector_extract=lambda data, name: None,
    )

    assert cancelled is False


@pytest.mark.parametrize(
    ("decision", "expected_cancel"),
    [("block", True), ("review", False), ("allow", False)],
)
def test_outlook_decision_survives_event_and_notifier_failures(
    monkeypatch, decision, expected_cancel
):
    monkeypatch.setattr("network_hook.outlook_hook._collect_text", lambda *args: "sensitive")
    item = _outlook_mail_item()

    cancelled = _handle_item_send(
        item=item,
        internal_domains=frozenset({"internal.example"}),
        on_blocked=_failing_side_effect_handler(decision, "outlook"),
        inspect=lambda text: [{"id": "rrn"}],
        file_inspector_extract=lambda data, name: None,
    )

    assert cancelled is expected_cancel


def test_smtp_review_relays_message():
    handler = _DLPHandler(
        internal_domains=frozenset({"internal.example"}),
        relay_host="smtp.example",
        relay_port=587,
        relay_use_tls=True,
        relay_username=None,
        relay_password=None,
        inspect=lambda text: [{"id": "rrn"}],
        on_blocked=lambda summary, hits, process: "review",
        fi_extract=lambda data, name: None,
    )
    handler._relay = AsyncMock()
    envelope = SimpleNamespace(
        mail_from="sender@internal.example",
        rcpt_tos=["outside@example.com"],
        content=(
            b"From: sender@internal.example\r\n"
            b"To: outside@example.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"sensitive content"
        ),
    )

    response = asyncio.run(handler._process(envelope))

    assert response.startswith("250 OK")
    handler._relay.assert_awaited_once_with(envelope)


def _smtp_envelope():
    return SimpleNamespace(
        mail_from="sender@internal.example",
        rcpt_tos=["outside@example.com"],
        content=(
            b"From: sender@internal.example\r\n"
            b"To: outside@example.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"sensitive content"
        ),
    )


@pytest.mark.parametrize(
    ("decision", "expected_status", "expected_relay_count"),
    [("block", "550", 0), ("review", "250", 1), ("allow", "250", 1)],
)
def test_smtp_decision_survives_event_and_notifier_failures(
    decision, expected_status, expected_relay_count
):
    handler = _DLPHandler(
        internal_domains=frozenset({"internal.example"}),
        relay_host="smtp.example",
        relay_port=587,
        relay_use_tls=True,
        relay_username=None,
        relay_password=None,
        inspect=lambda text: [{"id": "rrn"}],
        on_blocked=_failing_side_effect_handler(decision, "smtp"),
        fi_extract=lambda data, name: None,
    )
    handler._relay = AsyncMock()
    envelope = _smtp_envelope()

    response = asyncio.run(handler._process(envelope))

    assert response.startswith(expected_status)
    assert handler._relay.await_count == expected_relay_count


def _install_fake_mitmproxy_response(monkeypatch):
    class FakeResponse:
        @staticmethod
        def make(status_code, content, headers):
            return SimpleNamespace(
                status_code=status_code,
                content=content,
                headers=headers,
            )

    mitmproxy_module = ModuleType("mitmproxy")
    http_module = ModuleType("mitmproxy.http")
    http_module.Response = FakeResponse
    mitmproxy_module.http = http_module
    monkeypatch.setitem(sys.modules, "mitmproxy", mitmproxy_module)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", http_module)


def _web_flow():
    return SimpleNamespace(
        request=SimpleNamespace(
            method="POST",
            pretty_url="https://mail.example/upload",
            pretty_host="mail.example",
            content=b"sensitive content",
        ),
        response=None,
    )


@pytest.mark.parametrize(
    ("decision", "expected_status"),
    [("block", 451), ("review", None), ("allow", None)],
)
def test_web_decision_survives_event_and_notifier_failures(
    monkeypatch, decision, expected_status
):
    _install_fake_mitmproxy_response(monkeypatch)
    builder = Mock()
    builder.build.return_value = SimpleNamespace(request_id="web-decision-1")
    api_client = SimpleNamespace(
        is_mock=False,
        analyze=Mock(
            return_value=AnalysisResult(
                request_id="web-decision-1",
                confidence_score=0.9 if decision == "block" else 0.3,
                action=decision,
                reason="contract decision",
                model_version="koelectra-dlp-v7",
            )
        ),
    )
    event_logger = Mock()
    event_logger.log.side_effect = RuntimeError("event store unavailable")
    addon = _DLPAddon(
        inspect_domains=["mail.example"],
        rule_filter=SimpleNamespace(match=lambda text: [{"id": "rrn"}]),
        payload_builder=builder,
        api_client=api_client,
        event_logger=event_logger,
        file_inspector=Mock(),
        on_blocked=Mock(side_effect=RuntimeError("blocked popup unavailable")),
        log_traffic=False,
    )
    monkeypatch.setattr(addon, "_get_dlp_channel", lambda flow: "web_mail")
    monkeypatch.setattr(addon, "_extract_text", lambda flow: "sensitive content")
    if decision == "review":
        monkeypatch.setattr(
            "network_hook.web_proxy.notify_review",
            Mock(side_effect=RuntimeError("review popup unavailable")),
        )
    flow = _web_flow()

    addon._handle(flow)

    actual_status = getattr(flow.response, "status_code", None)
    assert actual_status == expected_status


def _load_usb_guard_with_win32_stubs(monkeypatch):
    win32api = ModuleType("win32api")
    win32con = ModuleType("win32con")
    win32file = ModuleType("win32file")
    win32con.DRIVE_REMOVABLE = 2
    win32con.DRIVE_FIXED = 3
    monkeypatch.setitem(sys.modules, "win32api", win32api)
    monkeypatch.setitem(sys.modules, "win32con", win32con)
    monkeypatch.setitem(sys.modules, "win32file", win32file)

    module_path = (
        Path(__file__).resolve().parents[1]
        / "usb_minifilter"
        / "usb_guard_usermode.py"
    )
    spec = importlib.util.spec_from_file_location("usb_guard_contract_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("decision", "expected_remove_count"),
    [("block", 1), ("review", 0), ("allow", 0)],
)
def test_usb_file_action_survives_event_and_notifier_failures(
    monkeypatch, decision, expected_remove_count
):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    monkeypatch.setattr(usb_guard.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(usb_guard.os.path, "isfile", lambda path: True)
    monkeypatch.setattr(usb_guard.os.path, "getsize", lambda path: 128)
    remove = Mock()
    monkeypatch.setattr(usb_guard.os, "remove", remove)
    review_notice = Mock(side_effect=RuntimeError("review popup unavailable"))
    monkeypatch.setattr(usb_guard, "notify_review", review_notice)

    event_logger = Mock()
    event_logger.log.side_effect = RuntimeError("event store unavailable")
    blocked_notice = Mock(side_effect=RuntimeError("blocked popup unavailable"))
    guard = usb_guard.UsbGuardUserMode.__new__(usb_guard.UsbGuardUserMode)
    guard._max_size = 1024
    guard._fi = SimpleNamespace(
        extract_from_path=lambda path: "sensitive content long enough for inspection"
    )
    guard._rf = SimpleNamespace(match=lambda text: [{"id": "rrn"}])
    guard._pb = SimpleNamespace(
        build=lambda **kwargs: SimpleNamespace(request_id="usb-decision-1")
    )
    guard._ac = SimpleNamespace(
        is_mock=False,
        analyze=lambda payload: AnalysisResult(
            request_id=payload.request_id,
            confidence_score=0.9 if decision == "block" else 0.3,
            action=decision,
            reason="contract decision",
            model_version="koelectra-dlp-v7",
        ),
    )
    guard._el = event_logger
    guard._on_blocked = blocked_notice

    guard._inspect_file("E:\\sensitive.txt", "E:")

    assert remove.call_count == expected_remove_count
    if decision == "block":
        blocked_notice.assert_called_once()
    elif decision == "review":
        review_notice.assert_called_once()
