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
from core_comm.clipboard_analysis import (
    is_same_paste_destination,
    run_clipboard_analysis,
)
from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore
from core_comm.payload_builder import (
    AnalysisPayload,
    AnalysisResult,
    PayloadBuilder,
    ResponseParser,
)
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
        _valid_ai_response(event_id="e" * 121),
        _response_without("decision"),
        _valid_ai_response(decision="unknown"),
        _response_without("confidence_score"),
        _valid_ai_response(confidence_score="0.2"),
        _valid_ai_response(confidence_score=float("nan")),
        _valid_ai_response(confidence_score=1.1),
        _response_without("model_version"),
        _valid_ai_response(model_version="m" * 101),
        _response_without("latency_ms"),
        _valid_ai_response(latency_ms=-1),
        _valid_ai_response(latency_ms=600001),
        _valid_ai_response(reason=["invalid"]),
        _valid_ai_response(reason="r" * 501),
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


def test_ai_client_sends_configured_bearer_token(monkeypatch):
    captured = {}
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = _valid_ai_response()

    def capture_post(*args, **kwargs):
        captured.update(kwargs)
        return response

    monkeypatch.setattr("core_comm.api_client.requests.post", capture_post)

    result = ApiClient(
        "http://ai.example",
        token="private-ai-token",
    ).analyze(_analysis_payload())

    assert result.action == "allow"
    assert captured["headers"] == {
        "Authorization": "Bearer private-ai-token",
    }


def test_payload_builder_cannot_exceed_ai_request_bounds():
    text = "x" * 3000 + "secret" + "y" * 3000
    hits = [
        {
            "id": f"pattern-{index}-" + "z" * 120,
            "name": "test",
            "severity": "high",
            "regex": "secret",
        }
        for index in range(120)
    ]

    payload = PayloadBuilder(
        max_text_chars=0,
        max_per_pattern=1,
        context_chars=2500,
        user_id="u" * 150,
    ).build(text, hits, "clipboard", "p" * 600)
    request = payload.to_dict()

    assert len(request["snippet"]) == 4000
    assert len(request["user_id"]) == 100
    assert len(request["matched_patterns"]) == 100
    assert all(1 <= len(item) <= 100 for item in request["matched_patterns"])
    assert len(request["metadata"]["app"]) == 500


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


@pytest.mark.parametrize(
    ("channel", "action"),
    [("unknown_channel", "allowed"), ("clipboard", "unknown_action")],
)
def test_dashboard_payload_rejects_unknown_provenance(
    monkeypatch,
    tmp_path,
    channel,
    action,
):
    monkeypatch.setattr("core_comm.event_logger._get_host_ip", lambda: "127.0.0.1")
    store = LocalEventStore(tmp_path)
    event_logger = EventLogger(store)

    with pytest.raises(ValueError, match="지원하지 않는 이벤트"):
        event_logger._build_log_payload(
            channel=channel,
            action=action,
            process_name="test.exe",
            hits=[],
            text=None,
            extra={"ai_score": 0.0},
        )

    with pytest.raises(ValueError, match="지원하지 않는 이벤트"):
        event_logger.log(
            channel=channel,
            action=action,
            process_name="test.exe",
            hits=[],
            extra={"ai_score": 0.0},
        )
    assert not store._active_path.exists()


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
    assert dashboard_payload["detection_type"] == "RULE_BASED"
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


def test_clipboard_destination_requires_same_window_and_process():
    assert is_same_paste_destination(101, "Chrome.EXE", 101, "chrome.exe") is True
    assert is_same_paste_destination(101, "chrome.exe", 202, "chrome.exe") is False
    assert is_same_paste_destination(101, "chrome.exe", 101, "notepad.exe") is False
    assert is_same_paste_destination(0, "chrome.exe", 101, "chrome.exe") is False


@pytest.mark.parametrize("action", ["allow", "review"])
def test_clipboard_failed_release_is_recorded_once_as_warned(action):
    event_logger = Mock()
    release = Mock(return_value=False)
    review = Mock()

    _run_clipboard_worker(
        action,
        event_logger=event_logger,
        release=release,
        review=review,
    )

    release.assert_called_once_with()
    review.assert_not_called()
    event_logger.log.assert_called_once()
    logged = event_logger.log.call_args.kwargs
    assert logged["action"] == "review"
    assert logged["extra"]["event_id"] == "clipboard-event-1"
    assert logged["extra"]["ai_score"] == 0.3
    assert logged["extra"]["model_version"] == "koelectra-dlp-v7"
    assert "붙여넣기 재발행 미수행" in logged["extra"]["reason"]


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
    if failure_stage in {"build", "analyze"}:
        event_logger.log.assert_called_once()
        logged = event_logger.log.call_args.kwargs
        assert logged["action"] == "allowed"
        assert logged["extra"]["model_version"] == "unavailable"
        assert logged["extra"]["detection_type"] == "RULE_BASED"
        assert logged["extra"]["event_id"]


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
    assert logged["extra"]["detection_type"] == "RULE_BASED"
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


def _outlook_mail_item(save=None, body="", attachments=None):
    recipient = SimpleNamespace(Address="outside@example.com")
    recipients = SimpleNamespace(Count=1, Item=lambda index: recipient)
    return SimpleNamespace(
        Class=43,
        Recipients=recipients,
        Body=body,
        Attachments=attachments or SimpleNamespace(Count=0),
        Save=save or Mock(),
        Move=Mock(),
        Application=SimpleNamespace(
            Session=SimpleNamespace(GetDefaultFolder=Mock())
        ),
    )


@pytest.mark.parametrize(
    ("primary_smtp", "expected_recipient"),
    [
        ("outside@example.com", "outside@example.com"),
        ("", "SMTP 확인 불가 Exchange 수신자"),
    ],
)
def test_outlook_exchange_recipient_is_resolved_or_inspected_conservatively(
    monkeypatch, primary_smtp, expected_recipient
):
    monkeypatch.setattr("network_hook.outlook_hook._collect_text", lambda *args: "sensitive")
    exchange_user = SimpleNamespace(PrimarySmtpAddress=primary_smtp)
    entry = SimpleNamespace(
        Type="EX",
        GetExchangeUser=lambda: exchange_user,
        GetExchangeDistributionList=lambda: None,
    )
    recipient = SimpleNamespace(
        Address="/O=ORG/OU=EXCHANGE/CN=RECIPIENTS/CN=USER",
        AddressEntry=entry,
    )
    item = _outlook_mail_item()
    item.Recipients = SimpleNamespace(Count=1, Item=lambda index: recipient)
    captured = {}

    def capture_recipient_context(text, hits, process):
        captured["text"] = text
        return "allow"

    cancelled = _handle_item_send(
        item=item,
        internal_domains=frozenset({"internal.example"}),
        on_blocked=capture_recipient_context,
        inspect=lambda text: [{"id": "rrn"}],
        file_inspector_extract=lambda data, name: None,
    )

    assert cancelled is False
    assert expected_recipient in captured["text"]


def test_outlook_ai_payload_contains_inspected_body_and_attachment_content():
    sensitive_value = "900101-1234567"
    body = "외부 공유 메일 본문입니다."
    attachment = SimpleNamespace(
        FileName="sensitive.txt",
        SaveAsFile=lambda path: Path(path).write_bytes(
            f"첨부 문서의 주민등록번호는 {sensitive_value} 입니다.".encode()
        ),
    )
    attachments = SimpleNamespace(Count=1, Item=lambda index: attachment)
    hit = {
        "id": "rrn",
        "name": "주민등록번호",
        "severity": "critical",
        "regex": r"\d{6}-\d{7}",
    }
    captured = {}

    def inspect(text):
        assert sensitive_value in text
        return [hit]

    def analyze(text, hits, process):
        captured["payload"] = PayloadBuilder(
            context_chars=256,
            user_id="presenter",
        ).build(text, hits, "outlook", process)
        return "allow"

    cancelled = _handle_item_send(
        item=_outlook_mail_item(body=body, attachments=attachments),
        internal_domains=frozenset({"internal.example"}),
        on_blocked=analyze,
        inspect=inspect,
        file_inspector_extract=lambda data, name: data.decode(),
    )

    payload = captured["payload"]
    request = payload.to_dict()
    assert cancelled is False
    assert body in request["snippet"]
    assert "[첨부: sensitive.txt]" in request["snippet"]
    assert sensitive_value in request["snippet"]
    assert "outside@example.com" in request["snippet"]
    assert request["metadata"]["app"] == "outlook.exe"
    assert request["matched_patterns"] == ["rrn"]
    assert [match.match for match in payload.matched_patterns] == [sensitive_value]


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


def _web_extract_addon(file_inspector):
    return _DLPAddon(
        inspect_domains=[],
        rule_filter=Mock(),
        payload_builder=Mock(),
        api_client=Mock(),
        event_logger=Mock(),
        file_inspector=file_inspector,
        log_traffic=False,
    )


def test_dropbox_docx_uses_api_filename_before_generic_binary_detection():
    body = b"PK\x03\x04docx-content"
    file_inspector = SimpleNamespace(
        extract_from_bytes=Mock(return_value="sensitive document text")
    )
    addon = _web_extract_addon(file_inspector)
    flow = SimpleNamespace(
        request=SimpleNamespace(
            method="POST",
            pretty_url="https://content.dropboxapi.com/2/files/upload",
            pretty_host="content.dropboxapi.com",
            content=body,
            headers={
                "content-type": "application/octet-stream",
                "dropbox-api-arg": json.dumps({"path": "/reports/sensitive.docx"}),
            },
        )
    )

    extracted = addon._extract_text(flow)

    assert extracted == "sensitive document text"
    file_inspector.extract_from_bytes.assert_called_once_with(
        body,
        "sensitive.docx",
    )


@pytest.mark.parametrize(
    ("host", "url", "method"),
    [
        ("graph.microsoft.com", "https://graph.microsoft.com/v1.0/drive/root:/a.txt:/content", "PUT"),
        ("upload.box.com", "https://upload.box.com/api/2.0/files/content", "POST"),
        ("fs.mybox.naver.com", "https://fs.mybox.naver.com/file/upload.api", "POST"),
    ],
)
def test_cloud_service_branch_runs_before_generic_binary_detection(
    monkeypatch,
    host,
    url,
    method,
):
    addon = _web_extract_addon(Mock())
    extract_binary = Mock(return_value="service-specific extraction")
    monkeypatch.setattr(addon, "_extract_upload_binary", extract_binary)
    monkeypatch.setattr(
        addon,
        "_is_drive_upload",
        Mock(side_effect=AssertionError("generic branch ran first")),
    )
    flow = SimpleNamespace(
        request=SimpleNamespace(
            method=method,
            pretty_url=url,
            pretty_host=host,
            content=b"sensitive content",
            headers={"content-type": "application/octet-stream"},
        )
    )

    assert addon._extract_text(flow) == "service-specific extraction"
    extract_binary.assert_called_once()


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


@pytest.mark.parametrize("failure_stage", ["build", "analyze"])
def test_web_ai_pipeline_failure_is_recorded_fail_open(monkeypatch, failure_stage):
    _install_fake_mitmproxy_response(monkeypatch)
    builder = Mock()
    builder.build.return_value = SimpleNamespace(request_id="web-fail-open-1")
    api_client = SimpleNamespace(is_mock=False, analyze=Mock())
    if failure_stage == "build":
        builder.build.side_effect = RuntimeError("payload failed")
    else:
        api_client.analyze.side_effect = RuntimeError("analysis failed")
    event_logger = Mock()
    addon = _DLPAddon(
        inspect_domains=["mail.example"],
        rule_filter=SimpleNamespace(match=lambda text: [{"id": "rrn"}]),
        payload_builder=builder,
        api_client=api_client,
        event_logger=event_logger,
        file_inspector=Mock(),
        log_traffic=False,
    )
    monkeypatch.setattr(addon, "_get_dlp_channel", lambda flow: "web_mail")
    monkeypatch.setattr(addon, "_extract_text", lambda flow: "sensitive content")
    flow = _web_flow()

    addon._handle(flow)

    assert flow.response is None
    event_logger.log.assert_called_once()
    logged = event_logger.log.call_args.kwargs
    assert logged["action"] == "allowed"
    assert logged["extra"]["event_id"]
    assert logged["extra"]["model_version"] == "unavailable"
    assert logged["extra"]["detection_type"] == "RULE_BASED"
    assert "Fail-Open 허용" in logged["extra"]["reason"]


@pytest.mark.parametrize("failure_stage", ["channel", "extract", "rules"])
def test_web_pre_ai_pipeline_failure_is_recorded_fail_open(monkeypatch, failure_stage):
    _install_fake_mitmproxy_response(monkeypatch)
    rule_filter = Mock()
    rule_filter.match.return_value = [{"id": "rrn"}]
    event_logger = Mock()
    addon = _DLPAddon(
        inspect_domains=["mail.example"],
        rule_filter=rule_filter,
        payload_builder=Mock(),
        api_client=SimpleNamespace(is_mock=False),
        event_logger=event_logger,
        file_inspector=Mock(),
        log_traffic=False,
    )
    flow = _web_flow()

    if failure_stage == "channel":
        monkeypatch.setattr(
            addon,
            "_get_dlp_channel",
            Mock(side_effect=RuntimeError("classifier detail must stay internal")),
        )
    else:
        monkeypatch.setattr(addon, "_get_dlp_channel", lambda candidate: "web_mail")
        if failure_stage == "extract":
            monkeypatch.setattr(
                addon,
                "_extract_text",
                Mock(side_effect=RuntimeError("extractor detail must stay internal")),
            )
        else:
            monkeypatch.setattr(addon, "_extract_text", lambda candidate: "sensitive")
            rule_filter.match.side_effect = RuntimeError("rule detail must stay internal")

    addon.request(flow)

    assert flow.response is None
    event_logger.log.assert_called_once()
    logged = event_logger.log.call_args.kwargs
    assert logged["action"] == "allowed"
    assert logged["extra"]["event_id"]
    assert logged["extra"]["model_version"] == "unavailable"
    assert logged["extra"]["detection_type"] == "RULE_BASED"
    assert "Fail-Open 허용" in logged["extra"]["reason"]
    assert "must stay internal" not in logged["extra"]["reason"]


def test_web_block_response_failure_is_recorded_as_warned(monkeypatch):
    class FailingResponse:
        @staticmethod
        def make(status_code, content, headers):
            raise RuntimeError("response creation failed")

    mitmproxy_module = ModuleType("mitmproxy")
    http_module = ModuleType("mitmproxy.http")
    http_module.Response = FailingResponse
    mitmproxy_module.http = http_module
    monkeypatch.setitem(sys.modules, "mitmproxy", mitmproxy_module)
    monkeypatch.setitem(sys.modules, "mitmproxy.http", http_module)

    event_logger = Mock()
    addon = _DLPAddon(
        inspect_domains=["mail.example"],
        rule_filter=SimpleNamespace(match=lambda text: [{"id": "rrn"}]),
        payload_builder=SimpleNamespace(
            build=lambda *args: SimpleNamespace(request_id="web-response-failure")
        ),
        api_client=SimpleNamespace(
            is_mock=False,
            analyze=lambda payload: AnalysisResult(
                request_id=payload.request_id,
                confidence_score=0.9,
                action="block",
                reason="contract decision",
                model_version="koelectra-dlp-v7",
            ),
        ),
        event_logger=event_logger,
        file_inspector=Mock(),
        log_traffic=False,
    )
    monkeypatch.setattr(addon, "_get_dlp_channel", lambda flow: "web_mail")
    monkeypatch.setattr(addon, "_extract_text", lambda flow: "sensitive content")
    monkeypatch.setattr("network_hook.web_proxy.notify_review", Mock())
    flow = _web_flow()

    addon._handle(flow)

    assert flow.response is None
    event_logger.log.assert_called_once()
    logged = event_logger.log.call_args.kwargs
    assert logged["action"] == "review"
    assert logged["extra"]["event_id"] == "web-response-failure"
    assert "451 차단 응답 생성 실패" in logged["extra"]["reason"]


def _load_usb_guard_with_win32_stubs(monkeypatch):
    win32api = ModuleType("win32api")
    win32con = ModuleType("win32con")
    win32file = ModuleType("win32file")
    win32con.DRIVE_REMOVABLE = 2
    win32con.DRIVE_FIXED = 3
    win32con.GENERIC_READ = 0x80000000
    win32con.FILE_SHARE_READ = 1
    win32con.OPEN_EXISTING = 3
    win32con.FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    win32con.FILE_ATTRIBUTE_DIRECTORY = 0x10
    win32con.FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    win32file.FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
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


_USB_ANALYSIS_FINGERPRINT = (128, 2, 12, 22, 32)
_USB_CHANGED_FINGERPRINT = (128, 2, 12, 22, 33)
_USB_VOLUME_SERIAL = 0x1234
_USB_HANDLE_FINGERPRINT = (0, _USB_VOLUME_SERIAL, 77, 128, 100, 200)
_USB_CHANGED_HANDLE_FINGERPRINT = (0, _USB_VOLUME_SERIAL, 77, 128, 100, 201)


class _UsbFakeHandle:
    def __init__(self, call_order=None, close_error=None, value=91):
        self.call_order = call_order if call_order is not None else []
        self.close_error = close_error
        self.close_calls = 0
        self.value = value

    def Close(self):
        self.call_order.append("close")
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error

    def __int__(self):
        return self.value


def _usb_guard_for_decision(
    monkeypatch,
    usb_guard,
    *,
    decision="block",
    final_handle_fingerprint=_USB_HANDLE_FINGERPRINT,
    disposition_error=None,
    close_error=None,
    payload_error=None,
    event_error=None,
):
    call_order = []
    handle = _UsbFakeHandle(call_order, close_error)
    monkeypatch.setattr(
        usb_guard,
        "_wait_for_stable_file",
        lambda path: _USB_ANALYSIS_FINGERPRINT,
    )
    monkeypatch.setattr(
        usb_guard,
        "_read_file_fingerprint",
        Mock(return_value=_USB_ANALYSIS_FINGERPRINT),
    )
    monkeypatch.setattr(usb_guard, "_open_file_handle", Mock(return_value=handle))

    handle_states = iter([_USB_HANDLE_FINGERPRINT, final_handle_fingerprint])

    def read_handle_fingerprint(candidate):
        call_order.append("handle_fingerprint")
        state = next(handle_states)
        if isinstance(state, BaseException):
            raise state
        return state

    handle_fingerprint = Mock(side_effect=read_handle_fingerprint)
    monkeypatch.setattr(usb_guard, "_handle_fingerprint", handle_fingerprint)
    read_handle = Mock(return_value=b"sensitive bytes")
    monkeypatch.setattr(usb_guard, "_read_handle_bytes", read_handle)

    def mark_delete(candidate):
        call_order.append("disposition")
        if disposition_error is not None:
            raise disposition_error

    disposition = Mock(side_effect=mark_delete)
    monkeypatch.setattr(usb_guard, "_mark_delete_on_close", disposition)
    review_notice = Mock(side_effect=RuntimeError("review popup unavailable"))
    monkeypatch.setattr(usb_guard, "notify_review", review_notice)

    file_inspector = Mock()
    file_inspector.extract_from_bytes.return_value = (
        "sensitive content long enough for inspection"
    )
    payload_builder = Mock()
    if payload_error is None:
        payload_builder.build.return_value = SimpleNamespace(
            request_id="usb-decision-1"
        )
    else:
        payload_builder.build.side_effect = payload_error
    api_client = SimpleNamespace(
        is_mock=False,
        analyze=Mock(
            return_value=AnalysisResult(
                request_id="usb-decision-1",
                confidence_score=0.9 if decision == "block" else 0.3,
                action=decision,
                reason="contract decision",
                model_version="koelectra-dlp-v7",
            )
        ),
    )
    event_logger = Mock()

    def log_event(**kwargs):
        call_order.append("log")
        if event_error is not None:
            raise event_error

    event_logger.log.side_effect = log_event
    blocked_notice = Mock(side_effect=RuntimeError("blocked popup unavailable"))

    guard = usb_guard.UsbGuardUserMode.__new__(usb_guard.UsbGuardUserMode)
    guard._lock = usb_guard.threading.Lock()
    guard._inflight_paths = set()
    guard._max_size = 1024
    guard._fi = file_inspector
    guard._rf = SimpleNamespace(match=lambda text: [{"id": "rrn"}])
    guard._pb = payload_builder
    guard._ac = api_client
    guard._el = event_logger
    guard._on_blocked = blocked_notice

    return SimpleNamespace(
        guard=guard,
        handle=handle,
        handle_fingerprint=handle_fingerprint,
        read_handle=read_handle,
        disposition=disposition,
        review_notice=review_notice,
        blocked_notice=blocked_notice,
        event_logger=event_logger,
        file_inspector=file_inspector,
        api_client=api_client,
        call_order=call_order,
    )


def test_usb_file_stability_waits_for_unchanged_size_and_mtime(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    observations = iter(
        [
            SimpleNamespace(
                st_size=64,
                st_mtime_ns=1,
                st_ctime_ns=11,
                st_dev=21,
                st_ino=31,
            ),
            *[
                SimpleNamespace(
                    st_size=128,
                    st_mtime_ns=2,
                    st_ctime_ns=12,
                    st_dev=22,
                    st_ino=32,
                )
                for _ in range(5)
            ],
        ]
    )
    monkeypatch.setattr(usb_guard.os, "stat", lambda path: next(observations))
    monkeypatch.setattr(usb_guard.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(usb_guard.time, "monotonic", lambda: 0.0)

    assert (
        usb_guard._wait_for_stable_file("E:\\sensitive.txt")
        == _USB_ANALYSIS_FINGERPRINT
    )


def test_usb_file_stability_stops_when_file_disappears(monkeypatch, caplog):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    monkeypatch.setattr(
        usb_guard.os,
        "stat",
        Mock(side_effect=FileNotFoundError("gone")),
    )

    with caplog.at_level("WARNING"):
        assert usb_guard._wait_for_stable_file("E:\\sensitive.txt") is None

    assert "안정화 중 파일이 사라져 검사 종료" in caplog.text


def test_usb_file_stability_timeout_is_finite(monkeypatch, caplog):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    clock = [0.0]
    sample = [0]

    def changing_stat(path):
        sample[0] += 1
        return SimpleNamespace(
            st_size=sample[0],
            st_mtime_ns=sample[0],
            st_ctime_ns=sample[0],
            st_dev=1,
            st_ino=1,
        )

    def advance(seconds):
        clock[0] += seconds

    monkeypatch.setattr(usb_guard, "_FILE_STABLE_TIMEOUT_SEC", 0.5)
    monkeypatch.setattr(usb_guard.os, "stat", changing_stat)
    monkeypatch.setattr(usb_guard.time, "sleep", advance)
    monkeypatch.setattr(usb_guard.time, "monotonic", lambda: clock[0])

    with caplog.at_level("WARNING"):
        assert usb_guard._wait_for_stable_file("E:\\sensitive.txt") is None

    assert clock[0] == 0.5
    assert "파일 안정화 시간 초과로 검사 종료" in caplog.text


def test_usb_unstable_file_is_not_inspected_or_deleted(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    monkeypatch.setattr(usb_guard, "_wait_for_stable_file", lambda path: None)
    open_handle = Mock()
    monkeypatch.setattr(usb_guard, "_open_file_handle", open_handle)

    guard = usb_guard.UsbGuardUserMode.__new__(usb_guard.UsbGuardUserMode)
    guard._fi = Mock()
    guard._inspect_stable_file(
        "E:\\sensitive.txt",
        "E:",
        _USB_VOLUME_SERIAL,
    )

    guard._fi.extract_from_bytes.assert_not_called()
    open_handle.assert_not_called()


def test_usb_payload_failure_has_stable_fail_open_event_id(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    state = _usb_guard_for_decision(
        monkeypatch,
        usb_guard,
        decision="allow",
        payload_error=RuntimeError("payload failed"),
    )

    state.guard._inspect_file(
        "E:\\sensitive.txt",
        "E:",
        _USB_VOLUME_SERIAL,
    )

    state.event_logger.log.assert_called_once()
    logged = state.event_logger.log.call_args.kwargs
    assert logged["action"] == "allowed"
    assert logged["extra"]["event_id"]
    assert logged["extra"]["model_version"] == "unavailable"
    assert logged["extra"]["detection_type"] == "RULE_BASED"
    assert state.handle.close_calls == 1
    state.disposition.assert_not_called()


def test_usb_file_inspection_deduplicates_inflight_path(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    started = usb_guard.threading.Event()
    release = usb_guard.threading.Event()

    def inspect_once(file_path, drive, volume_serial):
        assert volume_serial == _USB_VOLUME_SERIAL
        started.set()
        assert release.wait(1.0)

    guard = usb_guard.UsbGuardUserMode.__new__(usb_guard.UsbGuardUserMode)
    guard._lock = usb_guard.threading.Lock()
    guard._inflight_paths = set()
    guard._inspect_stable_file = Mock(side_effect=inspect_once)

    worker = usb_guard.threading.Thread(
        target=guard._inspect_file,
        args=("E:\\sensitive.txt", "E:", _USB_VOLUME_SERIAL),
    )
    worker.start()
    assert started.wait(1.0)

    guard._inspect_file("E:\\sensitive.txt", "E:", _USB_VOLUME_SERIAL)
    assert guard._inspect_stable_file.call_count == 1

    release.set()
    worker.join(1.0)
    assert not worker.is_alive()

    guard._inspect_file("E:\\sensitive.txt", "E:", _USB_VOLUME_SERIAL)
    assert guard._inspect_stable_file.call_count == 2


@pytest.mark.parametrize(
    (
        "decision",
        "final_handle_fingerprint",
        "disposition_error",
        "close_error",
        "expected_disposition_count",
        "expected_log_action",
        "expected_blocked_notices",
        "expected_review_notices",
        "expected_failure_reason",
    ),
    [
        (
            "block",
            _USB_HANDLE_FINGERPRINT,
            None,
            None,
            1,
            "blocked",
            1,
            0,
            None,
        ),
        (
            "block",
            _USB_HANDLE_FINGERPRINT,
            PermissionError("file locked"),
            None,
            1,
            "review",
            0,
            1,
            "USB 파일 삭제 예약 실패",
        ),
        (
            "block",
            _USB_CHANGED_HANDLE_FINGERPRINT,
            None,
            None,
            0,
            "review",
            0,
            1,
            "핸들 지문 변경 감지",
        ),
        (
            "block",
            OSError("fingerprint failed"),
            None,
            None,
            0,
            "review",
            0,
            1,
            "삭제 예약 실패",
        ),
        (
            "block",
            _USB_HANDLE_FINGERPRINT,
            None,
            OSError("close failed"),
            1,
            "review",
            0,
            1,
            "핸들 닫기 실패",
        ),
        (
            "review",
            _USB_HANDLE_FINGERPRINT,
            None,
            None,
            0,
            "review",
            0,
            1,
            None,
        ),
        (
            "allow",
            _USB_HANDLE_FINGERPRINT,
            None,
            None,
            0,
            "allowed",
            0,
            0,
            None,
        ),
        (
            "allow",
            _USB_HANDLE_FINGERPRINT,
            None,
            OSError("close failed"),
            0,
            "review",
            0,
            1,
            "핸들 해제 상태 미확인",
        ),
    ],
)
def test_usb_file_action_survives_event_and_notifier_failures(
    monkeypatch,
    decision,
    final_handle_fingerprint,
    disposition_error,
    close_error,
    expected_disposition_count,
    expected_log_action,
    expected_blocked_notices,
    expected_review_notices,
    expected_failure_reason,
):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    state = _usb_guard_for_decision(
        monkeypatch,
        usb_guard,
        decision=decision,
        final_handle_fingerprint=final_handle_fingerprint,
        disposition_error=disposition_error,
        close_error=close_error,
        event_error=RuntimeError("event store unavailable"),
    )

    state.guard._inspect_file(
        "E:\\sensitive.txt",
        "E:",
        _USB_VOLUME_SERIAL,
    )

    assert state.disposition.call_count == expected_disposition_count
    assert state.handle.close_calls == 1
    assert state.event_logger.log.call_count == 1
    assert state.event_logger.log.call_args.kwargs["action"] == expected_log_action
    assert state.blocked_notice.call_count == expected_blocked_notices
    assert state.review_notice.call_count == expected_review_notices
    state.file_inspector.extract_from_bytes.assert_called_once_with(
        b"sensitive bytes",
        "sensitive.txt",
    )
    assert state.call_order.index("close") < state.call_order.index("log")
    if decision == "block":
        assert state.handle_fingerprint.call_count == 2
        if expected_disposition_count:
            assert state.call_order.index("handle_fingerprint") < state.call_order.index(
                "disposition"
            )
            assert state.call_order.index("disposition") < state.call_order.index("close")
    else:
        state.disposition.assert_not_called()
        assert state.handle_fingerprint.call_count == 1

    extra = state.event_logger.log.call_args.kwargs["extra"]
    assert extra["event_id"] == "usb-decision-1"
    assert extra["model_version"] == "koelectra-dlp-v7"
    if expected_log_action == "review" and decision == "block":
        assert extra["ai_score"] == 0.9
        assert "실제 차단 미확인" in extra["reason"]
    if expected_failure_reason:
        assert expected_failure_reason in extra["reason"]


@pytest.mark.parametrize(
    ("attributes", "expected_volume", "path_fingerprint", "handle_error"),
    [
        (0x10, _USB_VOLUME_SERIAL, _USB_ANALYSIS_FINGERPRINT, None),
        (0x400, _USB_VOLUME_SERIAL, _USB_ANALYSIS_FINGERPRINT, None),
        (0, _USB_VOLUME_SERIAL + 1, _USB_ANALYSIS_FINGERPRINT, None),
        (0, _USB_VOLUME_SERIAL, _USB_CHANGED_FINGERPRINT, None),
        (0, _USB_VOLUME_SERIAL, _USB_ANALYSIS_FINGERPRINT, OSError("info failed")),
    ],
)
def test_usb_unsafe_handle_target_aborts_before_content_or_ai(
    monkeypatch,
    attributes,
    expected_volume,
    path_fingerprint,
    handle_error,
):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    handle = _UsbFakeHandle()
    monkeypatch.setattr(
        usb_guard,
        "_wait_for_stable_file",
        lambda path: _USB_ANALYSIS_FINGERPRINT,
    )
    monkeypatch.setattr(usb_guard, "_open_file_handle", Mock(return_value=handle))
    if handle_error is not None:
        monkeypatch.setattr(
            usb_guard,
            "_handle_fingerprint",
            Mock(side_effect=handle_error),
        )
    else:
        monkeypatch.setattr(
            usb_guard,
            "_handle_fingerprint",
            Mock(
                return_value=(
                    attributes,
                    _USB_VOLUME_SERIAL,
                    77,
                    128,
                    100,
                    200,
                )
            ),
        )
    monkeypatch.setattr(
        usb_guard,
        "_read_file_fingerprint",
        Mock(return_value=path_fingerprint),
    )
    read_handle = Mock()
    monkeypatch.setattr(usb_guard, "_read_handle_bytes", read_handle)
    disposition = Mock()
    monkeypatch.setattr(usb_guard, "_mark_delete_on_close", disposition)

    guard = usb_guard.UsbGuardUserMode.__new__(usb_guard.UsbGuardUserMode)
    guard._max_size = 1024
    guard._fi = Mock()
    guard._rf = Mock()
    guard._pb = Mock()
    guard._ac = Mock()
    guard._el = Mock()
    guard._on_blocked = Mock()

    guard._inspect_stable_file(
        "E:\\sensitive.txt",
        "E:",
        expected_volume,
    )

    assert handle.close_calls == 1
    read_handle.assert_not_called()
    guard._fi.extract_from_bytes.assert_not_called()
    guard._ac.analyze.assert_not_called()
    disposition.assert_not_called()
    guard._el.log.assert_not_called()


def test_usb_open_handle_denies_write_and_delete_sharing(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    handle = _UsbFakeHandle()
    create_file = Mock(return_value=handle)
    usb_guard.win32file.CreateFile = create_file

    assert usb_guard._open_file_handle("E:\\sensitive.txt") is handle

    args = create_file.call_args.args
    assert args[1] == usb_guard.win32con.GENERIC_READ | usb_guard._DELETE_ACCESS
    assert args[2] == usb_guard.win32con.FILE_SHARE_READ
    assert args[5] == (
        usb_guard.win32file.FILE_FLAG_OPEN_REPARSE_POINT
        | usb_guard.win32con.FILE_FLAG_BACKUP_SEMANTICS
    )


def test_usb_handle_information_uses_win32_identity_fields(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    handle = _UsbFakeHandle()
    usb_guard.win32file.GetFileInformationByHandle = Mock(
        return_value=(
            0x20,
            100,
            110,
            120,
            _USB_VOLUME_SERIAL,
            0,
            128,
            1,
            0,
            77,
        )
    )

    assert usb_guard._handle_volume_serial(handle) == _USB_VOLUME_SERIAL
    assert usb_guard._handle_fingerprint(handle) == (
        0x20,
        _USB_VOLUME_SERIAL,
        77,
        128,
        100,
        120,
    )


def test_usb_reads_exact_bytes_from_one_handle(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    handle = _UsbFakeHandle()
    usb_guard.win32file.SetFilePointer = Mock()
    usb_guard.win32file.ReadFile = Mock(
        side_effect=[(0, b"abc"), (0, b"def")]
    )

    assert usb_guard._read_handle_bytes(handle, 6) == b"abcdef"
    usb_guard.win32file.SetFilePointer.assert_called_once_with(handle, 0, 0)
    assert usb_guard.win32file.ReadFile.call_count == 2


def test_usb_short_handle_read_fails_closed_before_analysis(monkeypatch):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    handle = _UsbFakeHandle()
    usb_guard.win32file.SetFilePointer = Mock()
    usb_guard.win32file.ReadFile = Mock(side_effect=[(0, b"abc"), (0, b"")])

    with pytest.raises(OSError, match="EOF"):
        usb_guard._read_handle_bytes(handle, 6)


@pytest.mark.parametrize("api_result", [1, 0])
def test_usb_file_disposition_info_ctypes_contract(monkeypatch, api_result):
    usb_guard = _load_usb_guard_with_win32_stubs(monkeypatch)
    captured = {}

    class FakeSetFileInformation:
        def __call__(self, handle, info_class, info_pointer, info_size):
            captured["handle"] = handle.value
            captured["class"] = info_class
            captured["delete_file"] = usb_guard.ctypes.cast(
                info_pointer,
                usb_guard.ctypes.POINTER(usb_guard._FileDispositionInfo),
            ).contents.delete_file
            captured["size"] = info_size
            return api_result

    fake_api = FakeSetFileInformation()
    kernel32 = SimpleNamespace(SetFileInformationByHandle=fake_api)
    monkeypatch.setattr(
        usb_guard.ctypes,
        "WinDLL",
        lambda name, use_last_error: kernel32,
        raising=False,
    )
    monkeypatch.setattr(
        usb_guard.ctypes,
        "get_last_error",
        lambda: 5,
        raising=False,
    )
    monkeypatch.setattr(
        usb_guard.ctypes,
        "FormatError",
        lambda error: "access denied",
        raising=False,
    )
    handle = _UsbFakeHandle(value=123)

    if api_result:
        usb_guard._mark_delete_on_close(handle)
    else:
        with pytest.raises(OSError) as exc_info:
            usb_guard._mark_delete_on_close(handle)
        assert exc_info.value.errno == 5

    assert captured == {
        "handle": 123,
        "class": 4,
        "delete_file": 1,
        "size": usb_guard.ctypes.sizeof(usb_guard._FileDispositionInfo),
    }
