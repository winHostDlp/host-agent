from __future__ import annotations

import json
import threading
from typing import Any
from unittest.mock import Mock

import pytest

from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore
from scripts import flush_dashboard_logs


class _Response:
    status_code = 201

    def __init__(
        self,
        error: Exception | None = None,
        body: dict[str, Any] | None = None,
    ) -> None:
        self._error = error
        self._body = body

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error

    def json(self) -> dict[str, Any] | None:
        return self._body


def _accepted_response(
    *args: Any,
    error: Exception | None = None,
    **kwargs: Any,
) -> _Response:
    payload = kwargs["json"]
    return _Response(
        error=error,
        body={"event_id": payload["event_id"], "log_id": 1, "duplicate": False},
    )


def _logger_with_records(tmp_path: Any, count: int) -> EventLogger:
    store = LocalEventStore(tmp_path)
    for index in range(count):
        store.write(
            channel="clipboard",
            action="allowed",
            process_name=f"process-{index}",
            hits=[],
        )
    return EventLogger(store=store, dashboard_url="https://dashboard.test")


def test_flush_counts_all_successful_posts(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    event_logger = _logger_with_records(tmp_path, count=3)
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        _accepted_response,
    )

    assert event_logger.flush_to_server() == 3


def test_failed_immediate_send_replays_persisted_id_and_accepts_duplicate_receipt(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalEventStore(tmp_path)
    event_logger = EventLogger(
        store=store,
        dashboard_url="https://dashboard.test",
        send_immediately=True,
    )
    posted: list[dict[str, Any]] = []
    original_extra = {"reason": "stable delivery id"}
    responses = iter(
        [
            _Response(RuntimeError("offline")),
            _Response(RuntimeError("offline")),
            _Response(RuntimeError("offline")),
            _Response(
                body={
                    "event_id": "filled-after-local-write",
                    "log_id": 7,
                    "duplicate": True,
                }
            ),
        ]
    )

    class ImmediateThread:
        def __init__(self, *, target: Any, args: tuple[Any, ...], **_: Any) -> None:
            self._target = target
            self._args = args

        def start(self) -> None:
            self._target(*self._args)

    monkeypatch.setattr("core_comm.event_logger.threading.Thread", ImmediateThread)
    monkeypatch.setattr("core_comm.event_logger.sleep", lambda _delay: None)

    def post_in_sequence(*args: Any, **kwargs: Any) -> _Response:
        posted.append(kwargs["json"])
        response = next(responses)
        if response._body is not None:
            response._body["event_id"] = kwargs["json"]["event_id"]
        return response

    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        post_in_sequence,
    )

    event_logger.log(
        channel="clipboard",
        action="allowed",
        process_name="chrome.exe",
        hits=[],
        extra=original_extra,
    )

    record = json.loads(store._active_path.read_text(encoding="utf-8"))
    persisted_event_id = record["extra"]["event_id"]
    assert len(posted) == 3
    assert {payload["event_id"] for payload in posted} == {persisted_event_id}
    assert event_logger.flush_to_server() == 1
    assert posted[-1]["event_id"] == persisted_event_id
    assert "event_id" not in original_extra


def test_flush_stops_between_records_when_agent_is_stopping(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_logger = _logger_with_records(tmp_path, count=3)
    stop_event = threading.Event()
    posted: list[dict[str, Any]] = []

    def post_once(*args: Any, **kwargs: Any) -> _Response:
        posted.append(kwargs["json"])
        stop_event.set()
        return _accepted_response(*args, **kwargs)

    monkeypatch.setattr("core_comm.event_logger.requests.post", post_once)

    assert event_logger.flush_to_server(stop_event=stop_event) == 1
    assert len(posted) == 1


def test_flush_replays_rotated_and_active_logs(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalEventStore(tmp_path)
    store.write("clipboard", "allowed", "first.exe", [], extra={"event_id": "first"})
    store._active_path.rename(tmp_path / "events.2026-08-29_010101.jsonl")
    store.write("clipboard", "allowed", "second.exe", [], extra={"event_id": "second"})
    posted = []
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: (
            posted.append(kwargs["json"]) or _accepted_response(*args, **kwargs)
        ),
    )

    event_logger = EventLogger(store=store, dashboard_url="https://dashboard.test")

    assert event_logger.flush_to_server() == 2
    assert [item["event_id"] for item in posted] == ["first", "second"]


def test_flush_does_not_count_failed_posts(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    event_logger = _logger_with_records(tmp_path, count=3)
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: _Response(RuntimeError("server unavailable")),
    )

    assert event_logger.flush_to_server() == 0


def test_flush_counts_only_successful_posts_in_mixed_batch(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event_logger = _logger_with_records(tmp_path, count=4)
    errors = iter(
        [None, RuntimeError("server unavailable"), None, RuntimeError("server unavailable")]
    )
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: _accepted_response(
            *args,
            error=next(errors),
            **kwargs,
        ),
    )

    assert event_logger.flush_to_server() == 2


def test_flush_preserves_original_event_timestamp(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalEventStore(tmp_path)
    store.write(
        channel="clipboard",
        action="allowed",
        process_name="chrome.exe",
        hits=[],
        extra={"event_id": "timestamp-contract"},
    )
    original = json.loads(store._active_path.read_text(encoding="utf-8"))
    posted: list[dict[str, Any]] = []

    def capture_post(*args: Any, **kwargs: Any) -> _Response:
        posted.append(kwargs["json"])
        return _accepted_response(*args, **kwargs)

    monkeypatch.setattr("core_comm.event_logger.requests.post", capture_post)
    event_logger = EventLogger(store=store, dashboard_url="https://dashboard.test")

    assert event_logger.flush_to_server() == 1
    assert posted[0]["timestamp"] == original["timestamp"]


def test_legacy_record_with_preview_replays_with_stable_id(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalEventStore(tmp_path)
    legacy_preview = "주민등록번호 900101-1234567"
    store._active_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-08-29T00:00:00+00:00",
                "hostname": "legacy-host",
                "channel": "clipboard",
                "action": "allowed",
                "process": "legacy.exe",
                "hits": [],
                "text_preview": legacy_preview,
                "text_sha256": "legacy-hash",
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    posted: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: (
            posted.append(kwargs["json"])
            or _accepted_response(*args, **kwargs)
        ),
    )
    event_logger = EventLogger(store=store, dashboard_url="https://dashboard.test")

    assert event_logger.flush_to_server() == 1
    assert event_logger.flush_to_server() == 1
    assert len(posted) == 2
    assert posted[0]["event_id"] == posted[1]["event_id"]
    assert all(legacy_preview not in json.dumps(item, ensure_ascii=False) for item in posted)


@pytest.mark.parametrize(
    "body",
    [
        None,
        {"event_id": "different", "log_id": 1, "duplicate": False},
        {"event_id": "receipt-event", "log_id": None, "duplicate": False},
        {"event_id": "receipt-event", "log_id": 1, "duplicate": "false"},
    ],
)
def test_post_rejects_invalid_dashboard_receipt(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    body: dict[str, Any] | None,
) -> None:
    event_logger = _logger_with_records(tmp_path, count=0)
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: _Response(body=body),
    )

    assert event_logger._post({"event_id": "receipt-event"}) is False


def test_post_logs_valid_dashboard_receipt(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    event_logger = _logger_with_records(tmp_path, count=0)
    monkeypatch.setattr("core_comm.event_logger.requests.post", _accepted_response)

    with caplog.at_level("INFO", logger="core_comm.event_logger"):
        assert event_logger._post({"event_id": "receipt-event"}) is True

    assert "event_id=receipt-event log_id=1 duplicate=False" in caplog.text


def test_immediate_post_retries_until_success(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    event_logger = _logger_with_records(tmp_path, count=0)
    post = Mock(side_effect=[False, False, True])
    wait = Mock()
    monkeypatch.setattr(event_logger, "_post", post)
    monkeypatch.setattr("core_comm.event_logger.sleep", wait)

    assert event_logger._post_immediately({"event_id": "retry-ok"}) is True
    assert post.call_count == 3
    assert [call.args[0] for call in wait.call_args_list] == [0.25, 0.75]


def test_immediate_post_stops_after_bounded_retries(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_logger = _logger_with_records(tmp_path, count=0)
    post = Mock(return_value=False)
    monkeypatch.setattr(event_logger, "_post", post)
    monkeypatch.setattr("core_comm.event_logger.sleep", lambda _delay: None)

    assert event_logger._post_immediately({"event_id": "retry-failed"}) is False
    assert post.call_count == 3


@pytest.mark.parametrize(("post_error", "expected_exit"), [(None, 0), (RuntimeError("down"), 1)])
def test_flush_cli_replays_local_logs_and_reports_partial_failure(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    post_error: Exception | None,
    expected_exit: int,
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "settings.yaml").write_text(
        """
agent:
  agent_id: flush-test
  user_id: presenter
  department: QA
server:
  dashboard_url: https://dashboard.test
  dashboard_token: test-token
  request_timeout_sec: 1
logging:
  log_dir: logs
""".strip(),
        encoding="utf-8",
    )
    store = LocalEventStore(tmp_path / "logs")
    store.write(
        channel="clipboard",
        action="warned",
        process_name="chrome.exe",
        hits=[{"id": "rrn"}],
        extra={"event_id": "flush-event-1", "reason": "contract test"},
    )
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: _accepted_response(
            *args,
            error=post_error,
            **kwargs,
        ),
    )

    assert flush_dashboard_logs.main(["--project-root", str(tmp_path)]) == expected_exit
    output = capsys.readouterr().out
    assert "attempted=1" in output
    assert f"successful_posts={1 if post_error is None else 0}" in output


def test_flush_uses_local_settings_and_environment_token(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "settings.yaml").write_text(
        "server:\n  dashboard_url: http://127.0.0.1:8000\n  dashboard_token: tracked\n",
        encoding="utf-8",
    )
    (config / "settings.local.yaml").write_text(
        "server:\n  dashboard_url: https://dashboard.local\n  dashboard_token: local\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_API_TOKEN", "environment-token")

    logger = flush_dashboard_logs._build_logger(tmp_path)

    assert logger._dashboard_url == "https://dashboard.local"
    assert logger._token == "environment-token"
