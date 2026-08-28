from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest

from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore
from scripts import flush_dashboard_logs


class _Response:
    status_code = 201

    def __init__(self, error: Exception | None = None) -> None:
        self._error = error

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error


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
        lambda *args, **kwargs: _Response(),
    )

    assert event_logger.flush_to_server() == 3


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
    responses = iter(
        [
            _Response(),
            _Response(RuntimeError("server unavailable")),
            _Response(),
            _Response(RuntimeError("server unavailable")),
        ]
    )
    monkeypatch.setattr(
        "core_comm.event_logger.requests.post",
        lambda *args, **kwargs: next(responses),
    )

    assert event_logger.flush_to_server() == 2


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
def test_flush_cli_replays_active_log_and_reports_partial_failure(
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
        lambda *args, **kwargs: _Response(post_error),
    )

    assert flush_dashboard_logs.main(["--project-root", str(tmp_path)]) == expected_exit
    output = capsys.readouterr().out
    assert "attempted=1" in output
    assert f"successful_posts={1 if post_error is None else 0}" in output
