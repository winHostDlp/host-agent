from __future__ import annotations

from typing import Any

import pytest

from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore


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
