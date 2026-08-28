"""Replay the active local Host event log to the configured Web dashboard."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Sequence

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore


def _load_settings(project_root: Path) -> dict[str, Any]:
    settings_path = project_root / "config" / "settings.yaml"
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    if not isinstance(settings, dict):
        raise ValueError("settings.yaml must contain a mapping")
    return settings


def _build_logger(project_root: Path) -> EventLogger:
    settings = _load_settings(project_root)
    log_cfg = settings.get("logging") or {}
    server_cfg = settings.get("server") or {}
    agent_cfg = settings.get("agent") or {}

    dashboard_url = str(server_cfg.get("dashboard_url") or "").strip()
    dashboard_token = str(server_cfg.get("dashboard_token") or "").strip()
    if not dashboard_url:
        raise ValueError("server.dashboard_url is required")
    if not dashboard_token:
        raise ValueError("server.dashboard_token is required")

    log_dir = Path(log_cfg.get("log_dir", "logs"))
    if not log_dir.is_absolute():
        log_dir = project_root / log_dir
    store = LocalEventStore(
        log_dir=log_dir,
        max_bytes=log_cfg.get("max_bytes", 10 * 1024 * 1024),
        text_preview_len=log_cfg.get("text_preview_len", 120),
    )
    user_id = agent_cfg.get("user_id") or os.environ.get("USERNAME", "")
    return EventLogger(
        store=store,
        dashboard_url=dashboard_url,
        dashboard_token=dashboard_token,
        timeout=server_cfg.get("request_timeout_sec", 10),
        send_immediately=False,
        agent_id=agent_cfg.get("agent_id", ""),
        user_id=user_id,
        department=agent_cfg.get("department", "Unknown"),
    )


def _active_record_count(logger: EventLogger) -> int:
    active_path = logger._store._active_path
    if not active_path.exists():
        return 0
    with active_path.open("r", encoding="utf-8") as stream:
        return sum(1 for line in stream if line.strip())


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Replay logs/events.jsonl after dashboard connectivity is restored. "
            "The Web API deduplicates stable event_id values."
        )
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="Host Agent project root containing config/settings.yaml.",
    )
    args = parser.parse_args(argv)

    try:
        logger = _build_logger(args.project_root.resolve())
        attempted = _active_record_count(logger)
        sent = logger.flush_to_server()
    except Exception as exc:
        print(f"[FAIL] Dashboard log replay could not start: {type(exc).__name__}: {exc}")
        return 1

    print(f"[RESULT] attempted={attempted} successful_posts={sent}")
    if sent != attempted:
        print("[FAIL] 일부 로그가 전송되지 않았습니다. 연결·토큰을 확인한 뒤 다시 실행하세요.")
        return 1
    print("[PASS] 활성 로컬 로그 재전송 완료(Web event_id 중복 방지 적용).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
