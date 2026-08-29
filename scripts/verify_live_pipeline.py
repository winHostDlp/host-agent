"""Verify one synthetic Host -> AI -> JSONL -> Web server pipeline event."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Sequence

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core_comm.analysis_events import record_analysis_result
from core_comm.api_client import ApiClient
from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore
from core_comm.payload_builder import PayloadBuilder
from scripts.demo_preflight import EXPECTED_MODEL_VERSION, _valid_base_url
from scripts.flush_dashboard_logs import _load_settings


MARKER_PATTERN_ID = "dlp_test_allow"
MARKER_TEXT = "SERVER_PIPELINE_R013 >> 확인완료"
SCOPE = "SERVER_PIPELINE"


class PipelineError(Exception):
    """Expected verification failure represented by a safe error code."""

    def __init__(
        self,
        code: str,
        evidence_path: Path | None = None,
        evidence_sha256: str | None = None,
    ) -> None:
        self.code = code
        self.evidence_path = evidence_path
        self.evidence_sha256 = evidence_sha256
        super().__init__(code)


def _mapping(value: Any, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PipelineError(code)
    return value


def _configured_pipeline(project_root: Path) -> tuple[dict[str, Any], ...]:
    try:
        settings = _load_settings(project_root)
    except Exception as exc:
        raise PipelineError("CONFIG_INVALID") from exc

    server = _mapping(settings.get("server"), "CONFIG_INVALID")
    agent = _mapping(settings.get("agent") or {}, "CONFIG_INVALID")
    logging_cfg = _mapping(settings.get("logging") or {}, "CONFIG_INVALID")
    ai_url = str(server.get("ai_base_url") or "").strip()
    dashboard_url = str(server.get("dashboard_url") or "").strip()
    ai_token = str(os.environ.get("AI_API_TOKEN") or server.get("ai_token") or "").strip()
    dashboard_token = str(
        os.environ.get("AGENT_API_TOKEN") or server.get("dashboard_token") or ""
    ).strip()
    viewer_username = os.environ.get("DASHBOARD_VIEWER_USERNAME", "")
    viewer_password = os.environ.get("DASHBOARD_VIEWER_PASSWORD", "")

    if not _valid_base_url(ai_url, require_remote=False) or not ai_token:
        raise PipelineError("AI_CONFIG_INVALID")
    if not _valid_base_url(dashboard_url, require_remote=False) or not dashboard_token:
        raise PipelineError("WEB_CONFIG_INVALID")
    if bool(viewer_username) != bool(viewer_password):
        raise PipelineError("WEB_CONFIG_INVALID")
    if viewer_username and viewer_password:
        try:
            viewer_username.encode("ascii")
            viewer_password.encode("ascii")
        except UnicodeEncodeError as exc:
            raise PipelineError("WEB_CONFIG_INVALID") from exc
        if ":" in viewer_username or len(viewer_password) < 16:
            raise PipelineError("WEB_CONFIG_INVALID")
    return server, agent, logging_cfg, {
        "ai_url": ai_url,
        "ai_token": ai_token,
        "dashboard_url": dashboard_url,
        "dashboard_token": dashboard_token,
        "viewer_auth": (
            (viewer_username, viewer_password)
            if viewer_username and viewer_password
            else None
        ),
    }


def _marker_hit(project_root: Path, agent: dict[str, Any]) -> dict[str, Any]:
    patterns_path = Path(agent.get("regex_patterns") or "config/regex_patterns.json")
    if not patterns_path.is_absolute():
        patterns_path = project_root / patterns_path
    try:
        data = json.loads(patterns_path.read_text(encoding="utf-8"))
        hits = [
            hit
            for hit in data.get("patterns", [])
            if isinstance(hit, dict)
            and hit.get("id") == MARKER_PATTERN_ID
            and isinstance(hit.get("regex"), str)
            and hit["regex"]
            and re.search(hit["regex"], MARKER_TEXT)
        ]
    except Exception as exc:
        raise PipelineError("MARKER_CONFIG_INVALID") from exc
    if len(hits) != 1:
        raise PipelineError("MARKER_CONFIG_INVALID")
    return hits[0]


def _read_single_record(store: LocalEventStore, event_id: str) -> dict[str, Any]:
    try:
        lines = [
            line
            for line in store._active_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        record = json.loads(lines[0]) if len(lines) == 1 else None
    except Exception as exc:
        raise PipelineError("JSONL_INVALID") from exc
    if not isinstance(record, dict):
        raise PipelineError("JSONL_INVALID")
    extra = record.get("extra")
    hit_ids = [hit.get("id") for hit in record.get("hits", []) if isinstance(hit, dict)]
    if (
        not isinstance(extra, dict)
        or extra.get("event_id") != event_id
        or extra.get("model_version") != EXPECTED_MODEL_VERSION
        or extra.get("detection_type") != "HYBRID"
        or hit_ids != [MARKER_PATTERN_ID]
    ):
        raise PipelineError("JSONL_INVALID")
    return record


def _read_back(
    dashboard_url: str,
    dashboard_token: str,
    viewer_auth: tuple[str, str] | None,
    timeout: float,
    expected_payload: dict[str, Any],
) -> dict[str, Any]:
    event_id = expected_payload["event_id"]
    try:
        response = requests.get(
            dashboard_url.rstrip("/") + "/api/v1/logs",
            params={"q": event_id, "limit": 50},
            headers={"X-Agent-Token": dashboard_token},
            auth=viewer_auth,
            timeout=timeout,
        )
        response.raise_for_status()
        body = response.json()
    except Exception as exc:
        raise PipelineError("WEB_READBACK_FAILED") from exc

    items = body.get("items") if isinstance(body, dict) else None
    exact = (
        [item for item in items if isinstance(item, dict) and item.get("event_id") == event_id]
        if isinstance(items, list)
        else []
    )
    if len(exact) != 1:
        raise PipelineError("WEB_READBACK_INVALID")
    item = exact[0]
    log_id = item.get("log_id")
    if (
        not isinstance(log_id, int)
        or isinstance(log_id, bool)
        or log_id < 1
        or item.get("model_version") != expected_payload.get("model_version")
        or item.get("detection_type") != expected_payload.get("detection_type")
        or item.get("leak_channel") != expected_payload.get("leak_channel")
        or item.get("action_taken") != expected_payload.get("action_taken")
    ):
        raise PipelineError("WEB_READBACK_INVALID")
    return item


def _verify(project_root: Path, evidence_root: Path) -> dict[str, Any]:
    server, agent, logging_cfg, endpoints = _configured_pipeline(project_root)
    timeout = float(server.get("request_timeout_sec", 10))
    marker_hit = _marker_hit(project_root, agent)
    builder = PayloadBuilder(
        max_text_chars=agent.get("ai_max_text_chars", 4000),
        max_per_pattern=agent.get("ai_max_matches_per_pattern", 10),
        context_chars=agent.get("ai_context_chars", 200),
        user_id=agent.get("user_id") or os.environ.get("USERNAME", ""),
    )
    client = ApiClient(endpoints["ai_url"], timeout, endpoints["ai_token"])
    if client.is_mock:
        raise PipelineError("AI_CONFIG_INVALID")

    event_started = time.perf_counter()
    payload = builder.build(MARKER_TEXT, [marker_hit], "clipboard", "server-pipeline-r013")
    ai_started = time.perf_counter()
    result = client.analyze(payload)
    ai_rtt_ms = (time.perf_counter() - ai_started) * 1000
    if (
        result.analysis_failed
        or result.request_id != payload.request_id
        or result.model_version != EXPECTED_MODEL_VERSION
    ):
        raise PipelineError("AI_RESPONSE_INVALID")

    evidence_dir = evidence_root / payload.timestamp[:10] / payload.request_id
    try:
        evidence_dir.mkdir(parents=True, exist_ok=False)
    except Exception as exc:
        raise PipelineError("EVIDENCE_CREATE_FAILED") from exc
    evidence_path = evidence_dir / "events.jsonl"
    evidence_sha256: str | None = None

    try:
        store = LocalEventStore(
            evidence_dir,
            max_bytes=logging_cfg.get("max_bytes", 10 * 1024 * 1024),
            text_preview_len=logging_cfg.get("text_preview_len", 120),
        )
        logger = EventLogger(
            store=store,
            dashboard_url=endpoints["dashboard_url"],
            dashboard_token=endpoints["dashboard_token"],
            timeout=timeout,
            send_immediately=False,
            agent_id=agent.get("agent_id", ""),
            user_id=agent.get("user_id") or os.environ.get("USERNAME", ""),
            department=agent.get("department", "Unknown"),
        )
        record_analysis_result(
            logger,
            result,
            channel="clipboard",
            process_name="server-pipeline-r013",
            hits=[marker_hit],
            text=MARKER_TEXT,
            event_id=payload.request_id,
            detection_type="HYBRID",
        )
        event_to_jsonl_ms = (time.perf_counter() - event_started) * 1000
        record = _read_single_record(store, payload.request_id)
        evidence_sha256 = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        dashboard_payload = logger._build_log_payload_from_record(record)
        if dashboard_payload.get("event_id") != payload.request_id:
            raise PipelineError("WEB_PAYLOAD_INVALID")

        web_started = time.perf_counter()
        if not logger._post(dashboard_payload):
            raise PipelineError("WEB_RECEIPT_INVALID")
        web_ack_ms = (time.perf_counter() - web_started) * 1000
        stored = _read_back(
            endpoints["dashboard_url"],
            endpoints["dashboard_token"],
            endpoints["viewer_auth"],
            timeout,
            dashboard_payload,
        )
    except PipelineError as exc:
        exc.evidence_path = evidence_path
        exc.evidence_sha256 = evidence_sha256
        raise
    except Exception as exc:
        raise PipelineError("PIPELINE_FAILED", evidence_path, evidence_sha256) from exc

    return {
        "status": "PASS",
        "scope": SCOPE,
        "windows_hook_e2e": False,
        "event_id": payload.request_id,
        "model_version": result.model_version,
        "action": result.action,
        "log_id": stored["log_id"],
        "evidence_path": str(evidence_path.resolve()),
        "evidence_sha256": evidence_sha256,
        "ai_rtt_ms": round(ai_rtt_ms, 3),
        "event_to_jsonl_ms": round(event_to_jsonl_ms, 3),
        "web_ack_ms": round(web_ack_ms, 3),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Send one synthetic marker through the real AI, Host JSONL, and Web APIs. "
            "This verifies SERVER_PIPELINE only, not Windows hook E2E."
        )
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="Host Agent project root containing config/settings.yaml.",
    )
    parser.add_argument(
        "--evidence-root",
        type=Path,
        help=(
            "Directory that keeps one <event_id>/events.jsonl evidence file. "
            "Relative paths are resolved from the project root."
        ),
    )
    args = parser.parse_args(argv)
    project_root = args.project_root.resolve()
    evidence_root = args.evidence_root or Path("logs/server-pipeline-evidence")
    if not evidence_root.is_absolute():
        evidence_root = project_root / evidence_root

    try:
        output = _verify(project_root, evidence_root)
    except PipelineError as exc:
        output = {
            "status": "FAIL",
            "scope": SCOPE,
            "windows_hook_e2e": False,
            "error_code": exc.code,
        }
        if exc.evidence_path is not None:
            output["evidence_path"] = str(exc.evidence_path.resolve())
        if exc.evidence_sha256 is not None:
            output["evidence_sha256"] = exc.evidence_sha256
        exit_code = 1
    except Exception:
        output = {
            "status": "FAIL",
            "scope": SCOPE,
            "windows_hook_e2e": False,
            "error_code": "UNEXPECTED_ERROR",
        }
        exit_code = 1
    else:
        exit_code = 0

    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
