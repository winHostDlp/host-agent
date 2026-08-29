from __future__ import annotations

import base64
import hashlib
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

import pytest

from scripts import verify_live_pipeline


AI_TOKEN = "ai-test-token-never-print-0123456789"
WEB_TOKEN = "web-test-token-never-print-012345678"
VIEWER_USERNAME = "viewer-never-print"
VIEWER_PASSWORD = "viewer-password-never-print"
VIEWER_AUTHORIZATION = "Basic " + base64.b64encode(
    f"{VIEWER_USERNAME}:{VIEWER_PASSWORD}".encode()
).decode()
CHECKPOINT_SHA256 = "a" * 64
MODEL_BUNDLE_SHA256 = "c" * 64
BLOCK_THRESHOLD = 0.41
REVIEW_THRESHOLD = 0.20


def _handler(state: dict[str, Any]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def _send(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length))

        def do_POST(self) -> None:
            if self.path == "/api/v1/analyze":
                request = self._body()
                state["ai_request"] = request
                state["ai_authorization"] = self.headers.get("Authorization")
                if state.get("ai_status", 200) != 200:
                    self._send(state["ai_status"], {"detail": "AI unavailable"})
                    return
                self._send(
                    200,
                    {
                        "event_id": state.get("ai_event_id") or request["event_id"],
                        "decision": "allow",
                        "confidence_score": 0.12,
                        "model_version": state.get("model_version", "koelectra-dlp-v7"),
                        "latency_ms": 7.5,
                        "reason": "synthetic marker accepted",
                    },
                )
                return

            if self.path == "/api/v1/logs":
                request = self._body()
                state["web_request"] = request
                state["web_token"] = self.headers.get("X-Agent-Token")
                if state.get("web_status", 201) != 201:
                    self._send(state["web_status"], {"detail": "Web unavailable"})
                    return
                log_id = 17
                state["stored"] = {**request, "log_id": log_id}
                event_id = (
                    "receipt-event-id-mismatch"
                    if state.get("receipt_mismatch")
                    else request["event_id"]
                )
                self._send(
                    201,
                    {"event_id": event_id, "log_id": log_id, "duplicate": False},
                )
                return

            self._send(404, {"detail": "not found"})

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                state["ai_health_authorization"] = self.headers.get("Authorization")
                status = state.get("ai_health_http_status", 200)
                body = {
                    "status": "running",
                    "engine": "koelectra-dlp-v7",
                    "auth_required": True,
                    "checkpoint_sha256": CHECKPOINT_SHA256,
                    "model_bundle_sha256": MODEL_BUNDLE_SHA256,
                    "block_threshold": BLOCK_THRESHOLD,
                    "review_threshold": REVIEW_THRESHOLD,
                }
                body.update(state.get("ai_health_overrides", {}))
                self._send(status, body)
                return
            if parsed.path == "/health":
                state["web_health_authorization"] = self.headers.get("Authorization")
                status = state.get("web_health_http_status", 200)
                body = {
                    "status": "ok",
                    "database_status": "ok",
                    "dashboard_auth_enabled": True,
                }
                body.update(state.get("web_health_overrides", {}))
                self._send(status, body)
                return
            if parsed.path != "/api/v1/logs":
                self._send(404, {"detail": "not found"})
                return
            state["readback_token"] = self.headers.get("X-Agent-Token")
            state["readback_authorization"] = self.headers.get("Authorization")
            state["readback_query"] = parse_qs(parsed.query)
            if state.get("require_viewer_auth") and (
                state["readback_authorization"] != VIEWER_AUTHORIZATION
            ):
                self._send(401, {"detail": "viewer auth required"})
                return
            if state.get("readback_status", 200) != 200:
                self._send(state["readback_status"], {"detail": "readback unavailable"})
                return
            stored = state.get("stored")
            if state.get("readback_mismatch") and stored:
                stored = {**stored, "event_id": "readback-event-id-mismatch"}
            items = [stored] if stored else []
            self._send(200, {"items": items, "count": len(items)})

    return Handler


@contextmanager
def _http_server(state: dict[str, Any]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _write_project(project_root: Path, base_url: str) -> None:
    config = project_root / "config"
    config.mkdir()
    (config / "settings.yaml").write_text(
        f"""
server:
  ai_base_url: "{base_url}"
  ai_token: "tracked-ai-placeholder"
  dashboard_url: "{base_url}"
  dashboard_token: "tracked-web-placeholder"
  request_timeout_sec: 1
agent:
  regex_patterns: "config/regex_patterns.json"
  agent_id: "r013-test-agent"
  user_id: "r013-test-user"
  department: "Test"
logging:
  max_bytes: 1048576
  text_preview_len: 120
""".lstrip(),
        encoding="utf-8",
    )
    (config / "regex_patterns.json").write_text(
        json.dumps(
            {
                "patterns": [
                    {
                        "id": verify_live_pipeline.MARKER_PATTERN_ID,
                        "name": "synthetic marker",
                        "regex": ">> 확인완료",
                        "severity": "low",
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _valid_ood_result(**overrides: Any) -> dict[str, Any]:
    result = {
        "status": "passed",
        "gate": "blind_ood_final_v1",
        "model_version": "koelectra-dlp-v7",
        "quality_passed": True,
        "checkpoint_sha256": CHECKPOINT_SHA256,
        "model_bundle_sha256": MODEL_BUNDLE_SHA256,
        "block_threshold": BLOCK_THRESHOLD,
        "review_threshold": REVIEW_THRESHOLD,
        "minimum_f1": 0.90,
        "minimum_recall": 0.90,
        "metrics": {"f1": 0.95, "recall": 0.96},
    }
    result.update(overrides)
    return result


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: dict[str, Any],
    evidence_root: Path | None = None,
    viewer_auth: bool = True,
    ood_result: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], str]:
    with _http_server(state) as base_url:
        _write_project(tmp_path, base_url)
        monkeypatch.setenv("AI_API_TOKEN", AI_TOKEN)
        monkeypatch.setenv("AGENT_API_TOKEN", WEB_TOKEN)
        if viewer_auth:
            monkeypatch.setenv("DASHBOARD_VIEWER_USERNAME", VIEWER_USERNAME)
            monkeypatch.setenv("DASHBOARD_VIEWER_PASSWORD", VIEWER_PASSWORD)
        else:
            monkeypatch.delenv("DASHBOARD_VIEWER_USERNAME", raising=False)
            monkeypatch.delenv("DASHBOARD_VIEWER_PASSWORD", raising=False)
        argv = ["--project-root", str(tmp_path)]
        if evidence_root is not None:
            argv.extend(["--evidence-root", str(evidence_root)])
        if ood_result is not None:
            ood_result_path = tmp_path / "ood-result.json"
            ood_result_path.write_text(json.dumps(ood_result), encoding="utf-8")
            argv.extend(["--ood-result", str(ood_result_path)])
        result = verify_live_pipeline.main(argv)
    captured = capsys.readouterr()
    return result, json.loads(captured.out), captured.out + captured.err


@pytest.mark.parametrize(
    "custom_evidence",
    [False, True],
)
def test_live_pipeline_uses_real_http_headers_and_one_event_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    custom_evidence: bool,
) -> None:
    state: dict[str, Any] = {"require_viewer_auth": True}
    evidence_root = tmp_path / "custom-evidence" if custom_evidence else None

    result, output, all_output = _run(
        tmp_path,
        monkeypatch,
        capsys,
        state,
        evidence_root,
    )

    assert result == 0
    assert output["status"] == "PASS"
    assert output["scope"] == "SERVER_PIPELINE"
    assert output["windows_hook_e2e"] is False
    assert output["model_version"] == "koelectra-dlp-v7"
    assert output["checkpoint_sha256"] == CHECKPOINT_SHA256
    assert output["model_bundle_sha256"] == MODEL_BUNDLE_SHA256
    assert output["block_threshold"] == BLOCK_THRESHOLD
    assert output["review_threshold"] == REVIEW_THRESHOLD
    assert output["ood_bound"] is False
    assert output["ood_result_sha256"] is None
    assert output["event_id"] == state["ai_request"]["event_id"]
    assert output["event_id"] == state["web_request"]["event_id"]
    assert state["ai_authorization"] == f"Bearer {AI_TOKEN}"
    assert state["ai_health_authorization"] == f"Bearer {AI_TOKEN}"
    assert state["web_token"] == WEB_TOKEN
    assert state["readback_token"] == WEB_TOKEN
    assert state["readback_authorization"] == VIEWER_AUTHORIZATION
    assert state["readback_query"]["q"] == [output["event_id"]]
    assert state["readback_query"]["limit"] == ["50"]
    assert state["ai_request"]["matched_patterns"] == [
        verify_live_pipeline.MARKER_PATTERN_ID
    ]
    assert all(output[name] >= 0 for name in ("ai_rtt_ms", "event_to_jsonl_ms", "web_ack_ms"))
    assert AI_TOKEN not in all_output
    assert WEB_TOKEN not in all_output
    assert verify_live_pipeline.MARKER_TEXT not in all_output
    assert VIEWER_USERNAME not in all_output
    assert VIEWER_PASSWORD not in all_output
    evidence_path = Path(output["evidence_path"])
    assert evidence_path.parents[2] == (
        evidence_root or tmp_path / "logs" / "server-pipeline-evidence"
    )
    assert len(evidence_path.parent.parent.name) == 10
    assert evidence_path.parent.name == output["event_id"]
    assert evidence_path.name == "events.jsonl"
    assert evidence_path.exists()
    assert output["evidence_sha256"] == hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    evidence_text = evidence_path.read_text(encoding="utf-8")
    assert verify_live_pipeline.MARKER_TEXT not in evidence_text
    evidence_record = json.loads(evidence_text)
    assert "text_preview" not in evidence_record
    assert evidence_record["text_sha256"] == hashlib.sha256(
        verify_live_pipeline.MARKER_TEXT.encode()
    ).hexdigest()
    assert evidence_record["hits"][0]["id"] == verify_live_pipeline.MARKER_PATTERN_ID
    assert evidence_record["extra"]["event_id"] == output["event_id"]
    assert evidence_record["extra"]["checkpoint_sha256"] == CHECKPOINT_SHA256
    assert evidence_record["extra"]["model_bundle_sha256"] == MODEL_BUNDLE_SHA256
    assert evidence_record["extra"]["block_threshold"] == BLOCK_THRESHOLD
    assert evidence_record["extra"]["review_threshold"] == REVIEW_THRESHOLD
    assert evidence_record["extra"]["ood_bound"] is False
    assert evidence_record["extra"]["ood_result_sha256"] is None


@pytest.mark.parametrize(
    ("state", "error_code"),
    [
        ({"ai_health_http_status": 503}, "AI_HEALTH_FAILED"),
        ({"ai_health_overrides": {"status": "ok"}}, "AI_HEALTH_INVALID"),
        ({"ai_health_overrides": {"engine": "onnx"}}, "AI_HEALTH_INVALID"),
        (
            {"ai_health_overrides": {"status": "model_load_failed"}},
            "AI_HEALTH_INVALID",
        ),
        ({"ai_health_overrides": {"auth_required": False}}, "AI_HEALTH_INVALID"),
        ({"ai_health_overrides": {"checkpoint_sha256": "A" * 64}}, "AI_HEALTH_INVALID"),
        ({"ai_health_overrides": {"model_bundle_sha256": None}}, "AI_HEALTH_INVALID"),
        ({"ai_health_overrides": {"model_bundle_sha256": "C" * 64}}, "AI_HEALTH_INVALID"),
        ({"ai_health_overrides": {"block_threshold": True}}, "AI_HEALTH_INVALID"),
        (
            {"ai_health_overrides": {"review_threshold": BLOCK_THRESHOLD}},
            "AI_HEALTH_INVALID",
        ),
        ({"web_health_http_status": 503}, "WEB_HEALTH_FAILED"),
        ({"web_health_overrides": {"status": "degraded"}}, "WEB_HEALTH_INVALID"),
        ({"web_health_overrides": {"database_status": "error"}}, "WEB_HEALTH_INVALID"),
        (
            {"web_health_overrides": {"dashboard_auth_enabled": False}},
            "WEB_HEALTH_INVALID",
        ),
        ({"ai_event_id": "wrong-event-id"}, "AI_RESPONSE_INVALID"),
        ({"model_version": "unexpected-model"}, "AI_RESPONSE_INVALID"),
        ({"ai_status": 500}, "AI_RESPONSE_INVALID"),
        ({"web_status": 503}, "WEB_RECEIPT_INVALID"),
        ({"receipt_mismatch": True}, "WEB_RECEIPT_INVALID"),
        ({"readback_status": 503}, "WEB_READBACK_FAILED"),
        ({"readback_mismatch": True}, "WEB_READBACK_INVALID"),
    ],
)
def test_live_pipeline_fails_closed_on_contract_and_http_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: dict[str, Any],
    error_code: str,
) -> None:
    result, output, all_output = _run(tmp_path, monkeypatch, capsys, state)

    assert result == 1
    assert output["error_code"] == error_code
    assert output["scope"] == "SERVER_PIPELINE"
    assert output["status"] == "FAIL"
    assert output["windows_hook_e2e"] is False
    if error_code in {
        "WEB_RECEIPT_INVALID",
        "WEB_READBACK_FAILED",
        "WEB_READBACK_INVALID",
    }:
        evidence_path = Path(output["evidence_path"])
        assert evidence_path.exists()
        assert output["evidence_sha256"] == hashlib.sha256(
            evidence_path.read_bytes()
        ).hexdigest()
    else:
        assert "evidence_path" not in output
        assert "evidence_sha256" not in output
    assert AI_TOKEN not in all_output
    assert WEB_TOKEN not in all_output
    assert verify_live_pipeline.MARKER_TEXT not in all_output
    assert VIEWER_USERNAME not in all_output
    assert VIEWER_PASSWORD not in all_output


@pytest.mark.parametrize(
    ("viewer_username", "viewer_password"),
    [
        (None, None),
        (VIEWER_USERNAME, None),
        (None, VIEWER_PASSWORD),
        ("viewer-한글", VIEWER_PASSWORD),
        (VIEWER_USERNAME, "password-한글-12345678"),
        ("viewer:admin", VIEWER_PASSWORD),
        (VIEWER_USERNAME, "fifteen-characters"[:15]),
    ],
)
def test_live_pipeline_rejects_invalid_viewer_credentials_without_exposing_them(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    viewer_username: str | None,
    viewer_password: str | None,
) -> None:
    state: dict[str, Any] = {}
    with _http_server(state) as base_url:
        _write_project(tmp_path, base_url)
        monkeypatch.setenv("AI_API_TOKEN", AI_TOKEN)
        monkeypatch.setenv("AGENT_API_TOKEN", WEB_TOKEN)
        monkeypatch.delenv("DASHBOARD_VIEWER_USERNAME", raising=False)
        monkeypatch.delenv("DASHBOARD_VIEWER_PASSWORD", raising=False)
        if viewer_username is not None:
            monkeypatch.setenv("DASHBOARD_VIEWER_USERNAME", viewer_username)
        if viewer_password is not None:
            monkeypatch.setenv("DASHBOARD_VIEWER_PASSWORD", viewer_password)
        result = verify_live_pipeline.main(["--project-root", str(tmp_path)])

    output = capsys.readouterr().out
    assert result == 1
    assert json.loads(output)["error_code"] == "WEB_CONFIG_INVALID"
    assert "ai_request" not in state
    if viewer_username:
        assert viewer_username not in output
    if viewer_password:
        assert viewer_password not in output


def test_live_pipeline_keeps_explicit_evidence_without_overwriting_existing_folder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixed_event_id = "00000000-0000-0000-0000-000000000013"
    evidence_root = tmp_path / "kept-evidence"
    event_date = verify_live_pipeline.PayloadBuilder().build(
        "", [], "clipboard", "test"
    ).timestamp[:10]
    existing_dir = evidence_root / event_date / fixed_event_id
    existing_dir.mkdir(parents=True)
    sentinel = existing_dir / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    monkeypatch.setattr("core_comm.payload_builder.uuid.uuid4", lambda: fixed_event_id)
    state: dict[str, Any] = {}

    with _http_server(state) as base_url:
        _write_project(tmp_path, base_url)
        monkeypatch.setenv("AI_API_TOKEN", AI_TOKEN)
        monkeypatch.setenv("AGENT_API_TOKEN", WEB_TOKEN)
        monkeypatch.setenv("DASHBOARD_VIEWER_USERNAME", VIEWER_USERNAME)
        monkeypatch.setenv("DASHBOARD_VIEWER_PASSWORD", VIEWER_PASSWORD)
        result = verify_live_pipeline.main(
            [
                "--project-root",
                str(tmp_path),
                "--evidence-root",
                str(evidence_root),
            ]
        )

    output = json.loads(capsys.readouterr().out)
    assert result == 1
    assert output["error_code"] == "EVIDENCE_CREATE_FAILED"
    assert "evidence_path" not in output
    assert sentinel.read_text(encoding="utf-8") == "keep"
    assert sorted(path.name for path in existing_dir.iterdir()) == ["keep.txt"]


def test_live_pipeline_binds_a_passed_ood_result_to_live_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state: dict[str, Any] = {"require_viewer_auth": True}
    ood_result = _valid_ood_result()

    result, output, _ = _run(
        tmp_path,
        monkeypatch,
        capsys,
        state,
        ood_result=ood_result,
    )

    ood_path = tmp_path / "ood-result.json"
    assert result == 0
    assert output["ood_bound"] is True
    assert output["ood_result_sha256"] == hashlib.sha256(ood_path.read_bytes()).hexdigest()
    evidence = json.loads(Path(output["evidence_path"]).read_text(encoding="utf-8"))
    assert output["model_bundle_sha256"] == MODEL_BUNDLE_SHA256
    assert evidence["extra"]["model_bundle_sha256"] == MODEL_BUNDLE_SHA256
    assert evidence["extra"]["ood_bound"] is True
    assert evidence["extra"]["ood_result_sha256"] == output["ood_result_sha256"]


@pytest.mark.parametrize(
    "override",
    [
        {"status": "quality_failed"},
        {"gate": "different_gate"},
        {"model_version": "koelectra-dlp-v6"},
        {"quality_passed": False},
        {"metrics": None},
        {"metrics": {"f1": True, "recall": 0.96}},
        {"metrics": {"f1": 0.95, "recall": 1.01}},
        {"minimum_f1": True},
        {"minimum_recall": 0.89},
        {"metrics": {"f1": 0.89, "recall": 0.96}},
        {"metrics": {"f1": 0.95, "recall": 0.89}},
        {"checkpoint_sha256": "b" * 64},
        {"model_bundle_sha256": "d" * 64},
        {"block_threshold": 0.42},
        {"review_threshold": 0.19},
        {"block_threshold": True},
    ],
)
def test_live_pipeline_rejects_unbound_ood_results_before_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    override: dict[str, Any],
) -> None:
    state: dict[str, Any] = {}
    ood_result = _valid_ood_result(**override)

    result, output, _ = _run(
        tmp_path,
        monkeypatch,
        capsys,
        state,
        ood_result=ood_result,
    )

    assert result == 1
    assert output["error_code"] == "OOD_RESULT_INVALID"
    assert "ai_request" not in state
    assert "web_request" not in state
