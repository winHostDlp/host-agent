"""이벤트 로거 — 로컬 저장과 웹 대시보드 전송을 분리한다.

로컬 저장
  └─ LocalEventStore에 JSONL 저장 (항상 수행).

웹 대시보드 전송 (send_immediately=True 설정 시)
  └─ POST /api/v1/logs  with  X-Agent-Token 헤더
     LogCreate 포맷 맞춤 변환 후 비동기 전송.

채널 → leak_channel 매핑
  clipboard  → CLIPBOARD
  outlook    → EMAIL_ATTACHMENT
  smtp       → EMAIL_ATTACHMENT
  web_mail   → WEB_UPLOAD
  drive_upload → CLOUD_DRIVE
  http       → WEB_UPLOAD
  file_guard → USB_COPY
  usb        → USB_COPY
  print      → PRINT
  messenger  → MESSENGER
"""

import json
import logging
import socket
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import sleep
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from core_comm.local_store import LocalEventStore

logger = logging.getLogger(__name__)

_HOSTNAME = socket.gethostname()


def _get_host_ip() -> str:
    """로컬 호스트의 외부 접속용 IP를 반환한다. 실패 시 '127.0.0.1'."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ── 채널·액션 매핑 ──────────────────────────────────────────────────────────

_CHANNEL_TO_LEAK: dict[str, str] = {
    "clipboard":  "CLIPBOARD",
    "outlook":    "EMAIL_ATTACHMENT",
    "smtp":       "EMAIL_ATTACHMENT",
    "web_mail":   "WEB_UPLOAD",
    "drive_upload": "CLOUD_DRIVE",
    "http":       "WEB_UPLOAD",
    "file_guard": "USB_COPY",
    "usb":        "USB_COPY",
    "print":      "PRINT",
    "messenger":  "MESSENGER",
}

_ACTION_TO_TAKEN: dict[str, str] = {
    "blocked": "BLOCKED",
    "block":   "BLOCKED",
    "review":  "WARNED",
    "warned":  "WARNED",
    "allowed": "ALLOWED",
    "allow":   "ALLOWED",
}


def _map_event_provenance(channel: str, action: str) -> tuple[str, str]:
    try:
        leak_channel = _CHANNEL_TO_LEAK[channel]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"지원하지 않는 이벤트 채널: {channel!r}") from exc
    try:
        action_taken = _ACTION_TO_TAKEN[action.lower()]
    except (AttributeError, KeyError) as exc:
        raise ValueError(f"지원하지 않는 이벤트 조치: {action!r}") from exc
    return leak_channel, action_taken


def _resolve_file_name(channel: str, process_name: str, extra: dict[str, Any]) -> str:
    """채널별 file_name 결정 (대시보드 required 필드 — 최소 1자)."""
    if channel in ("file_guard", "usb"):
        fp = str(extra.get("file_path", ""))
        if fp:
            return fp.replace("\\", "/").rsplit("/", 1)[-1][:255] or "file"
        return (process_name or "unknown_file")[:255]

    if channel in ("outlook", "smtp"):
        return "email_body"

    if channel in ("web_mail", "drive_upload"):
        url = str(extra.get("url", ""))
        try:
            host = urlparse(url).netloc
            prefix = "cloud_drive" if channel == "drive_upload" else "web_upload"
            return f"{prefix}@{host}"[:255] if host else prefix
        except Exception:
            return "cloud_drive" if channel == "drive_upload" else "web_upload"

    # clipboard, http, messenger
    return (process_name or "clipboard_content")[:255]


# ── EventLogger ─────────────────────────────────────────────────────────────

class EventLogger:
    """탐지 이벤트를 로컬에 기록하고 (선택적으로) 웹 대시보드로 전송한다."""

    def __init__(
        self,
        store: LocalEventStore,
        dashboard_url: Optional[str] = None,
        dashboard_token: str = "",
        timeout: float = 10.0,
        send_immediately: bool = False,
        agent_id: str = "",
        user_id: str = "",
        department: str = "Unknown",
    ) -> None:
        """
        Parameters
        ----------
        store:
            로컬 JSONL 저장소.
        dashboard_url:
            웹 대시보드 API 베이스 URL. None이면 네트워크 전송을 시도하지 않는다.
        dashboard_token:
            X-Agent-Token 헤더 값.
        timeout:
            HTTP 요청 타임아웃 (초).
        send_immediately:
            True면 write()마다 웹으로도 즉시 전송 (best-effort).
        agent_id:
            에이전트/장치 식별자. 비워두면 호스트명 사용.
        user_id:
            이벤트 발생 사용자 ID. 비워두면 "unknown".
        department:
            소속 부서명 (대시보드 필수 필드).
        """
        self._store            = store
        self._dashboard_url    = dashboard_url.rstrip("/") if dashboard_url else None
        self._token            = dashboard_token
        self._timeout          = timeout
        self._send_immediately = send_immediately and bool(dashboard_url)
        self._agent_id         = agent_id or _HOSTNAME
        self._user_id          = user_id or "unknown"
        self._department       = department
        self._host_ip          = _get_host_ip()

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        channel: str,
        action: str,
        process_name: str,
        hits: list[dict[str, Any]],
        text: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """이벤트를 로컬에 저장하고, 즉시 전송 모드면 비동기로 서버에도 보낸다."""
        # 잘못된 provenance가 JSONL에 영구히 남아 flush마다 실패하지 않게
        # 로컬 파일을 쓰기 전에 검증한다.
        _map_event_provenance(channel, action)
        self._store.write(
            channel=channel,
            action=action,
            process_name=process_name,
            hits=hits,
            text=text,
            extra=extra,
        )

        if self._send_immediately:
            payload = self._build_log_payload(channel, action, process_name, hits, text, extra)
            threading.Thread(
                target=self._post_immediately,
                args=(payload,),
                daemon=True,
                name="EventSender",
            ).start()

    def flush_to_server(self) -> int:
        """로컬 JSONL의 모든 레코드를 웹 서버로 POST하고 성공 건수를 반환한다.

        서버가 준비된 뒤 호출하면 미전송 이벤트를 일괄 전송한다.
        성공한 레코드는 삭제하지 않는다(서버 측 event_id 기반 중복 처리).
        """
        if not self._dashboard_url:
            logger.warning("flush_to_server: dashboard_url이 설정되지 않았습니다.")
            return 0

        active = self._store._active_path
        if not active.exists():
            return 0

        sent = 0
        with active.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    # 로컬 레코드 → LogCreate 포맷 변환
                    payload = self._build_log_payload_from_record(record)
                    if self._post(payload):
                        sent += 1
                except Exception as exc:
                    logger.warning("flush 중 오류 (건너뜀): %s", exc)

        logger.info("flush_to_server 완료: %d건 전송", sent)
        return sent

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_log_payload(
        self,
        channel: str,
        action: str,
        process_name: str,
        hits: list[dict[str, Any]],
        text: Optional[str],
        extra: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        """LogCreate 포맷의 대시보드 페이로드를 구성한다."""
        extra = extra or {}

        leak_channel, action_taken = _map_event_provenance(channel, action)

        # ai_score: extra에 0-1 스케일 ai_score 또는 0-100 risk_score 사용
        if "ai_score" in extra:
            ai_score = float(extra["ai_score"])
        else:
            ai_score = float(extra.get("risk_score", 95.0)) / 100.0
        ai_score = round(max(0.0, min(1.0, ai_score)), 4)

        # detection_type: extra에서 명시 또는 추론
        detection_type = extra.get("detection_type", "RULE_BASED")

        file_name = _resolve_file_name(channel, process_name or "", extra)

        file_path = extra.get("file_path") or extra.get("url")
        if file_path:
            file_path = str(file_path)[:500]

        reason       = str(extra.get("reason", ""))
        evidence     = reason[:500]
        decision_rsn = reason[:500] or None

        latency = extra.get("latency_ms")
        if latency is not None:
            latency = max(0, int(latency))

        return {
            "event_id":        extra.get("event_id") or str(uuid.uuid4()),
            "agent_id":        self._agent_id,
            "timestamp":       extra.get("_event_timestamp") or datetime.now(timezone.utc).isoformat(),
            "host_ip":         self._host_ip,
            "hostname":        _HOSTNAME,
            "user_id":         self._user_id,
            "department":      self._department,
            "file_name":       file_name,
            "file_path":       file_path,
            "process_name":    (process_name or None),
            "leak_channel":    leak_channel,
            "detection_type":  detection_type,
            "ai_score":        ai_score,
            "model_version":   extra.get("model_version") or None,
            "matched_keywords": [h.get("id", "") for h in hits if h.get("id")],
            "policy_id":       None,
            "action_taken":    action_taken,
            "decision_reason": decision_rsn,
            "evidence_summary": evidence,
            "latency_ms":      latency,
        }

    def _build_log_payload_from_record(self, record: dict[str, Any]) -> dict[str, Any]:
        """flush_to_server용: 로컬 JSONL 레코드 → LogCreate 포맷 변환."""
        hits  = record.get("hits", [])
        extra = record.get("extra") or {}
        extra.setdefault("event_id", record.get("event_id"))
        extra.setdefault("_event_timestamp", record.get("timestamp"))

        return self._build_log_payload(
            channel=record["channel"],
            action=record["action"],
            process_name=record.get("process", ""),
            hits=hits,
            text=record.get("text_preview"),
            extra=extra,
        )

    def _post(self, payload: dict[str, Any]) -> bool:
        """단일 레코드를 대시보드로 전송하고 성공 여부를 반환한다."""
        url = f"{self._dashboard_url}/api/v1/logs"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["X-Agent-Token"] = self._token
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=self._timeout)
            resp.raise_for_status()
            logger.debug(
                "Event posted → %s (%d) event_id=%s",
                url, resp.status_code, payload.get("event_id"),
            )
            return True
        except Exception as exc:
            logger.warning("Event POST 실패 (로컬에는 저장됨): %s", exc)
            return False

    def _post_immediately(self, payload: dict[str, Any]) -> bool:
        """Retry a live dashboard post briefly without blocking channel actions."""
        delays = (0.0, 0.25, 0.75)
        for attempt, delay in enumerate(delays, start=1):
            if delay:
                sleep(delay)
            if self._post(payload):
                return True
            if attempt < len(delays):
                logger.warning(
                    "Event POST 재시도 예정 (%d/%d) event_id=%s",
                    attempt,
                    len(delays),
                    payload.get("event_id"),
                )
        logger.error(
            "Event POST 최종 실패 — 로컬 JSONL 보존 event_id=%s",
            payload.get("event_id"),
        )
        return False
