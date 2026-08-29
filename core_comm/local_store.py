"""로컬 이벤트 저장소 — JSONL 파일에 탐지 이벤트를 기록한다.

파일 구조
---------
logs/events.jsonl          ← 활성 로그
logs/events.2026-07-04.jsonl  ← 로테이션된 로그 (날짜별)

각 줄은 독립된 JSON 오브젝트이므로 파일 일부가 깨져도 나머지를 파싱할 수 있다.
웹 서버 전송 준비가 되면 이 파일을 읽어 POST하면 된다.
"""

import hashlib
import json
import logging
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_HOSTNAME = socket.gethostname()


class LocalEventStore:
    """스레드 안전한 JSONL 로컬 이벤트 저장소."""

    def __init__(
        self,
        log_dir: Path,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB 초과 시 로테이션
        text_preview_len: int = 120,
    ) -> None:
        self._log_dir = log_dir
        self._max_bytes = max_bytes
        # 기존 설정·생성자 호출 호환용 no-op. 신규 로그에는 원문 preview를
        # 저장하지 않는다.
        self._preview_len = text_preview_len
        self._lock = threading.Lock()

        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._active_path = self._log_dir / "events.jsonl"

    # ── Public API ────────────────────────────────────────────────────────────

    def write(
        self,
        channel: str,
        action: str,
        process_name: str,
        hits: list[dict[str, Any]],
        text: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """이벤트 한 건을 JSONL에 append한다.

        Parameters
        ----------
        channel:
            이벤트 발생 채널 — ``"clipboard"``, ``"usb"``, ``"email"`` 등.
        action:
            수행된 조치 — ``"blocked"`` 또는 ``"allowed"``.
        process_name:
            대상 프로세스 이름 (예: ``"slack.exe"``).
        hits:
            rule_filter가 반환한 정규식 매칭 목록.
        text:
            검사한 원본 텍스트 (내용은 저장하지 않고 SHA-256만 기록).
        extra:
            채널별 추가 정보 (파일 경로, 수신자 주소 등).
        """
        record = self._build_record(channel, action, process_name, hits, text, extra)
        line = json.dumps(record, ensure_ascii=False)

        with self._lock:
            self._rotate_if_needed()
            with self._active_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

        logger.info(
            "Event saved [%s/%s] process=%s hits=%s",
            channel,
            action,
            process_name,
            [h.get("id") for h in hits],
        )

    # ── Internals ─────────────────────────────────────────────────────────────

    def _build_record(
        self,
        channel: str,
        action: str,
        process_name: str,
        hits: list[dict[str, Any]],
        text: Optional[str],
        extra: Optional[dict[str, Any]],
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": _HOSTNAME,
            "channel": channel,
            "action": action,
            "process": process_name,
            "hits": [
                {
                    "id": h.get("id"),
                    "name": h.get("name"),
                    "severity": h.get("severity"),
                }
                for h in hits
            ],
        }

        if text:
            record["text_sha256"] = hashlib.sha256(text.encode()).hexdigest()

        if extra:
            record["extra"] = extra

        return record

    def _rotate_if_needed(self) -> None:
        """활성 로그 파일이 max_bytes를 초과하면 날짜 이름으로 이동한다."""
        if not self._active_path.exists():
            return
        if self._active_path.stat().st_size < self._max_bytes:
            return

        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
        rotated = self._log_dir / f"events.{stamp}.jsonl"
        self._active_path.rename(rotated)
        logger.info("Log rotated → %s", rotated)
