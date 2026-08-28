"""AI 분석 결과를 채널 공통 이벤트 형식으로 기록한다."""

import logging
from typing import Any, Optional, Protocol
from uuid import uuid4

from core_comm.payload_builder import AnalysisResult


class EventSink(Protocol):
    """EventLogger.log에 필요한 최소 인터페이스."""

    def log(
        self,
        channel: str,
        action: str,
        process_name: str,
        hits: list[dict[str, Any]],
        text: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None: ...


_RESULT_TO_LOG_ACTION = {
    "block": "blocked",
    "review": "review",
    "allow": "allowed",
}


def record_analysis_result(
    event_logger: EventSink,
    result: AnalysisResult,
    *,
    channel: str,
    process_name: str,
    hits: list[dict[str, Any]],
    text: Optional[str],
    event_id: Optional[str],
    detection_type: str,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """block/review/allow를 빠짐없이 로컬·대시보드 이벤트로 기록한다."""
    try:
        log_action = _RESULT_TO_LOG_ACTION[result.action]
    except KeyError as exc:
        raise ValueError(f"지원하지 않는 AI action: {result.action!r}") from exc

    extra = dict(metadata or {})
    extra.update(
        {
            "event_id": event_id or result.request_id or None,
            "ai_score": result.confidence_score,
            "reason": result.reason,
            "model_version": result.model_version,
            "latency_ms": int(result.latency_ms),
            "detection_type": detection_type,
        }
    )
    event_logger.log(
        channel=channel,
        action=log_action,
        process_name=process_name,
        hits=hits,
        text=text,
        extra=extra,
    )


def _safe_log(
    logger: logging.Logger,
    level: str,
    message: str,
    *args: Any,
) -> None:
    """진단 로그 장애가 프로세스 판정을 바꾸지 않게 한다."""
    try:
        getattr(logger, level)(message, *args)
    except Exception:
        pass


def _fail_open_result(event_id: str, reason: str) -> AnalysisResult:
    return AnalysisResult(
        request_id=event_id,
        confidence_score=0.0,
        action="allow",
        reason=f"{reason} — Fail-Open 허용",
        model_version="unavailable",
        analysis_failed=True,
    )


def make_network_decision_handler(
    *,
    channel: str,
    event_logger: EventSink,
    api_client: Any,
    payload_builder: Any,
    notify_blocked: Any,
    notify_review: Any,
    logger: Optional[logging.Logger] = None,
) -> Any:
    """네트워크 채널의 AI 판정을 부수 효과와 분리한 콜백을 만든다.

    로컬 이벤트 저장과 사용자 알림은 모두 best-effort이다. AI가
    ``block``을 반환했다면 이 부수 효과가 실패해도 ``block``을,
    ``review``면 ``review``를 반환한다. 페이로드 구성이나 분석 호출이
    예외를 던지면 새 event_id를 부여한 명시적 Fail-Open 이벤트를
    기록하고 ``allow``를 반환한다.
    """
    decision_logger = logger or logging.getLogger(__name__)

    def on_detected(
        text: str,
        hits: list[dict[str, Any]],
        process_name: str,
    ) -> str:
        fallback_event_id = str(uuid4())
        payload = None

        try:
            payload = payload_builder.build(text, hits, channel, process_name)
        except Exception as exc:
            result = _fail_open_result(
                fallback_event_id,
                f"AI 요청 페이로드 생성 실패: {exc}",
            )
        else:
            try:
                result = api_client.analyze(payload)
            except Exception as exc:
                result = _fail_open_result(
                    getattr(payload, "request_id", "") or fallback_event_id,
                    f"AI 분석 호출 실패: {exc}",
                )

        event_id = (
            getattr(payload, "request_id", "")
            or getattr(result, "request_id", "")
            or fallback_event_id
        )

        if getattr(result, "action", "") not in {"block", "review", "allow"}:
            result = _fail_open_result(
                event_id,
                f"AI 응답 판정값 오류: {getattr(result, 'action', None)!r}",
            )

        action = result.action
        _safe_log(
            decision_logger,
            "info",
            "[%s] AI 판단: action=%s confidence=%.2f reason=%s",
            channel,
            action,
            result.confidence_score,
            result.reason,
        )

        try:
            record_analysis_result(
                event_logger,
                result,
                channel=channel,
                process_name=process_name,
                hits=hits,
                text=text,
                event_id=event_id,
                detection_type=(
                    "RULE_BASED" if getattr(api_client, "is_mock", False) else "HYBRID"
                ),
            )
        except Exception as exc:
            _safe_log(
                decision_logger,
                "error",
                "[%s] 분석 결과 기록 실패(판정 유지): %s",
                channel,
                exc,
            )

        if action == "block":
            try:
                notify_blocked(process_name, hits)
            except Exception as exc:
                _safe_log(
                    decision_logger,
                    "error",
                    "[%s] 차단 알림 실패(차단 유지): %s",
                    channel,
                    exc,
                )
            return "block"

        if action == "review":
            try:
                notify_review(channel, process_name, hits)
            except Exception as exc:
                _safe_log(
                    decision_logger,
                    "error",
                    "[%s] review 알림 실패(허용 유지): %s",
                    channel,
                    exc,
                )
            _safe_log(
                decision_logger,
                "warning",
                "[%s] review 경고 기록 — 전송 허용: %s",
                channel,
                process_name,
            )
            return "review"

        if result.analysis_failed:
            _safe_log(
                decision_logger,
                "warning",
                "[%s] AI 장애 Fail-Open 기록 — 전송 허용: %s",
                channel,
                process_name,
            )
        else:
            _safe_log(
                decision_logger,
                "info",
                "[%s] AI allow 기록 — 전송 허용: %s",
                channel,
                process_name,
            )
        return "allow"

    return on_detected
