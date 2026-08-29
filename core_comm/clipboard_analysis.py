"""Platform-neutral clipboard AI decision orchestration.

The keyboard hook suppresses the original paste before this function runs. A
paste therefore has to be released exactly once for every outcome except a
fully completed block path. Keeping this policy free of Win32 imports lets us
exercise the failure paths on any CI host.
"""

import logging
from dataclasses import replace
from typing import Any, Callable
from uuid import uuid4

from core_comm.analysis_events import record_analysis_result
from core_comm.payload_builder import AnalysisResult


def is_same_paste_destination(
    expected_hwnd: int,
    expected_process: str,
    current_hwnd: int,
    current_process: str,
) -> bool:
    """Return whether a delayed paste still targets the intercepted window."""
    return bool(
        expected_hwnd
        and current_hwnd
        and expected_hwnd == current_hwnd
        and expected_process
        and current_process
        and expected_process.casefold() == current_process.casefold()
    )


def run_clipboard_analysis(
    *,
    text: str,
    process_name: str,
    hits: list[dict[str, Any]],
    payload_builder: Any,
    api_client: Any,
    event_logger: Any,
    release_paste: Callable[[], Any],
    notify_blocked: Callable[[str, list[dict[str, Any]]], None],
    notify_review: Callable[[str, list[dict[str, Any]]], None],
    logger: logging.Logger,
) -> None:
    """Analyze one suppressed paste and apply the Fail-Open policy.

    ``release_paste`` is invoked at most once. An AI ``block`` result remains
    blocked even if its event log or user notification fails. Failures before
    an AI decision, and every non-block result, fall through to one best-effort
    release attempt.
    """

    release_attempted = False
    release_succeeded = False
    block_confirmed = False
    fallback_event_id = str(uuid4())
    payload = None
    event_recorded = False

    def _release_once() -> bool:
        nonlocal release_attempted, release_succeeded
        if release_attempted:
            return release_succeeded
        release_attempted = True
        try:
            # 기존 콜백의 None은 성공으로 간주하되, 훅은 명시적으로
            # False를 반환해 대상/클립보드 변경과 SendInput 실패를 알린다.
            release_succeeded = release_paste() is not False
        except Exception:
            # Never retry blindly: a partial SendInput could duplicate a paste.
            release_succeeded = False
            try:
                logger.exception("[clipboard] 붙여넣기 재발행 실패")
            except Exception:
                pass
        return release_succeeded

    def _record(result: Any, event_id: str) -> None:
        nonlocal event_recorded
        try:
            record_analysis_result(
                event_logger,
                result,
                channel="clipboard",
                process_name=process_name,
                hits=hits,
                text=text,
                event_id=event_id,
                detection_type="RULE_BASED" if api_client.is_mock else "HYBRID",
            )
            event_recorded = True
        except Exception:
            try:
                logger.exception("[clipboard] 분석 결과 기록 실패(판정 유지)")
            except Exception:
                pass

    try:
        payload = payload_builder.build(text, hits, "clipboard", process_name)
        result = api_client.analyze(payload)

        # AI block 판정은 로깅·알림보다 먼저 확정한다. 이후 부수 효과
        # 예외가 finally에서 붙여넣기를 재발행하는 일을 막는다.
        block_confirmed = result.should_block

        try:
            logger.info(
                "[clipboard] AI 판단: action=%s confidence=%.2f reason=%s",
                result.action,
                result.confidence_score,
                result.reason,
            )
        except Exception:
            pass

        if block_confirmed:
            _record(result, payload.request_id)
            try:
                notify_blocked(process_name, hits)
            except Exception:
                try:
                    logger.exception("[clipboard] 차단 알림 실패(차단 유지)")
                except Exception:
                    pass
            return

        # 원래 붙여넣기가 아니라 재발행의 실제 성공 여부를 확인한 뒤
        # 대시보드 조치를 기록한다. 재발행이 취소되면 AI allow였어도
        # 실제 붙여넣기는 수행되지 않았으므로 WARNED로 남긴다.
        released = _release_once()
        recorded_result = result
        if not released:
            reason = result.reason.strip()
            suffix = "붙여넣기 재발행 미수행(대상 창/클립보드 변경 또는 입력 주입 실패)"
            recorded_result = replace(
                result,
                action="review",
                reason=f"{reason} — {suffix}" if reason else suffix,
            )
            try:
                logger.warning("[clipboard] %s — WARNED 기록", suffix)
            except Exception:
                pass

        _record(recorded_result, payload.request_id)

        if not released:
            # 기존 review 팝업은 "붙여넣기 허용"으로 표시되므로 사용하지
            # 않는다. 훅의 경고 로그와 WARNED 이벤트가 실제 결과를 남긴다.
            return

        if result.needs_review:
            logger.warning("[clipboard] review 경고 기록 — 붙여넣기 허용")
            try:
                notify_review(process_name, hits)
            except Exception:
                try:
                    logger.exception("[clipboard] review 알림 실패")
                except Exception:
                    pass
            return

        if result.analysis_failed:
            logger.warning("[clipboard] AI 장애 Fail-Open 기록 — 붙여넣기 허용")
        else:
            logger.info("[clipboard] AI allow 기록 — 오탐 복구: 붙여넣기 재발행")
    except Exception as exc:
        try:
            logger.exception("[clipboard] 비동기 처리 예외 — Fail-Open 붙여넣기 허용")
        except Exception:
            pass
        failure_event_id = getattr(payload, "request_id", "") or fallback_event_id
        if not event_recorded:
            _record(
                AnalysisResult(
                    request_id=failure_event_id,
                    confidence_score=0.0,
                    action="allow",
                    reason=f"클립보드 AI 처리 실패: {exc} — Fail-Open 허용",
                    model_version="unavailable",
                    analysis_failed=True,
                ),
                failure_event_id,
            )
    finally:
        if not block_confirmed:
            _release_once()
