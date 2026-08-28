"""Platform-neutral clipboard AI decision orchestration.

The keyboard hook suppresses the original paste before this function runs. A
paste therefore has to be released exactly once for every outcome except a
fully completed block path. Keeping this policy free of Win32 imports lets us
exercise the failure paths on any CI host.
"""

import logging
from typing import Any, Callable

from core_comm.analysis_events import record_analysis_result


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
    block_confirmed = False

    def _release_once() -> None:
        nonlocal release_attempted
        if release_attempted:
            return
        release_attempted = True
        try:
            release_paste()
        except Exception:
            # Never retry blindly: a partial SendInput could duplicate a paste.
            try:
                logger.exception("[clipboard] 붙여넣기 재발행 실패")
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

        try:
            record_analysis_result(
                event_logger,
                result,
                channel="clipboard",
                process_name=process_name,
                hits=hits,
                text=text,
                event_id=payload.request_id,
                detection_type="RULE_BASED" if api_client.is_mock else "HYBRID",
            )
        except Exception:
            try:
                logger.exception("[clipboard] 분석 결과 기록 실패(판정 유지)")
            except Exception:
                pass

        if block_confirmed:
            try:
                notify_blocked(process_name, hits)
            except Exception:
                try:
                    logger.exception("[clipboard] 차단 알림 실패(차단 유지)")
                except Exception:
                    pass
            return

        if result.needs_review:
            logger.warning("[clipboard] review 경고 기록 — 붙여넣기 허용")
            # Release before opening the popup so it cannot steal focus from
            # the original paste target.
            _release_once()
            try:
                notify_review(process_name, hits)
            except Exception:
                try:
                    logger.exception("[clipboard] review 알림 실패(허용 유지)")
                except Exception:
                    pass
            return

        if result.analysis_failed:
            logger.warning("[clipboard] AI 장애 Fail-Open 기록 — 붙여넣기 허용")
        else:
            logger.info("[clipboard] AI allow 기록 — 오탐 복구: 붙여넣기 재발행")
        _release_once()
    except Exception:
        try:
            logger.exception("[clipboard] 비동기 처리 예외 — Fail-Open 붙여넣기 허용")
        except Exception:
            pass
    finally:
        if not block_confirmed:
            _release_once()
