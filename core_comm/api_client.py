"""AI 분석 서버 클라이언트.

운영 모드 (ai_base_url 설정 시)
  AnalysisPayload → POST /api/v1/analyze → AnalysisResult

Mock 모드 (ai_base_url = "" 또는 미설정 시)
  severity 기반 규칙으로 즉시 AnalysisResult 반환
  실제 AI 서버 없이도 파이프라인 전체를 테스트할 수 있다.

Mock 판단 기준 (AI 서버 confidence_score 스케일 0-1 기준)
----------------------------------------------------------
  critical 패턴 있음 → block  (confidence 0.95)
  high 패턴만 있음   → block  (confidence 0.75)
  medium만 있음      → review (confidence 0.40)
  low만 있음         → allow  (confidence 0.10)

장애 정책
---------
  실제 AI 서버의 타임아웃·통신·응답 오류 → allow (confidence 0.0, Fail-Open)
"""

import logging
from typing import Any

import requests

from core_comm.payload_builder import AnalysisPayload, AnalysisResult, ResponseParser

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _mock_result(payload: AnalysisPayload) -> AnalysisResult:
    """AI 서버 없이 severity만으로 즉시 판단하는 mock.

    confidence_score를 0-1 스케일로 반환해 실제 AI 서버와 동일한 AnalysisResult 구조를 유지한다.
    """
    max_sev = payload.metadata.get("max_severity", "medium")
    rank = _SEVERITY_RANK.get(max_sev, 1)

    if rank >= 3:          # critical
        return AnalysisResult(
            request_id=payload.request_id,
            confidence_score=0.95,
            action="block",
            reason=f"[mock] critical 패턴 탐지 ({payload.metadata.get('pattern_ids')})",
            model_version="mock-severity-v1",
        )
    elif rank == 2:        # high
        return AnalysisResult(
            request_id=payload.request_id,
            confidence_score=0.75,
            action="block",
            reason=f"[mock] high 패턴 탐지 ({payload.metadata.get('pattern_ids')})",
            model_version="mock-severity-v1",
        )
    elif rank == 1:        # medium
        return AnalysisResult(
            request_id=payload.request_id,
            confidence_score=0.40,
            action="review",
            reason=f"[mock] medium 패턴 탐지 — AI 검토 필요 ({payload.metadata.get('pattern_ids')})",
            model_version="mock-severity-v1",
        )
    else:                  # low
        return AnalysisResult(
            request_id=payload.request_id,
            confidence_score=0.10,
            action="allow",
            reason=f"[mock] low 패턴 — 허용 ({payload.metadata.get('pattern_ids')})",
            model_version="mock-severity-v1",
        )


class ApiClient:
    """AnalysisPayload를 AI 서버로 전송하고 AnalysisResult를 반환한다."""

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 10.0,
        token: str | None = "",
    ) -> None:
        self._base_url = base_url.rstrip("/") if base_url else ""
        self._timeout  = timeout
        self._token    = token.strip() if isinstance(token, str) else ""
        self._mock     = not bool(self._base_url)

        if self._mock:
            logger.info("ApiClient: AI 서버 URL 없음 → mock 모드")
        else:
            logger.info("ApiClient: AI 서버 → %s", self._base_url)

    @property
    def is_mock(self) -> bool:
        return self._mock

    def analyze(self, payload: AnalysisPayload) -> AnalysisResult:
        """페이로드를 분석하고 결과를 반환한다. mock 모드면 즉시 반환."""
        if self._mock:
            result = _mock_result(payload)
            logger.debug(
                "Mock 분석 결과: action=%s confidence=%.2f reason=%s",
                result.action, result.confidence_score, result.reason,
            )
            return result

        return self._call_server(payload)

    def _call_server(self, payload: AnalysisPayload) -> AnalysisResult:
        url = f"{self._base_url}/api/v1/analyze"
        logger.debug("AI 서버 요청 → %s (event_id=%s)", url, payload.request_id)

        try:
            headers = (
                {"Authorization": f"Bearer {self._token}"}
                if self._token
                else None
            )
            resp = requests.post(
                url,
                json=payload.to_dict(),   # AgentRequest 포맷
                headers=headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return ResponseParser.parse(resp.json(), payload.request_id)
        except requests.Timeout:
            logger.error("AI 서버 타임아웃 (%.1fs) — Fail-Open 허용", self._timeout)
            return AnalysisResult(
                request_id=payload.request_id,
                confidence_score=0.0,
                action="allow",
                reason=f"AI 서버 타임아웃 ({self._timeout:.1f}s) — Fail-Open 허용",
                model_version="unavailable",
                analysis_failed=True,
            )
        except Exception as exc:
            logger.error("AI 서버 오류: %s — Fail-Open 허용", exc)
            return AnalysisResult(
                request_id=payload.request_id,
                confidence_score=0.0,
                action="allow",
                reason=f"AI 서버 오류: {exc} — Fail-Open 허용",
                model_version="unavailable",
                analysis_failed=True,
            )
