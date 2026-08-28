"""AI 분석 서버 전송용 페이로드 구성 모듈.

설계 원칙
---------
1. 정규식 1차 hit가 난 전체 텍스트에서 매치 앞뒤 context_chars 자만 스니펫으로 추출해 AI에 전달
2. 마스킹하지 않음 — 마스킹은 문맥 분석 성능을 해침
3. matched_patterns로 1차 게이트 힌트 제공 (AI가 어디에 주목할지 참고)

AI 서버 요청 포맷 (AgentRequest)
---------------------------------
{
  "event_id":         "<uuid>",
  "channel":          "clipboard|outlook|smtp|web_mail|drive_upload|file_guard|http",
  "user_id":          "<Windows USERNAME>",
  "matched_patterns": ["rrn", "credit_card"],   // 패턴 ID 목록 (문자열)
  "snippet":          "검사 대상 텍스트 스니펫",
  "metadata": {
    "app":           "chrome.exe",
    "severity_hint": "critical"
  }
}

AI 서버 응답 포맷 (AgentResponse)
----------------------------------
{
  "event_id":         "<uuid>",
  "decision":         "allow|review|block",
  "confidence_score": 0.87,     // 0.0–1.0
  "model_version":    "koelectra-dlp-v7",
  "latency_ms":       23.4,
  "reason":           "주민등록번호 탐지됨"
}
"""

import hashlib
import math
import os
import re
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

_HOSTNAME = socket.gethostname()

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# AI 전송 시 매치 위치 앞뒤로 포함할 문자 수
DEFAULT_CONTEXT_CHARS = 200

# 0 이하면 제한 없음 (전체 텍스트 전송 — 하위 호환용)
DEFAULT_MAX_TEXT_CHARS = 0


@dataclass
class PatternMatch:
    """정규식 hit 위치 정보 — AI에 힌트로 전달 (마스킹 없음)."""
    pattern_id: str
    pattern_name: str
    severity: str
    match: str
    start: int
    end: int


@dataclass
class AnalysisPayload:
    """내부 페이로드. to_dict()로 AI 서버 AgentRequest 포맷을 생성한다."""
    request_id: str           # AgentRequest.event_id 로 매핑
    timestamp: str
    channel: str
    process: str              # AgentRequest.metadata.app 으로 매핑
    user_id: str              # AgentRequest.user_id
    text: str                 # AgentRequest.snippet 으로 매핑
    matched_patterns: list[PatternMatch]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """AI 서버 AgentRequest 포맷으로 직렬화한다."""
        max_sev = self.metadata.get("max_severity", "medium")
        # matched_patterns는 패턴 ID 문자열 리스트 (중복 제거)
        pattern_ids = list(dict.fromkeys(m.pattern_id for m in self.matched_patterns))
        return {
            "event_id":         self.request_id,
            "channel":          self.channel,
            "user_id":          self.user_id,
            "matched_patterns": pattern_ids,
            "snippet":          self.text,
            "metadata": {
                "app":           self.process,
                "severity_hint": max_sev,
            },
        }


@dataclass
class AnalysisResult:
    """AI 서버 AgentResponse 파싱 결과."""
    request_id: str
    confidence_score: float    # 0.0–1.0 (AI 서버 네이티브 스케일)
    action: str                # "allow" | "block" | "review"
    reason: str = ""
    model_version: str = ""
    latency_ms: float = 0.0
    analysis_failed: bool = False  # AI 장애로 Fail-Open 결과가 생성됐는지 여부

    @property
    def risk_score(self) -> float:
        """0–100 스케일 (내부 로직 호환용)."""
        return round(self.confidence_score * 100, 1)

    @property
    def is_sensitive(self) -> bool:
        return self.action in ("block", "review")

    @property
    def should_block(self) -> bool:
        return self.action == "block"

    @property
    def needs_review(self) -> bool:
        return self.action == "review"


def _collect_matches(
    text: str,
    hits: list[dict[str, Any]],
    max_per_pattern: int = 10,
) -> list[PatternMatch]:
    """정규식 hit 위치·원문 매칭 문자열을 수집 (마스킹 없음)."""
    matches: list[PatternMatch] = []

    sorted_hits = sorted(
        hits,
        key=lambda h: _SEVERITY_RANK.get(h.get("severity", "medium"), 1),
        reverse=True,
    )

    for hit in sorted_hits:
        pattern_id   = hit.get("id", "unknown")
        pattern_name = hit.get("name", "알 수 없음")
        severity     = hit.get("severity", "medium")
        regex        = hit.get("regex", "")
        if not regex:
            continue

        count = 0
        try:
            for m in re.finditer(regex, text):
                if count >= max_per_pattern:
                    break
                matches.append(PatternMatch(
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                    severity=severity,
                    match=m.group(),
                    start=m.start(),
                    end=m.end(),
                ))
                count += 1
        except re.error:
            pass

    return matches


def _extract_snippets(
    text: str,
    matches: list[PatternMatch],
    context: int,
) -> str:
    """매치 위치 앞뒤 context 자 범위만 잘라 합친다.

    겹치는 구간은 병합하고 '...'로 구분해 반환한다.
    매치가 없으면 text 앞부분 context*4 자를 반환한다.
    """
    if not matches:
        return text[: context * 4]

    windows: list[tuple[int, int]] = []
    for m in matches:
        s = max(0, m.start - context)
        e = min(len(text), m.end + context)
        windows.append((s, e))

    windows.sort()
    merged: list[list[int]] = []
    for s, e in windows:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])

    parts = [text[s:e] for s, e in merged]
    return "\n...\n".join(parts)


class PayloadBuilder:
    """탐지 결과를 AI 서버 전송용 AnalysisPayload로 변환한다.

    정규식이 전체 텍스트를 검사하고, AI에는 매치 위치 앞뒤 context_chars 자만
    스니펫으로 전송해 페이로드 크기를 최소화한다.
    """

    def __init__(
        self,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
        max_per_pattern: int = 10,
        context_chars: int = DEFAULT_CONTEXT_CHARS,
        user_id: str = "",
    ) -> None:
        self._max_text_chars  = max_text_chars
        self._max_per_pattern = max_per_pattern
        self._context_chars   = context_chars
        self._user_id         = user_id or os.environ.get("USERNAME", "unknown")

    def build(
        self,
        text: str,
        hits: list[dict[str, Any]],
        channel: str,
        process_name: str,
    ) -> AnalysisPayload:
        matches = _collect_matches(text, hits, self._max_per_pattern)

        snippet = _extract_snippets(text, matches, self._context_chars)
        if self._max_text_chars and len(snippet) > self._max_text_chars:
            snippet = snippet[: self._max_text_chars]

        severities = [h.get("severity", "medium") for h in hits]
        max_sev = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 1), default="medium")

        return AnalysisPayload(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            channel=channel,
            process=process_name,
            user_id=self._user_id,
            text=snippet,
            matched_patterns=matches,
            metadata={
                "hostname":         _HOSTNAME,
                "total_text_len":   len(text),
                "snippet_text_len": len(snippet),
                "context_chars":    self._context_chars,
                "total_hits":       len(hits),
                "max_severity":     max_sev,
                "pattern_ids":      list(dict.fromkeys(h.get("id") for h in hits)),
                "text_hash":        hashlib.sha256(text.encode()).hexdigest()[:16],
            },
        )


class ResponseParser:
    """AI 서버 AgentResponse dict를 AnalysisResult로 변환한다."""

    @staticmethod
    def parse(raw: dict[str, Any], request_id: str = "") -> AnalysisResult:
        if not isinstance(raw, dict):
            raise ValueError("AI 응답은 JSON 객체여야 합니다.")

        # AgentResponse의 필수 계약은 누락·보정하지 않는다. 잘못된 응답은
        # ApiClient 예외 경로에서 명시적인 Fail-Open 결과로 변환한다.
        raw_event_id = raw.get("event_id")
        if not isinstance(raw_event_id, str) or not raw_event_id.strip():
            raise ValueError("AI 응답 event_id가 누락되었거나 문자열이 아닙니다.")
        if request_id and raw_event_id != request_id:
            raise ValueError(
                f"AI 응답 event_id가 요청과 다릅니다: {raw_event_id!r} != {request_id!r}"
            )

        raw_action = raw.get("decision")
        if not isinstance(raw_action, str) or not raw_action.strip():
            raise ValueError("AI 응답 decision이 누락되었거나 문자열이 아닙니다.")
        action = raw_action.strip().lower()
        if action not in {"allow", "block", "review"}:
            raise ValueError(f"알 수 없는 AI decision: {raw_action!r}")

        raw_confidence = raw.get("confidence_score")
        if isinstance(raw_confidence, bool) or not isinstance(raw_confidence, (int, float)):
            raise ValueError("AI 응답 confidence_score가 누락되었거나 숫자가 아닙니다.")
        confidence = float(raw_confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("AI 응답 confidence_score는 0.0~1.0의 유한한 숫자여야 합니다.")

        raw_model_version = raw.get("model_version")
        if not isinstance(raw_model_version, str) or not raw_model_version.strip():
            raise ValueError("AI 응답 model_version이 누락되었거나 문자열이 아닙니다.")

        raw_latency = raw.get("latency_ms")
        if isinstance(raw_latency, bool) or not isinstance(raw_latency, (int, float)):
            raise ValueError("AI 응답 latency_ms가 누락되었거나 숫자가 아닙니다.")
        latency = float(raw_latency)
        if not math.isfinite(latency) or latency < 0.0:
            raise ValueError("AI 응답 latency_ms는 0 이상의 유한한 숫자여야 합니다.")

        raw_reason = raw.get("reason")
        if raw_reason is not None and not isinstance(raw_reason, str):
            raise ValueError("AI 응답 reason은 문자열 또는 null이어야 합니다.")

        return AnalysisResult(
            request_id=raw_event_id,
            confidence_score=confidence,
            action=action,
            reason=raw_reason or "",
            model_version=raw_model_version,
            latency_ms=latency,
        )
