"""web_proxy.py — HTTPS MITM 웹 메일 DLP 채널.

- allow_hosts: channel_policy inspect_domains (국내 주요 웹메일) 만 TLS 가로채기
- 로그/DLP: 해당 호스트의 전송(POST/PUT/PATCH) 패킷만
- 그 외 트래픽: 터널 통과 (복호화·로그 없음)
"""

from __future__ import annotations

import asyncio
import base64
import email as _email_lib
import json
import logging
import re
import threading
import urllib.parse
from email import message_from_bytes
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse, parse_qs

from core_comm.analysis_events import record_analysis_result
from core_comm.review_notifier import notify_review

# Content-Type → 확장자 매핑 (업로드 파일 타입 추론용)
_CT_TO_EXT: dict[str, str] = {
    "application/pdf":   ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":       ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/msword":          ".doc",
    "application/zip":             ".zip",
    "application/x-zip-compressed": ".zip",
    "application/x-hwpml":         ".hwpx",
    "application/haansofthwp":     ".hwp",
    "text/plain":  ".txt",
    "text/html":   ".html",
    "text/csv":    ".csv",
    "text/rtf":    ".rtf",
    "application/rtf": ".rtf",
}


def _infer_ext_from_ct(content_type: str) -> str:
    """Content-Type 헤더에서 파일 확장자 추론."""
    ct = content_type.lower().split(";")[0].strip()
    return _CT_TO_EXT.get(ct, "")

logger = logging.getLogger(__name__)

# 차단 시 브라우저에 보여줄 HTML
_BLOCK_HTML = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Sentry DLP — 전송 차단</title>
  <style>
    body {{ font-family: 'Malgun Gothic', sans-serif; text-align: center;
            padding: 80px; background: #f8f9fa; }}
    .card {{ background: #fff; border-radius: 8px; padding: 40px;
             display: inline-block; box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
    h2 {{ color: #c0392b; }}
    .reason {{ color: #555; font-size: 14px; margin-top: 16px; }}
    .patterns {{ color: #888; font-size: 12px; margin-top: 8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 Sentry DLP — 전송 차단</h2>
    <p>민감정보가 포함된 내용의 전송이 차단되었습니다.<br>
       보안 담당자에게 문의하세요.</p>
    <div class="reason">{reason}</div>
    <div class="patterns">탐지 패턴: {patterns}</div>
  </div>
</body>
</html>"""


# ── DLP 애드온 ────────────────────────────────────────────────────────────────

class _DLPAddon:
    """mitmproxy 애드온 클래스 — POST/PUT 요청을 가로채 DLP 파이프라인 실행."""

    # 가로채기 로그에 붙일 본문 미리보기 길이 (원문 전체 덤프 방지)
    _BODY_PREVIEW = 160

    # 같은 호스트에서 팝업을 중복 발생시키지 않을 시간(초) — Gmail 장기 재시도 커버
    _POPUP_DEDUP_SEC = 600  # 10분

    def __init__(
        self,
        inspect_domains: list[str],
        rule_filter: Any,
        payload_builder: Any,
        api_client: Any,
        event_logger: Any,
        file_inspector: Any,
        on_blocked: Optional[Callable[[str, list, str], None]] = None,
        log_traffic: bool = True,
        skip_path_patterns: Optional[list[str]] = None,
        min_body_bytes: int = 0,
        drive_domains: Optional[list[str]] = None,
        drive_upload_patterns: Optional[list[str]] = None,
    ) -> None:
        self._domains           = frozenset(d.lower().lstrip("*.") for d in inspect_domains)
        self._drive_domains     = frozenset(d.lower().lstrip("*.") for d in (drive_domains or []))
        self._drive_upload_patterns = [p.lower() for p in (drive_upload_patterns or [])]
        self._rule_filter       = rule_filter
        self._builder           = payload_builder
        self._api               = api_client
        self._event_logger      = event_logger
        self._fi                = file_inspector
        self._on_blocked        = on_blocked
        self._log_traffic       = log_traffic
        self._skip_patterns     = [s.lower() for s in (skip_path_patterns or [])]
        self._min_body_bytes    = min_body_bytes
        # {host: last_popup_time} — 재시도 팝업 중복 방지
        self._popup_cache: dict[str, float] = {}
        # 업로드 세션 추적: upload_id → {filename, content_type}
        self._upload_meta: dict[str, dict] = {}
        self._upload_lock = threading.Lock()

    # ── mitmproxy 훅 ─────────────────────────────────────────────────────────

    def http_connect(self, flow) -> None:  # noqa: ANN001
        """DLP 대상 도메인 CONNECT만 로그. 그 외는 무시."""
        host = flow.request.pretty_host.lower()
        if self._is_target(host) or self._is_drive_target(host):
            logger.info("[WebProxy] CONNECT → %s [DLP 대상]", flow.request.pretty_host)

    def request(self, flow) -> None:  # noqa: ANN001
        """요청이 서버로 전달되기 전 호출. block 결정 시 즉시 응답 설정."""
        try:
            self._register_upload_init(flow)

            # ── 업로드 관련 요청 사전 로그 (도메인 파악용) ──────────────────────
            url = flow.request.pretty_url
            url_lower = url.lower()
            host = flow.request.pretty_host.lower()
            if self._is_drive_target(host) and flow.request.method in ("POST", "PUT", "PATCH"):
                cmd = flow.request.headers.get("x-goog-upload-command", "")
                logger.info(
                    "[WebProxy] Drive HTTP: method=%s size=%d cmd=%s url=%s",
                    flow.request.method,
                    len(flow.request.content or b""),
                    cmd or "-",
                    url[:200],
                )
            elif self._is_target(host) and any(
                p in url_lower for p in ("upload_id=", "/_/upload", "/upload/drive/")
            ):
                logger.info(
                    "[WebProxy] Upload 요청 수신: method=%s  size=%d  url=%s",
                    flow.request.method,
                    len(flow.request.content or b""),
                    url[:200],
                )

            self._handle(flow)
        except Exception:
            logger.exception("[WebProxy] request 처리 중 예외")

    def response(self, flow) -> None:  # noqa: ANN001
        """메일 전송 요청에 대한 응답만 로그. 업로드 세션 URI 캡처."""
        try:
            self._capture_upload_session(flow)
        except Exception:
            logger.debug("[WebProxy] 업로드 세션 캡처 실패", exc_info=True)

        if not self._log_traffic:
            return
        try:
            channel = self._get_dlp_channel(flow)
            if not channel:
                return
            req = flow.request
            res = flow.response
            if res is None:
                return
            logger.info(
                "[WebProxy] <- status=%s  %s %s  [%s]",
                res.status_code,
                req.method,
                req.pretty_url[:200],
                channel,
            )
        except Exception:
            logger.debug("[WebProxy] response 로그 실패", exc_info=True)

    # ── 업로드 세션 추적 ──────────────────────────────────────────────────────

    def _register_upload_init(self, flow) -> None:
        """업로드 초기화 POST에서 파일 메타데이터를 추출해 임시 저장."""
        req  = flow.request
        host = req.pretty_host.lower()
        if req.method != "POST":
            return
        if not self._is_target(host) and not self._is_drive_target(host):
            return
        upload_protocol = req.headers.get("x-goog-upload-protocol", "")
        upload_cmd = req.headers.get("x-goog-upload-command", "").lower()
        url = req.pretty_url.lower()
        is_init = (
            upload_cmd == "start"
            or bool(upload_protocol)
            or "/_/upload" in url
            or ("uploadtype=resumable" in url and "upload_id=" not in url)
        )
        if not is_init:
            return

        filename = (
            req.headers.get("x-goog-upload-file-name", "")
            or req.headers.get("x-goog-upload-original-filename", "")
            or req.headers.get("x-goog-upload-filename", "")
            or req.headers.get("x-goog-upload-header-content-disposition", "")
        )
        content_type = (
            req.headers.get("x-goog-upload-header-content-type", "")
            or req.headers.get("x-goog-upload-content-type", "")
            or req.headers.get("x-upload-content-type", "")
        )
        if filename or content_type:
            # 세션 ID를 모르는 상태 → response hook에서 연결
            flow.metadata["_upload_init"] = {
                "filename":     filename,
                "content_type": content_type,
            }
            logger.debug(
                "[WebProxy] Upload init 감지: filename=%s ct=%s",
                filename or "(미상)", content_type or "(미상)",
            )

    def _capture_upload_session(self, flow) -> None:
        """업로드 초기화 응답에서 upload_id를 추출해 메타데이터와 연결."""
        if "_upload_init" not in flow.metadata:
            return
        res = flow.response
        if res is None:
            return

        upload_id = res.headers.get("x-guploader-uploadid", "")
        if not upload_id:
            location = res.headers.get("location", "")
            if "upload_id=" in location:
                upload_id = parse_qs(urlparse(location).query).get("upload_id", [""])[0]

        meta = flow.metadata["_upload_init"]
        location = res.headers.get("location", "")

        # 응답 body 미리보기 — 실제 업로드 URL 파악용
        resp_body_preview = ""
        if res.content:
            try:
                resp_body_preview = res.content[:300].decode("utf-8", errors="ignore")
            except Exception:
                pass

        if upload_id:
            with self._upload_lock:
                self._upload_meta[upload_id] = meta
            logger.info(
                "[WebProxy] 업로드 세션 등록: id=%.24s  filename=%s  location=%s  resp_body=%s",
                upload_id,
                meta.get("filename") or "(미상)",
                location[:120] or "(없음)",
                resp_body_preview[:120] or "(없음)",
            )
        else:
            logger.info(
                "[WebProxy] Upload init 응답 (upload_id 미확인): status=%s  location=%s  resp_body=%s",
                res.status_code,
                location[:160] or "(없음)",
                resp_body_preview[:120] or "(없음)",
            )

    # ── 내부 로직 ─────────────────────────────────────────────────────────────

    def _is_mail_send(self, flow) -> bool:
        """검사 대상 웹메일 + 본문 전송 메서드(POST/PUT/PATCH) 여부.

        skip_path_patterns 에 걸리는 경로(sync·jserror·자동완성 등)는 제외.
        min_body_bytes 미만 본문도 제외.
        실제 파일 업로드(PUT /?...upload_id=...)는 skip_path_patterns 와 무관하게 항상 포함.
        """
        if flow.request.method not in ("POST", "PUT", "PATCH"):
            return False
        if not self._is_target(flow.request.pretty_host.lower()):
            return False

        url_lower = flow.request.pretty_url.lower()

        # 실제 파일 업로드 요청 — skip_path_patterns·min_body_bytes 우회
        # (작은 파일 1 byte라도 검사 대상)
        is_upload = "upload_id=" in url_lower or "/_/upload" in url_lower
        if is_upload:
            return len(flow.request.content or b"") >= 1

        # 경로·쿼리 기반 제외
        for pat in self._skip_patterns:
            if pat in url_lower:
                return False

        # 최소 본문 크기 미만 제외
        if self._min_body_bytes and len(flow.request.content or b"") < self._min_body_bytes:
            return False

        return True

    def _log_send(self, flow) -> None:
        """메일 전송 패킷 한 줄 + 본문 미리보기."""
        req = flow.request
        body = req.content or b""
        ct = req.headers.get("content-type", "-")
        if len(ct) > 60:
            ct = ct[:57] + "..."

        logger.info(
            "[WebProxy] -> %s %s  bytes=%d  ct=%s",
            req.method,
            req.pretty_url[:200],
            len(body),
            ct,
        )

        if body:
            try:
                preview = body.decode("utf-8", errors="replace")
            except Exception:
                preview = repr(body[: self._BODY_PREVIEW])
            preview = preview.replace("\r", " ").replace("\n", " ")
            if len(preview) > self._BODY_PREVIEW:
                preview = preview[: self._BODY_PREVIEW] + "..."
            logger.info("[WebProxy]    body preview: %s", preview)

    def _handle(self, flow) -> None:
        from mitmproxy.http import Response  # 지연 임포트 — 서비스 시 유효

        channel = self._get_dlp_channel(flow)
        if not channel:
            return

        # 실제 파일 업로드 PUT 감지 — 명시적 로그
        url_lower = flow.request.pretty_url.lower()
        if flow.request.method == "PUT" and "upload_id=" in url_lower:
            logger.info(
                "[WebProxy] 파일 업로드 PUT 수신: size=%d  url=%s",
                len(flow.request.content or b""),
                flow.request.pretty_url[:180],
            )

        if self._log_traffic:
            self._log_send(flow)

        text = self._extract_text(flow)
        if not text or not text.strip():
            if self._log_traffic:
                logger.info(
                    "[WebProxy]    DLP skip (empty text) url=%s",
                    flow.request.pretty_url[:180],
                )
            return

        hits = self._rule_filter.match(text)
        if not hits:
            if self._log_traffic:
                logger.info(
                    "[WebProxy]    DLP regex: no hit  text_len=%d",
                    len(text),
                )
            return

        if self._log_traffic:
            ids = ",".join(h.get("id", "?") for h in hits[:8])
            logger.info(
                "[WebProxy]    DLP regex: HIT n=%d ids=[%s]  text_len=%d",
                len(hits),
                ids,
                len(text),
            )

        host = flow.request.pretty_host.lower()
        process_name = f"browser@{host}"
        payload = self._builder.build(text, hits, channel, process_name)
        result  = self._api.analyze(payload)

        logger.info(
            "[WebProxy] AI 판단: action=%s confidence=%.2f url=%s",
            result.action, result.confidence_score, flow.request.pretty_url,
        )

        try:
            record_analysis_result(
                self._event_logger,
                result,
                channel=channel,
                process_name=process_name,
                hits=hits,
                text=text,
                event_id=payload.request_id,
                detection_type="RULE_BASED" if getattr(self._api, "is_mock", True) else "HYBRID",
                metadata={"url": flow.request.pretty_url},
            )
        except Exception:
            # 로컬 저장소·대시보드 기록 장애는 AI 판정을 바꾸지 않는다.
            logger.exception("[WebProxy] 분석 결과 기록 실패(판정 유지)")

        if result.should_block:
            # 차단 응답을 먼저 확정한다. 이후 팝업이 실패해도 451은 유지된다.
            pattern_names = ", ".join(h.get("name", h.get("id", "")) for h in hits)
            html = _BLOCK_HTML.format(
                reason=result.reason or "민감정보 탐지",
                patterns=pattern_names,
            )
            flow.response = Response.make(
                451,
                html.encode("utf-8"),
                {
                    "Content-Type":  "text/html; charset=utf-8",
                    "X-DLP-Blocked": "1",
                    "Cache-Control": "no-store",
                },
            )

            # 같은 호스트 60초 내 팝업 1회만 (재시도/동시다발 차단 팝업 폭탄 방지)
            if self._on_blocked:
                try:
                    import time as _time
                    host = flow.request.pretty_host.lower()
                    now = _time.monotonic()
                    last = self._popup_cache.get(host, 0)
                    if now - last > self._POPUP_DEDUP_SEC:
                        self._popup_cache[host] = now
                        self._on_blocked(flow.request.pretty_url, hits, process_name)
                    else:
                        logger.info(
                            "[WebProxy] 재시도 차단 (팝업 생략) url=%s",
                            flow.request.pretty_url[:120],
                        )
                except Exception:
                    logger.exception("[WebProxy] 차단 팝업 실패(451 차단 유지)")
            return

        if result.needs_review:
            try:
                notify_review(channel, flow.request.pretty_url, hits)
            except Exception:
                logger.exception("[WebProxy] review 경고 실패(업로드 허용 유지)")
            logger.warning("[WebProxy] review 기록 — %s", flow.request.pretty_url)
        elif result.analysis_failed:
            logger.warning("[WebProxy] AI 장애 Fail-Open 기록 — 업로드 허용: %s", flow.request.pretty_url)
        else:
            logger.info("[WebProxy] AI allow 기록 — 업로드 허용: %s", flow.request.pretty_url)
        # allow/review → 그대로 통과

    # ── 도메인 매칭 ──────────────────────────────────────────────────────────

    def _is_target(self, host: str) -> bool:
        """웹메일 도메인 여부."""
        for domain in self._domains:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def _is_drive_target(self, host: str) -> bool:
        """클라우드 드라이브 도메인 여부."""
        for domain in self._drive_domains:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    def _get_dlp_channel(self, flow) -> str:
        """DLP 채널 이름 반환. 검사 대상 아니면 빈 문자열."""
        if self._is_mail_send(flow):
            return "web_mail"
        if self._is_drive_upload(flow):
            return "drive_upload"
        return ""

    def _is_google_drive_host(self, host: str) -> bool:
        return any(
            k in host
            for k in (
                "drive.google.com",
                "docs.google.com",
                "googleapis.com",
                "clients6.google.com",
            )
        )

    def _is_drive_upload(self, flow) -> bool:
        """클라우드 드라이브 파일 업로드 요청 여부.

        Drive 웹 UI는 Gmail과 같이 /_/upload + X-Goog-Upload-* 를 쓴다.
        Drive API는 /upload/drive/?uploadType=media|multipart|resumable 를 쓴다.
        세션 초기화(start / resumable 메타데이터)는 파일 본문이 없으므로 제외.
        """
        if flow.request.method not in ("POST", "PUT", "PATCH"):
            return False
        host = flow.request.pretty_host.lower()
        if not self._is_drive_target(host):
            return False

        url_lower = flow.request.pretty_url.lower()
        body_len  = len(flow.request.content or b"")
        cmd       = flow.request.headers.get("x-goog-upload-command", "").lower()
        ct        = flow.request.headers.get("content-type", "").lower()

        # ── Google Drive / Docs / Drive API ──────────────────────────────────
        if self._is_google_drive_host(host):
            if cmd.strip() == "start":
                return False
            if (
                "uploadtype=resumable" in url_lower
                and "upload_id=" not in url_lower
                and "upload" not in cmd
                and "json" in ct
            ):
                return False

            if "upload" in cmd or "finalize" in cmd:
                return body_len >= 1
            if "upload_id=" in url_lower or "/_/upload" in url_lower:
                return body_len >= 1
            if "/upload/drive" in url_lower or "/upload/resumable" in url_lower:
                return body_len >= 1
            for pat in self._drive_upload_patterns:
                if pat in url_lower:
                    return body_len >= 1
            return False

        # ── Naver MYBOX ──────────────────────────────────────────────────────
        if "mybox.naver.com" in host:
            if "/upload" in url_lower:
                return body_len >= 1
            return "multipart" in ct and body_len >= 1

        # ── OneDrive / Microsoft Graph ────────────────────────────────────────
        if any(d in host for d in ("onedrive.live.com", "api.onedrive.com",
                                    "graph.microsoft.com", "storage.live.com")):
            if "createuploadsession" in url_lower:
                return False
            if url_lower.endswith("/content") or ":/content" in url_lower:
                return body_len >= 1
            if flow.request.method == "PUT":
                return body_len >= 1
            return False

        # ── Dropbox ──────────────────────────────────────────────────────────
        if "dropboxapi.com" in host:
            if "/2/files/upload" in url_lower:
                return body_len >= 1
            return False

        # ── Box ───────────────────────────────────────────────────────────────
        if "box.com" in host:
            if "/api/2.0/files/content" in url_lower:
                return body_len >= 1
            if "/api/2.0/files/upload_session" in url_lower and flow.request.method == "PUT":
                return body_len >= 1
            return False

        for pat in self._drive_upload_patterns:
            if pat in url_lower:
                return body_len >= 1
        return False

    # ── 본문 텍스트 추출 ─────────────────────────────────────────────────────

    def _extract_text(self, flow) -> str:
        ct       = flow.request.headers.get("content-type", "").lower()
        body     = flow.request.content
        if not body:
            return ""

        url       = flow.request.pretty_url
        url_lower = url.lower()
        host      = flow.request.pretty_host.lower()
        cmd       = flow.request.headers.get("x-goog-upload-command", "").lower()

        # Drive/Gmail 업로드가 multipart 이면 파트별로 파일 내용을 추출해야 한다.
        # (JSON 메타데이터 + 파일 본문이 한 요청에 실림)
        if "multipart/" in ct:
            extracted = self._from_multipart(body, ct)
            if extracted and extracted.strip():
                return extracted

        # ── 파일 업로드 바이너리 (Gmail 첨부 + Drive 웹/API) ───────────────────
        is_binary_upload = (
            "upload_id=" in url_lower
            or "/_/upload" in url_lower
            or "/upload/drive" in url_lower
            or "/upload/resumable" in url_lower
            or "upload" in cmd
            or "finalize" in cmd
            or self._is_drive_upload(flow)
        )
        if is_binary_upload and (
            self._is_drive_target(host) or "upload_id=" in url_lower or "/_/upload" in url_lower
        ):
            return self._extract_upload_binary(flow, body, ct) or ""

        # ── Dropbox 업로드: Dropbox-API-Arg 헤더에서 파일명 추출 ───────────────
        if "dropboxapi.com" in host and "/2/files/upload" in url_lower:
            return self._extract_dropbox_upload(flow, body, ct)

        # ── OneDrive / Microsoft Graph PUT ────────────────────────────────────
        if any(d in host for d in ("onedrive.live.com", "api.onedrive.com",
                                    "graph.microsoft.com", "storage.live.com")):
            if url_lower.endswith("/content") or ":/content" in url_lower or flow.request.method == "PUT":
                return self._extract_upload_binary(flow, body, ct) or ""

        # ── Box 업로드 ────────────────────────────────────────────────────────
        if "box.com" in host:
            if "multipart" in ct:
                return self._from_multipart(body, ct)
            return self._extract_upload_binary(flow, body, ct) or ""

        # ── Naver MYBOX (multipart 또는 octet-stream) ─────────────────────────
        if "mybox.naver.com" in host:
            if "multipart" in ct:
                return self._from_multipart(body, ct)
            return self._extract_upload_binary(flow, body, ct) or ""

        # ── 일반 경로 (웹메일 본문 텍스트 등) ────────────────────────────────
        if "application/json" in ct:
            return self._from_json(body)
        if "multipart/" in ct:
            return self._from_multipart(body, ct)
        if "application/x-www-form-urlencoded" in ct:
            return self._from_urlencoded(body)
        if self._fi and ("octet-stream" in ct or not ct):
            fname = url.rstrip("/").rsplit("/", 1)[-1].split("?")[0] or "upload.bin"
            extracted = self._fi.extract_from_bytes(body, fname)
            if extracted:
                return extracted
        return body.decode("utf-8", errors="ignore")

    def _extract_upload_binary(self, flow, body: bytes, ct: str) -> str:
        """첨부파일 업로드 본문에서 텍스트 추출.

        POST/PUT /_/upload 또는 upload_id 포함 URL 처리.
        우선순위: 세션 메타데이터 파일명 > Content-Disposition > Content-Type 추론 > UTF-8 디코드
        """
        url = flow.request.pretty_url

        # 업로드 세션 메타데이터에서 파일명·CT 조회
        upload_id = parse_qs(urlparse(url).query).get("upload_id", [""])[0]
        with self._upload_lock:
            meta = self._upload_meta.get(upload_id, {})

        filename  = meta.get("filename", "")
        stored_ct = meta.get("content_type", "") or ct

        if not filename:
            filename = (
                flow.request.headers.get("x-goog-upload-file-name", "")
                or flow.request.headers.get("x-goog-upload-original-filename", "")
            )

        # Content-Disposition 헤더에서 파일명 보완
        if not filename:
            cd = flow.request.headers.get("content-disposition", "")
            m  = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', cd)
            if m:
                filename = m.group(1).strip()

        # Content-Type에서 확장자 추론 (알려진 파일 형식일 때)
        effective_ct = stored_ct.split(";")[0].strip()
        if "multipart/" in effective_ct:
            extracted = self._from_multipart(body, stored_ct or ct)
            if extracted and extracted.strip():
                return extracted

        if not filename or "." not in filename:
            ext      = _infer_ext_from_ct(effective_ct)
            filename = f"upload{ext}" if ext else "upload.bin"

        logger.info(
            "[WebProxy] 첨부파일 업로드 검사: method=%s filename=%s size=%d ct=%s",
            flow.request.method, filename, len(body), effective_ct,
        )

        # FileInspector로 텍스트 추출
        if self._fi:
            try:
                text = self._fi.extract_from_bytes(body, filename)
                if text and text.strip():
                    return text
            except Exception as exc:
                logger.debug("[WebProxy] 업로드 FileInspector 실패: %s", exc)

        # text/* Content-Type이면 UTF-8로 직접 디코드
        if effective_ct.startswith("text/"):
            try:
                return body.decode("utf-8", errors="ignore")
            except Exception:
                pass

        # 순수 UTF-8 텍스트 fallback (binary 판별)
        try:
            decoded = body.decode("utf-8", errors="strict")
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t") / max(len(decoded), 1)
            if printable_ratio > 0.85:  # 85% 이상 출력 가능 문자 → 텍스트 파일
                return decoded
        except UnicodeDecodeError:
            pass

        return ""

    def _extract_dropbox_upload(self, flow, body: bytes, ct: str) -> str:
        """Dropbox 업로드 본문 텍스트 추출.

        Dropbox-API-Arg 헤더에서 파일 경로를 읽어 파일명을 확보하고,
        본문(raw 바이너리)을 FileInspector로 검사.
        """
        filename = ""
        try:
            arg_header = flow.request.headers.get("dropbox-api-arg", "")
            if arg_header:
                meta = json.loads(arg_header)
                path = meta.get("path", "")
                if path:
                    filename = path.rsplit("/", 1)[-1]
        except Exception:
            pass

        if not filename:
            cd = flow.request.headers.get("content-disposition", "")
            m  = re.search(r'filename[*]?=["\']?([^"\';\r\n]+)', cd)
            if m:
                filename = m.group(1).strip()

        if not filename:
            ext      = _infer_ext_from_ct(ct.split(";")[0].strip())
            filename = f"upload{ext}" if ext else "upload.bin"

        logger.info(
            "[WebProxy] Dropbox 업로드 검사: filename=%s size=%d",
            filename, len(body),
        )

        if self._fi:
            try:
                text = self._fi.extract_from_bytes(body, filename)
                if text and text.strip():
                    return text
            except Exception as exc:
                logger.debug("[WebProxy] Dropbox FileInspector 실패: %s", exc)

        try:
            decoded = body.decode("utf-8", errors="strict")
            ratio   = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t") / max(len(decoded), 1)
            if ratio > 0.85:
                return decoded
        except UnicodeDecodeError:
            pass

        return ""

    def _from_json(self, body: bytes) -> str:
        """JSON 객체에서 모든 문자열 값을 재귀 수집."""
        try:
            obj = json.loads(body)
        except Exception:
            return body.decode("utf-8", errors="ignore")
        parts: list[str] = []
        _collect_strings(obj, parts)
        return "\n".join(parts)

    def _from_multipart(self, body: bytes, ct: str) -> str:
        """multipart 파트별 텍스트 + 첨부파일 추출.

        Google Drive 웹 업로드는 filename 헤더 없이
        1) application/json 메타데이터 (title/mimeType)
        2) 파일 본문 (text/plain, octet-stream 등)
        순서로 보낸다. JSON에서 파일명을 읽어 두 번째 파트에 적용한다.
        """
        try:
            mime = message_from_bytes(
                b"Content-Type: " + ct.encode() + b"\r\n\r\n" + body
            )
        except Exception:
            return body.decode("utf-8", errors="ignore")

        parts: list[str] = []
        inferred_name = ""

        for part in mime.walk():
            if part.is_multipart():
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            filename = part.get_filename() or ""
            pct = (part.get_content_type() or "").lower()

            if "json" in pct:
                try:
                    meta = json.loads(payload.decode("utf-8", errors="ignore"))
                except Exception:
                    meta = None
                if isinstance(meta, dict):
                    inferred_name = (
                        meta.get("title")
                        or meta.get("name")
                        or meta.get("originalFilename")
                        or inferred_name
                    )
                    if inferred_name:
                        logger.info("[WebProxy] Drive 메타데이터 파일명: %s", inferred_name)
                continue

            name = filename or inferred_name
            encoding = (part.get("Content-Transfer-Encoding") or "").lower()
            if "base64" in encoding:
                try:
                    payload = base64.b64decode(payload)
                except Exception:
                    pass

            if name and self._fi:
                try:
                    extracted = self._fi.extract_from_bytes(payload, name)
                    if extracted:
                        parts.append(f"[첨부: {name}]\n{extracted}")
                        continue
                except Exception as exc:
                    logger.debug("[WebProxy] 첨부 추출 실패 %s: %s", name, exc)

            if self._fi and pct not in ("application/json",):
                ext = _infer_ext_from_ct(pct) or (
                    Path(name).suffix if name else ""
                )
                guess = name or (f"upload{ext}" if ext else "upload.bin")
                try:
                    extracted = self._fi.extract_from_bytes(payload, guess)
                    if extracted:
                        parts.append(extracted)
                        continue
                except Exception:
                    pass

            if "text" in pct or pct in ("application/octet-stream", ""):
                charset = part.get_param("charset", "utf-8") or "utf-8"
                try:
                    parts.append(payload.decode(charset, errors="ignore"))
                except Exception:
                    parts.append(payload.decode("utf-8", errors="ignore"))

        text = "\n\n".join(parts)
        if text.strip():
            return text
        return self._from_multipart_fallback(body, ct)

    def _from_multipart_fallback(self, body: bytes, ct: str) -> str:
        """email 파서가 파트를 못 나눌 때 boundary 기준 수동 분리."""
        boundary = ""
        m = re.search(r'boundary=("?)([^";\s]+)\1', ct, re.I)
        if m:
            boundary = m.group(2)
        if not boundary:
            first = body.split(b"\n", 1)[0].strip().rstrip(b"\r")
            if first.startswith(b"--") and len(first) > 4:
                boundary = first[2:].decode("ascii", errors="ignore").strip()
        if not boundary:
            return ""

        marker = b"--" + boundary.encode("ascii", errors="ignore")
        chunks = body.split(marker)
        inferred_name = ""
        out: list[str] = []
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk or chunk in (b"-", b"--"):
                continue
            header_blob, _, payload = chunk.partition(b"\r\n\r\n")
            if not payload:
                header_blob, _, payload = chunk.partition(b"\n\n")
            payload = payload.rstrip(b"\r\n-")
            if not payload:
                continue
            headers = header_blob.decode("utf-8", errors="ignore").lower()
            if "application/json" in headers:
                try:
                    meta = json.loads(payload.decode("utf-8", errors="ignore"))
                    if isinstance(meta, dict):
                        inferred_name = (
                            meta.get("title") or meta.get("name") or inferred_name
                        )
                except Exception:
                    pass
                continue
            name = inferred_name or "upload.bin"
            if self._fi:
                extracted = self._fi.extract_from_bytes(payload, name)
                if extracted:
                    out.append(f"[첨부: {name}]\n{extracted}")
                    continue
            out.append(payload.decode("utf-8", errors="ignore"))
        return "\n\n".join(out)

    def _from_urlencoded(self, body: bytes) -> str:
        """application/x-www-form-urlencoded 파싱."""
        try:
            params = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
            return "\n".join(v for values in params.values() for v in values)
        except Exception:
            return body.decode("utf-8", errors="ignore")


def _collect_strings(obj: Any, parts: list[str], depth: int = 0) -> None:
    """JSON 객체를 재귀 순회해 의미 있는 문자열을 수집."""
    if depth > 12:
        return
    if isinstance(obj, str):
        if len(obj) > 3:  # 너무 짧은 값 제외
            parts.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, parts, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, parts, depth + 1)


# ── WebProxy 클래스 ───────────────────────────────────────────────────────────

class WebProxy:
    """mitmproxy를 백그라운드 스레드에서 실행하는 HTTPS MITM DLP 채널.

    allow_hosts 로 inspect_domains 만 TLS 가로채기하고,
    그 외 트래픽은 터널 통과(로그·복호화 없음).
    DLP/로그는 메일 전송(POST/PUT/PATCH) 패킷만 대상.
    """

    def __init__(
        self,
        port: int,
        inspect_domains: list[str],
        rule_filter: Any,
        payload_builder: Any,
        api_client: Any,
        event_logger: Any,
        file_inspector: Any,
        on_blocked: Optional[Callable[[str, list, str], None]] = None,
        log_traffic: bool = True,
        skip_path_patterns: Optional[list[str]] = None,
        min_body_bytes: int = 0,
        drive_domains: Optional[list[str]] = None,
        drive_upload_patterns: Optional[list[str]] = None,
    ) -> None:
        self._port = port
        self._inspect_domains = [
            d.strip().lower().lstrip("*.") for d in inspect_domains if d and d.strip()
        ]
        self._drive_domains = [
            d.strip().lower().lstrip("*.") for d in (drive_domains or []) if d and d.strip()
        ]
        self._addon = _DLPAddon(
            inspect_domains=self._inspect_domains,
            rule_filter=rule_filter,
            payload_builder=payload_builder,
            api_client=api_client,
            event_logger=event_logger,
            file_inspector=file_inspector,
            on_blocked=on_blocked,
            log_traffic=log_traffic,
            skip_path_patterns=skip_path_patterns,
            min_body_bytes=min_body_bytes,
            drive_domains=self._drive_domains,
            drive_upload_patterns=drive_upload_patterns,
        )
        self._thread: Optional[threading.Thread] = None
        self._master: Any = None
        self._loop: Any = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name="WebProxy",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "[채널] web_proxy   ON  (port=%d, mail_hosts=%d, drive_hosts=%d)",
            self._port,
            len(self._inspect_domains),
            len(self._drive_domains),
        )

    def stop(self) -> None:
        if self._master is not None:
            try:
                if self._loop and self._loop.is_running():
                    self._loop.call_soon_threadsafe(self._master.shutdown)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("[WebProxy] 중지")

    @staticmethod
    def _allow_host_patterns(domains: list[str]) -> list[str]:
        """mitmproxy allow_hosts 용 정규식.

        mitmproxy는 allow_hosts 패턴을 'host:port' 문자열 전체에 대해
        re.search() 로 매칭한다. $ 앵커를 쓰면 :443 때문에 미매칭 발생.
        → 서브도메인 포함 도메인만 매칭하도록 lookahead 없이 구성.
        """
        patterns: list[str] = []
        for d in domains:
            esc = re.escape(d)
            # (subdomain.)domain.com(:port)? — re.search 기준
            patterns.append(rf"(?:^|\.){esc}(?::\d+)?$")
        return patterns

    # ── 내부 ─────────────────────────────────────────────────────────────────

    def _run(self) -> None:
        try:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster
        except ImportError:
            logger.error(
                "[WebProxy] mitmproxy가 설치되지 않았습니다.\n"
                "  pip install mitmproxy"
            )
            return

        # mitmproxy 자체 connect 로그 억제 — 메일 전송 로그만 노출
        logging.getLogger("mitmproxy").setLevel(logging.WARNING)
        logging.getLogger("mitmproxy.proxy").setLevel(logging.WARNING)
        logging.getLogger("mitmproxy.proxy.server").setLevel(logging.WARNING)
        logging.getLogger("mitmproxy.proxy.mode_servers").setLevel(logging.INFO)

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # 메일 + 드라이브 도메인 전체 TLS 가로채기 (그 외는 터널 통과)
        all_domains = self._inspect_domains + self._drive_domains
        allow = self._allow_host_patterns(all_domains)
        opts_kwargs: dict[str, Any] = {
            "listen_host": "127.0.0.1",
            "listen_port": self._port,
            "ssl_insecure": False,
        }
        if allow:
            opts_kwargs["allow_hosts"] = allow

        opts = Options(**opts_kwargs)

        self._master = DumpMaster(
            opts,
            loop=self._loop,
            with_termlog=False,
            with_dumper=False,
        )
        self._master.addons.add(self._addon)

        if allow:
            logger.info(
                "[WebProxy] TLS inspect: mail=%d drive=%d total=%d pattern(s)",
                len(self._inspect_domains),
                len(self._drive_domains),
                len(allow),
            )

        try:
            self._loop.run_until_complete(self._master.run())
        except Exception:
            logger.exception("[WebProxy] mitmproxy 실행 오류")
        finally:
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            except Exception:
                pass
            self._loop.close()
