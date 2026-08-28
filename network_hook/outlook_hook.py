"""Outlook COM ItemSend 이벤트 훅.

동작 흐름
---------
1. Outlook.Application COM 객체에 이벤트 싱크 연결
2. 전송 직전(ItemSend) 이벤트 수신
3. 수신자 도메인 확인 → 외부 수신자가 있을 때만 검사
4. 메일 본문 + 첨부파일 텍스트 추출 → 정규식 검사
5. AI block이면 ItemSend Cancel=True로 전송 취소, review/allow이면 전송 허용

제한
----
- Outlook이 실행 중이어야 한다 (이 훅이 먼저 켜져 있어도 Outlook 재시작 시 재연결 필요).
- pywin32는 이벤트 핸들러 반환값을 유일한 ByRef Cancel 파라미터로 전달한다.
- Outlook 버전: 2016 이상 (Microsoft 365 포함).
"""

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


def _build_sink(
    internal_domains: frozenset[str],
    on_blocked: Callable[[str, list[dict[str, Any]], str], Optional[str]],
    inspect: Callable[[str], list[dict[str, Any]]],
    file_inspector_extract: Callable[[bytes, str], Optional[str]],
) -> type:
    """이벤트 싱크 클래스를 동적으로 생성한다 (클로저로 의존성 주입)."""

    class _OutlookSink:
        def OnItemSend(self, item, cancel):  # noqa: N802
            try:
                return _handle_item_send(
                    item,
                    internal_domains,
                    on_blocked,
                    inspect,
                    file_inspector_extract,
                )
            except Exception:
                logger.exception("OutlookSink.OnItemSend 처리 중 예외")
                return False

    return _OutlookSink


def _is_external(recipient_address: str, internal_domains: frozenset[str]) -> bool:
    """수신자 주소가 외부 도메인인지 확인한다."""
    addr = recipient_address.lower().strip()
    if "@" not in addr:
        return False  # 그룹/별칭 — 보수적으로 내부로 처리
    domain = addr.split("@", 1)[1]
    return domain not in internal_domains


def _resolve_recipient_address(recipient: Any) -> tuple[str, bool]:
    """Resolve Exchange legacy addresses to SMTP.

    Returns ``(address, unresolved_exchange)``. An unresolved Exchange address
    must not be treated as internal merely because its legacy EX value lacks
    an ``@`` sign.
    """
    raw_address = ""
    try:
        raw_address = str(recipient.Address or "").strip()
    except Exception:
        pass

    entry = None
    entry_type = ""
    try:
        entry = recipient.AddressEntry
        entry_type = str(entry.Type or "").upper()
    except Exception:
        pass

    is_exchange = entry_type == "EX" or raw_address.upper().startswith("/O=")
    if not is_exchange:
        return raw_address, False

    if entry is not None:
        for resolver_name in ("GetExchangeUser", "GetExchangeDistributionList"):
            try:
                resolver = getattr(entry, resolver_name)
                resolved = resolver()
                smtp = str(getattr(resolved, "PrimarySmtpAddress", "") or "").strip()
                if "@" in smtp:
                    return smtp, False
            except Exception:
                continue

    return raw_address or "unresolved-exchange-recipient", True


def _collect_text(
    item: Any,
    file_inspector_extract: Callable[[bytes, str], Optional[str]],
) -> str:
    """MailItem 본문과 첨부파일 전체를 하나의 텍스트로 합친다."""
    parts: list[str] = []

    # 본문
    try:
        body = item.Body or ""
        parts.append(body[:32_768])  # 32 KB 상한
    except Exception:
        pass

    # 첨부파일
    try:
        for i in range(1, item.Attachments.Count + 1):
            att = item.Attachments.Item(i)
            try:
                import tempfile, os
                suffix = Path(att.FileName).suffix
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
                    tmp_path = tf.name
                att.SaveAsFile(tmp_path)
                data = Path(tmp_path).read_bytes()
                os.unlink(tmp_path)

                text = file_inspector_extract(data, att.FileName)
                if text:
                    parts.append(f"[첨부: {att.FileName}]\n{text[:16_384]}")
            except Exception as exc:
                logger.debug("첨부파일 추출 실패 (%s): %s", att.FileName, exc)
    except Exception:
        pass

    return "\n\n".join(parts)


def _handle_item_send(
    item: Any,
    internal_domains: frozenset[str],
    on_blocked: Callable[[str, list[dict[str, Any]], str], Optional[str]],
    inspect: Callable[[str], list[dict[str, Any]]],
    file_inspector_extract: Callable[[bytes, str], Optional[str]],
) -> bool:
    # 메일 아이템인지 확인 (약속/작업 등 제외)
    try:
        item_class = item.Class  # 43 = olMail
        if item_class != 43:
            return False
    except Exception:
        return False

    # 수신자 중 외부 도메인이 있는지 확인
    external_recipients: list[str] = []
    try:
        for i in range(1, item.Recipients.Count + 1):
            rec = item.Recipients.Item(i)
            addr, unresolved_exchange = _resolve_recipient_address(rec)
            if unresolved_exchange:
                external_recipients.append(
                    f"[SMTP 확인 불가 Exchange 수신자: {addr[:200]}]"
                )
            elif addr and _is_external(addr, internal_domains):
                external_recipients.append(addr)
    except Exception:
        pass

    if not external_recipients:
        logger.debug("OutlookHook: 외부 수신자 없음 — 검사 생략")
        return False

    logger.debug("OutlookHook: 외부 수신자 %s — 내용 검사 시작", external_recipients)

    text = _collect_text(item, file_inspector_extract)
    if not text.strip():
        return False

    hits = inspect(text)
    if not hits:
        logger.debug("OutlookHook: 정규식 미탐지 — 전송 허용")
        return False

    # 정규식으로 검사한 같은 본문을 AI에도 전달한다. 수신자는
    # 메일 목적지 문맥을 잃지 않도록 스니펫 앞에 붙인다.
    analysis_text = f"[외부 수신자: {', '.join(external_recipients)}]\n{text}"
    decision = on_blocked(analysis_text, hits, "outlook.exe")
    if decision != "block":
        logger.warning(
            "OutlookHook: %s 판정 — 메일 전송 허용 recipients=%s",
            decision or "unknown (Fail-Open)",
            external_recipients,
        )
        return False

    # Cancel=True가 실제 전송 취소 수단이다. 저장은 초안 보존을 위한 best-effort이며,
    # inline reply 등에서 Save가 실패해도 취소 반환값은 유지한다.
    try:
        item.Save()
    except Exception as exc:
        logger.warning("OutlookHook: 차단 메일 초안 저장 실패: %s", exc)

    logger.warning(
        "OutlookHook: 메일 차단 — hits=%s recipients=%s",
        [h.get("id") for h in hits],
        external_recipients,
    )
    return True


# ── 공개 클래스 ───────────────────────────────────────────────────────────────

class OutlookHook:
    """Outlook COM 이벤트를 구독하고 외부 메일 발송을 검사한다."""

    def __init__(
        self,
        internal_domains: list[str],
        inspect: Callable[[str], list[dict[str, Any]]],
        on_blocked: Callable[[str, list[dict[str, Any]], str], Optional[str]],
        file_inspector_extract: Callable[[bytes, str], Optional[str]],
        poll_interval: float = 1.0,
    ) -> None:
        self._domains = frozenset(d.lower() for d in internal_domains)
        self._inspect = inspect
        self._on_blocked = on_blocked
        self._fi_extract = file_inspector_extract
        self._poll_interval = poll_interval

        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="OutlookHook"
        )
        self._thread.start()
        logger.info("OutlookHook 스레드 시작")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("OutlookHook 종료")

    def _run(self) -> None:
        try:
            import pythoncom
            import win32com.client as wc
        except ImportError:
            logger.error("pywin32 미설치 — OutlookHook을 시작할 수 없습니다.")
            return

        pythoncom.CoInitialize()
        try:
            sink_class = _build_sink(
                self._domains,
                self._on_blocked,
                self._inspect,
                self._fi_extract,
            )
            app = wc.DispatchWithEvents("Outlook.Application", sink_class)
            logger.info("Outlook COM 연결 완료 — ItemSend 이벤트 수신 대기")

            while self._running:
                pythoncom.PumpWaitingMessages()
                time.sleep(self._poll_interval)
        except Exception as exc:
            logger.error("OutlookHook 실행 오류: %s", exc)
        finally:
            pythoncom.CoUninitialize()
