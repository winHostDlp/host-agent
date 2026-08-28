"""로컬 SMTP 프록시 — 메일 발송을 가로채 민감정보를 검사한다.

동작 흐름
---------
1. localhost:2525 에서 SMTP 서버 대기 (aiosmtpd)
2. 메일 클라이언트(Outlook, Thunderbird 등)의 SMTP를 localhost:2525 로 설정
3. 수신한 메일에서 본문 + 첨부파일 텍스트 추출 → 정규식 검사
4. 미탐지 또는 AI review/allow → 실제 SMTP 서버로 릴레이
   AI block                      → 릴레이 거부(SMTP 550) + 알림

설정 방법
---------
메일 클라이언트의 발신 SMTP 서버:
  호스트: 127.0.0.1
  포트  : 2525 (channel_policy.json smtp.proxy_port 값)
  인증  : 없음 (프록시가 알아서 처리)

실제 SMTP 서버는 channel_policy.json smtp.relay 섹션에 설정.
"""

import asyncio
import base64
import email
import email.policy
import logging
import threading
from email.message import EmailMessage
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class _DLPHandler:
    """aiosmtpd LMTP/SMTP 핸들러 — 메일 수신 후 검사·릴레이."""

    def __init__(
        self,
        internal_domains: frozenset[str],
        relay_host: str,
        relay_port: int,
        relay_use_tls: bool,
        relay_username: Optional[str],
        relay_password: Optional[str],
        inspect: Callable[[str], list[dict[str, Any]]],
        on_blocked: Callable[[str, list[dict[str, Any]], str], str],
        fi_extract: Callable[[bytes, str], Optional[str]],
    ) -> None:
        self._internal_domains = internal_domains
        self._relay_host = relay_host
        self._relay_port = relay_port
        self._relay_tls = relay_use_tls
        self._relay_user = relay_username
        self._relay_pass = relay_password
        self._inspect = inspect
        self._on_blocked = on_blocked
        self._fi_extract = fi_extract

    async def handle_DATA(self, server, session, envelope):  # noqa: N802
        """aiosmtpd이 DATA 명령 완료 후 호출하는 메서드."""
        try:
            return await self._process(envelope)
        except Exception:
            logger.exception("SMTP 핸들러 예외")
            return "421 내부 오류"

    async def _process(self, envelope) -> str:
        # 외부 수신자 필터
        external = [
            addr for addr in envelope.rcpt_tos
            if self._is_external(addr)
        ]
        if not external:
            await self._relay(envelope)
            return "250 OK (내부 수신자 — 검사 생략)"

        # 텍스트 추출
        msg = email.message_from_bytes(
            envelope.content, policy=email.policy.default
        )
        text = self._extract_text(msg)

        if not text.strip():
            await self._relay(envelope)
            return "250 OK"

        hits = self._inspect(text)
        if not hits:
            await self._relay(envelope)
            return "250 OK"

        summary = f"수신자: {', '.join(external)}"
        decision = self._on_blocked(summary, hits, "smtp_proxy") or "block"
        if decision != "block":
            await self._relay(envelope)
            logger.warning(
                "SMTP %s 경고 기록 — 메일 전송 허용 from=%s to=%s",
                decision,
                envelope.mail_from,
                external,
            )
            return "250 OK (DLP 경고 기록 — 전송 허용)"

        logger.warning(
            "SMTP 차단 — from=%s to=%s hits=%s",
            envelope.mail_from,
            external,
            [h.get("id") for h in hits],
        )
        return "550 민감한 정보가 포함되어 있어 전송이 차단되었습니다."

    def _is_external(self, addr: str) -> bool:
        addr = addr.lower().strip()
        if "@" not in addr:
            return False
        return addr.split("@", 1)[1] not in self._internal_domains

    def _extract_text(self, msg: EmailMessage) -> str:
        parts: list[str] = []
        for part in msg.walk():
            ct = part.get_content_type()
            cd = part.get_content_disposition() or ""

            if cd == "attachment":
                fname = part.get_filename() or "attachment"
                try:
                    data = part.get_payload(decode=True) or b""
                    extracted = self._fi_extract(data, fname)
                    if extracted:
                        parts.append(f"[첨부: {fname}]\n{extracted[:16_384]}")
                except Exception as exc:
                    logger.debug("첨부파일 추출 실패(%s): %s", fname, exc)
            elif ct in {"text/plain", "text/html"}:
                try:
                    payload = part.get_payload(decode=True) or b""
                    charset = part.get_content_charset() or "utf-8"
                    parts.append(payload.decode(charset, errors="replace")[:32_768])
                except Exception:
                    pass

        return "\n\n".join(parts)

    async def _relay(self, envelope) -> None:
        """검사를 통과한 메일을 실제 SMTP 서버로 전달한다."""
        import aiosmtplib

        relay_kwargs: dict[str, Any] = {
            "hostname": self._relay_host,
            "port": self._relay_port,
        }
        if self._relay_tls:
            relay_kwargs["use_tls"] = True
        if self._relay_user and self._relay_pass:
            relay_kwargs["username"] = self._relay_user
            relay_kwargs["password"] = self._relay_pass

        smtp = aiosmtplib.SMTP(**relay_kwargs)
        await smtp.connect()
        await smtp.sendmail(envelope.mail_from, envelope.rcpt_tos, envelope.content)
        await smtp.quit()
        logger.debug("SMTP 릴레이 완료 → %s:%d", self._relay_host, self._relay_port)


class SmtpProxy:
    """로컬 SMTP 프록시 서버 — 별도 스레드에서 asyncio 루프를 실행한다."""

    def __init__(
        self,
        listen_port: int,
        relay_host: str,
        relay_port: int,
        relay_use_tls: bool,
        relay_username: Optional[str],
        relay_password: Optional[str],
        internal_domains: list[str],
        inspect: Callable[[str], list[dict[str, Any]]],
        on_blocked: Callable[[str, list[dict[str, Any]], str], str],
        fi_extract: Callable[[bytes, str], Optional[str]],
    ) -> None:
        self._listen_port = listen_port
        self._internal_domains = frozenset(d.lower() for d in internal_domains)
        self._handler = _DLPHandler(
            internal_domains=self._internal_domains,
            relay_host=relay_host,
            relay_port=relay_port,
            relay_use_tls=relay_use_tls,
            relay_username=relay_username,
            relay_password=relay_password,
            inspect=inspect,
            on_blocked=on_blocked,
            fi_extract=fi_extract,
        )
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="SmtpProxy"
        )
        self._thread.start()
        logger.info("SmtpProxy 스레드 시작 (port=%d)", self._listen_port)

    def stop(self) -> None:
        self._running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info("SmtpProxy 종료")

    def _run(self) -> None:
        try:
            from aiosmtpd.controller import Controller
        except ImportError:
            logger.error("aiosmtpd 미설치 — pip install aiosmtpd aiosmtplib")
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        controller = Controller(
            self._handler,
            hostname="127.0.0.1",
            port=self._listen_port,
            loop=self._loop,
        )
        try:
            controller.start()
            logger.info("SMTP 프록시 리스닝 127.0.0.1:%d", self._listen_port)
            self._loop.run_forever()
        finally:
            controller.stop()
            self._loop.close()
