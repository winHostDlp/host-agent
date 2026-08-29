"""HTTP 업로드 모니터 — 설계 및 스켈레톤.

현재 상태: 스켈레톤 (WinDivert 드라이버 설치 필요)

동작 원리
---------
WinDivert 드라이버를 통해 TCP 레이어에서 아웃바운드 패킷을 가로채고,
HTTP POST 요청(multipart/form-data)의 파일 업로드 데이터를 재조합하여 검사한다.

커버 범위
---------
HTTP  (80, 8080)  → 패킷 내용 직접 파싱 가능
HTTPS (443)       → TLS 암호화로 내용 불가 → 별도 설계 필요 (프록시 방식)

HTTPS 처리 방안 (미구현)
------------------------
방안 A — mitmproxy 투명 프록시
  Windows 시스템 프록시를 로컬 mitmproxy(8080)로 설정 + 루트 인증서 설치
  → 모든 HTTPS 트래픽 검사 가능
  단점: 인증서 배포·관리 필요, 일부 앱이 certificate pinning 사용

방안 B — 프로세스별 API 훅 (WinHTTP/WinInet)
  C/C++ DLL 인젝션으로 WinHttpSendRequest, InternetWriteFile 등을 훅
  → 암호화 전 평문 데이터 접근 가능
  단점: C/C++ DLL 필요, AV/EDR 경고 가능성

방안 C — eBPF / NDR 어플라이언스
  엔터프라이즈 환경에서는 네트워크 경계 장비(DLP 게이트웨이)가 TLS 검사

사전 요구사항
-------------
  pip install pydivert
  WinDivert 드라이버 설치: https://reqrypt.org/windivert.html
  관리자 권한 필요
"""

import logging
import threading
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class HttpMonitor:
    """WinDivert 기반 HTTP 업로드 모니터 (스켈레톤)."""

    def __init__(
        self,
        inspect_ports: list[int],
        inspect: Callable[[str], list[dict[str, Any]]],
        on_blocked: Callable[[str, list[dict[str, Any]], str], str],
        fi_extract: Callable[[bytes, str], Optional[str]],
    ) -> None:
        self._ports = inspect_ports
        self._inspect = inspect
        self._on_blocked = on_blocked
        self._fi_extract = fi_extract

        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="HttpMonitor"
        )
        self._thread.start()
        logger.info("HttpMonitor 스레드 시작 (ports=%s)", self._ports)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("HttpMonitor 종료")

    def _run(self) -> None:
        try:
            import pydivert
        except ImportError:
            logger.error(
                "pydivert 미설치 또는 WinDivert 드라이버 없음 — HttpMonitor 비활성화\n"
                "설치: pip install pydivert  +  WinDivert 드라이버(관리자 권한)"
            )
            return

        port_filter = " or ".join(f"tcp.DstPort == {p}" for p in self._ports)
        flt = f"outbound and ({port_filter})"

        try:
            with pydivert.WinDivert(flt) as wd:
                logger.info("WinDivert 필터 활성화: %s", flt)
                while self._running:
                    packet = wd.recv(timeout=1.0)
                    if packet is None:
                        continue
                    try:
                        self._handle_packet(packet, wd)
                    except Exception:
                        logger.exception("패킷 처리 예외 — 통과 처리")
                        wd.send(packet)
        except Exception as exc:
            logger.error("WinDivert 시작 실패: %s", exc)

    def _handle_packet(self, packet: Any, wd: Any) -> None:
        """HTTP POST multipart 패킷을 검사하고 통과/차단을 결정한다."""
        payload: bytes = packet.payload or b""

        # HTTP POST + multipart 여부 간이 확인
        if b"POST " not in payload[:16] and b"Content-Disposition:" not in payload:
            wd.send(packet)
            return

        # multipart 파트 추출 (간이 파서)
        text = self._parse_multipart_text(payload)
        if not text:
            wd.send(packet)
            return

        hits = self._inspect(text)
        if not hits:
            wd.send(packet)
            return

        dst = f"{packet.dst_addr}:{packet.dst_port}"
        analysis_text = f"HTTP POST → {dst}\n\n{text}"
        decision = self._on_blocked(analysis_text, hits, "http_upload") or "block"
        if decision != "block":
            wd.send(packet)
            logger.warning("HTTP 업로드 %s 경고 기록 — 패킷 통과 → %s", decision, dst)
            return

        # block 판정: 패킷을 drop (send 안 함)
        logger.warning("HTTP 업로드 차단 → %s  hits=%s", dst, [h.get("id") for h in hits])
        # 패킷을 재전송하지 않으면 연결이 끊어짐(차단 효과)

    def _parse_multipart_text(self, payload: bytes) -> Optional[str]:
        """multipart 바디에서 텍스트 파트와 파일 파트를 추출한다 (간이 파서)."""
        try:
            # Content-Type 헤더에서 boundary 파싱
            header_end = payload.find(b"\r\n\r\n")
            if header_end < 0:
                return None
            header_raw = payload[:header_end].decode("utf-8", errors="ignore")
            body = payload[header_end + 4:]

            boundary: Optional[str] = None
            for line in header_raw.splitlines():
                if "boundary=" in line.lower():
                    boundary = line.split("boundary=", 1)[1].strip().strip('"')
                    break
            if not boundary:
                return None

            parts: list[str] = []
            sep = f"--{boundary}".encode()
            for part in body.split(sep):
                if not part or part.startswith(b"--"):
                    continue
                p_header_end = part.find(b"\r\n\r\n")
                if p_header_end < 0:
                    continue
                p_header = part[:p_header_end].decode("utf-8", errors="ignore")
                p_body = part[p_header_end + 4:]

                filename: Optional[str] = None
                for h_line in p_header.splitlines():
                    if "filename=" in h_line.lower():
                        filename = h_line.split("filename=", 1)[1].strip().strip('"')
                        break

                if filename:
                    extracted = self._fi_extract(p_body, filename)
                    if extracted:
                        parts.append(f"[파일: {filename}]\n{extracted}")
                else:
                    decoded = p_body.decode("utf-8", errors="ignore")
                    if decoded.strip():
                        parts.append(decoded)

            return "\n\n".join(parts) if parts else None
        except Exception as exc:
            logger.debug("multipart 파싱 실패: %s", exc)
            return None
