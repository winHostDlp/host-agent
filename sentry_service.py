"""sentry_service.py — Sentry DLP Windows 서비스 (Session 0 채널)

담당 채널 (Session 0, 데스크탑 불필요)
  - SMTP 프록시     : 로컬 SMTP 트래픽 감시
  - HTTP 모니터     : WinDivert HTTP 업로드 감시

사용자 세션 채널 (클립보드, Outlook, FileGuard, WebProxy, 알림)은
sentry_user_agent.py (Task Scheduler 로그온 트리거)가 담당.

────────────────────────────────────────────────────────────
설치 / 제거 (관리자 PowerShell 또는 install/setup_agent.ps1)
  설치:   python sentry_service.py install
  제거:   python sentry_service.py remove
  시작:   python sentry_service.py start
          sc start SentryDLPService
  중지:   python sentry_service.py stop

또는 한 번에:
  python sentry_service.py --startup=auto install start
────────────────────────────────────────────────────────────
"""

import logging
import sys
import threading
from pathlib import Path

# pywin32 임포트
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    _PYWIN32_AVAILABLE = True
except ImportError:
    _PYWIN32_AVAILABLE = False
    # 서비스 기능 없이도 파일을 import할 수 있도록 stub 제공
    class win32serviceutil:  # type: ignore
        class ServiceFramework:
            pass
        @staticmethod
        def HandleCommandLine(cls): pass

PROJECT_ROOT = Path(__file__).resolve().parent

# 서비스가 로그를 파일에 기록할 수 있도록 기본 설정
_LOG_FILE = PROJECT_ROOT / "logs" / "service.log"


def _configure_file_logging() -> None:
    """서비스 환경(Session 0, 콘솔 없음)용 파일 로그 설정."""
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(_LOG_FILE, encoding="utf-8"),
        ],
    )


class SentryDLPService(win32serviceutil.ServiceFramework):
    """Sentry DLP 시스템 서비스 — Session 0 채널(SMTP, HTTP)을 관리."""

    _svc_name_        = "SentryDLPService"
    _svc_display_name_= "Sentry DLP Service"
    _svc_description_ = (
        "Data Loss Prevention — SMTP/HTTP 모니터링. "
        "사용자 세션 채널(클립보드, Outlook, FileGuard, WebProxy)은 "
        "sentry_user_agent가 담당합니다."
    )
    # 자동 시작 + 크래시 시 재시작 (setup_agent.ps1에서 SC failure 설정)
    _svc_start_type_  = win32service.SERVICE_AUTO_START

    def __init__(self, args: list) -> None:
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._py_stop    = threading.Event()
        self._thread: threading.Thread | None = None

    # ── SCM 콜백 ────────────────────────────────────────────────────────────

    def SvcStop(self) -> None:
        """서비스 관리자(SCM)에서 STOP 명령을 받았을 때 호출."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        self._py_stop.set()

    def SvcDoRun(self) -> None:
        """서비스 시작 시 진입점. 에이전트를 별도 스레드에서 실행."""
        _configure_file_logging()
        logger = logging.getLogger(__name__)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        logger.info("SentryDLPService 시작 (mode=system)")

        # main_agent.run()을 데몬 스레드에서 실행
        self._thread = threading.Thread(
            target=self._run_agent,
            name="SentryAgentThread",
            daemon=True,
        )
        self._thread.start()

        # SCM STOP 신호 대기
        win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
        logger.info("SentryDLPService 종료 신호 수신")

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )

    # ── 내부 ────────────────────────────────────────────────────────────────

    def _run_agent(self) -> None:
        """별도 스레드에서 에이전트의 Session 0 채널을 실행."""
        logger = logging.getLogger(__name__)
        try:
            # PROJECT_ROOT를 sys.path에 추가 (서비스 환경의 CWD가 다를 수 있음)
            if str(PROJECT_ROOT) not in sys.path:
                sys.path.insert(0, str(PROJECT_ROOT))

            from main_agent import run as agent_run
            agent_run(mode="system", stop_event=self._py_stop)
        except Exception:
            logger.exception("에이전트 스레드에서 예외 발생")
        finally:
            # 에이전트가 예외로 종료된 경우 서비스도 중지
            self._py_stop.set()
            win32event.SetEvent(self._stop_event)


# ── CLI 진입점 ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not _PYWIN32_AVAILABLE:
        print("오류: pywin32가 설치되지 않았습니다.")
        print("  pip install pywin32")
        sys.exit(1)

    if len(sys.argv) == 1:
        # 인수 없이 실행 → 서비스 디스패처 모드 (SCM이 직접 호출)
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SentryDLPService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # python sentry_service.py install / start / stop / remove ...
        win32serviceutil.HandleCommandLine(SentryDLPService)
