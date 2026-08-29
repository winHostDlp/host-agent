"""sentry_user_agent.py — Sentry DLP 유저 세션 에이전트

담당 채널 (로그온한 사용자 세션에서 실행, 데스크탑 접근 필요)
  - 클립보드 훅    : WH_KEYBOARD_LL + 붙여넣기 목적지 검사
  - Outlook 훅     : COM ItemSend 이벤트 (사용자의 Outlook 인스턴스)
  - FileGuard      : USB 이동식 드라이브 파일 감시·사용자 알림
  - WebProxy       : 현재 사용자의 HTTPS 시스템 프록시 트래픽 검사
  - 알림 팝업      : 차단 시 화면 중앙 팝업 (Tkinter)

SMTP·HTTP LocalSystem 서비스는 이번 발표 설치 범위에서 제외됩니다.

────────────────────────────────────────────────────────────
실행 방법

  수동 (테스트):
    python sentry_user_agent.py

  Task Scheduler (자동):
    setup_agent.ps1이 다음 조건의 작업을 등록합니다.
      트리거 : 사용자 로그온 시
      권한   : 현재 사용자 제한 권한
      숨김   : 예 (백그라운드 실행)
────────────────────────────────────────────────────────────
"""

import logging
import signal
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

_LOG_FILE = PROJECT_ROOT / "logs" / "user_agent.log"


def _configure_logging(log_level: str = "INFO") -> None:
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [
        logging.FileHandler(_LOG_FILE, encoding="utf-8"),
    ]
    # 콘솔에서 직접 실행 시 stdout도 출력
    try:
        if sys.stdout and sys.stdout.fileno() >= 0:
            handlers.append(logging.StreamHandler(sys.stdout))
    except Exception:
        pass

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


def main() -> None:
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))

    # 설정 로드 (로그 레벨 확인 목적)
    try:
        import yaml
        cfg_path = PROJECT_ROOT / "config" / "settings.yaml"
        with cfg_path.open(encoding="utf-8") as f:
            settings = yaml.safe_load(f)
        log_level = settings.get("agent", {}).get("log_level", "INFO")
    except Exception:
        log_level = "INFO"

    _configure_logging(log_level)
    logger = logging.getLogger(__name__)
    logger.info("Sentry User Agent 시작 (mode=user)")

    from main_agent import run as agent_run
    agent_run(mode="user")


if __name__ == "__main__":
    main()
