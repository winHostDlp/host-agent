"""Sentry Host Agent — entry point. Runs as a background process.

활성 채널 (settings.yaml + channel_policy.json 으로 on/off)
  clipboard   : Ctrl+V 붙여넣기 목적지 검사
  outlook     : Outlook COM ItemSend 이벤트 훅
  smtp        : 로컬 SMTP 프록시 (127.0.0.1:2525)
  http        : WinDivert HTTP 업로드 모니터 (관리자 권한 필요)

파이프라인
  정규식(1차 게이트) → PayloadBuilder(정제) → ApiClient(AI 판단)
    → block  : 차단 + 팝업 + 로컬 JSONL 기록
    → review : 사용자 경고 + 허용 + 로컬 JSONL/대시보드 기록
    → allow  : 허용 + 로컬 JSONL/대시보드 기록

AI 서버 설정 (settings.yaml)
  ai_base_url: ""        → mock 모드 (severity 기반 즉시 판단)
  ai_base_url: "http://…" → 실제 AI 서버 호출
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Optional

import yaml

from clipboard_ctrl.clipboard_hook import ClipboardHook
from clipboard_ctrl.notifier import notify_blocked, notify_review as notify_clipboard_review
from clipboard_ctrl.paste_inspector import PasteInspector
from clipboard_ctrl.rule_filter import RuleFilter
from core_comm.analysis_events import make_network_decision_handler
from core_comm.api_client import ApiClient
from core_comm.clipboard_analysis import run_clipboard_analysis
from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore
from core_comm.payload_builder import PayloadBuilder
from core_comm.review_notifier import notify_review as notify_channel_review
from network_hook.file_inspector import FileInspector
from network_hook.proxy_cert import ProxyCert

PROJECT_ROOT = Path(__file__).resolve().parent


# ── 설정 로더 ──────────────────────────────────────────────────────────────────

def load_settings() -> dict[str, Any]:
    path = PROJECT_ROOT / "config" / "settings.yaml"
    with path.open(encoding="utf-8") as f:
        settings = yaml.safe_load(f)
    if not isinstance(settings, dict):
        raise ValueError("config/settings.yaml은 mapping이어야 합니다.")

    local_path = PROJECT_ROOT / "config" / "settings.local.yaml"
    if local_path.exists():
        with local_path.open(encoding="utf-8") as f:
            local_settings = yaml.safe_load(f)
        if not isinstance(local_settings, dict):
            raise ValueError("config/settings.local.yaml은 mapping이어야 합니다.")
        settings = _merge_settings(settings, local_settings)
    return settings


def _merge_settings(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge an ignored local settings file without mutating tracked defaults."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_settings(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_channel_policy() -> dict[str, Any]:
    path = PROJECT_ROOT / "config" / "channel_policy.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


# ── 공통 빌더 ──────────────────────────────────────────────────────────────────

def build_api_client(settings: dict[str, Any]) -> ApiClient:
    server_cfg = settings.get("server", {})
    return ApiClient(
        base_url=server_cfg.get("ai_base_url", ""),
        timeout=server_cfg.get("request_timeout_sec", 10),
        token=os.environ.get("AI_API_TOKEN") or server_cfg.get("ai_token", ""),
    )


def build_payload_builder(settings: dict[str, Any]) -> PayloadBuilder:
    agent_cfg = settings.get("agent", {})
    user_id   = agent_cfg.get("user_id") or os.environ.get("USERNAME", "")
    return PayloadBuilder(
        max_text_chars=agent_cfg.get("ai_max_text_chars", 4000),
        max_per_pattern=agent_cfg.get("ai_max_matches_per_pattern", 10),
        context_chars=agent_cfg.get("ai_context_chars", 200),
        user_id=user_id,
    )


def build_event_logger(settings: dict[str, Any]) -> EventLogger:
    log_cfg    = settings.get("logging", {})
    server_cfg = settings.get("server", {})
    agent_cfg  = settings.get("agent", {})

    store = LocalEventStore(
        log_dir=PROJECT_ROOT / log_cfg.get("log_dir", "logs"),
        max_bytes=log_cfg.get("max_bytes", 10 * 1024 * 1024),
        text_preview_len=log_cfg.get("text_preview_len", 120),
    )
    send_now = bool(log_cfg.get("send_immediately", False))
    dashboard_url = server_cfg.get("dashboard_url") if send_now else None

    user_id = agent_cfg.get("user_id") or os.environ.get("USERNAME", "")

    return EventLogger(
        store=store,
        dashboard_url=dashboard_url,
        dashboard_token=(
            os.environ.get("AGENT_API_TOKEN")
            or server_cfg.get("dashboard_token", "")
        ),
        timeout=server_cfg.get("request_timeout_sec", 10),
        send_immediately=send_now,
        agent_id=agent_cfg.get("agent_id", ""),
        user_id=user_id,
        department=agent_cfg.get("department", "Unknown"),
    )


def make_block_handler(
    channel: str,
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
) -> Any:
    """모든 채널이 공유하는 '탐지 → AI 판단 → 차단/허용 + 로그' 콜백 팩토리.

    Returns
    -------
    on_detected(summary_or_text, hits, process_name) → "block" | "review" | "allow"
        네트워크 채널(Outlook, SMTP, HTTP)에서 사용.
    """
    # rule_filter는 채널 훅에서 이미 hits를 생성하는 구조라 콜백 내에서는
    # 사용하지 않지만, 기존 빌더 API 호환성을 위해 인자를 유지한다.
    _ = rule_filter
    return make_network_decision_handler(
        channel=channel,
        event_logger=event_logger,
        api_client=api_client,
        payload_builder=payload_builder,
        notify_blocked=notify_blocked,
        notify_review=notify_channel_review,
        logger=logging.getLogger(__name__),
    )


# ── 채널별 빌더 ────────────────────────────────────────────────────────────────

def build_clipboard_hook(
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    fi: FileInspector,
) -> ClipboardHook:
    policy_path = PROJECT_ROOT / "config" / "paste_policy.json"
    inspector   = PasteInspector(policy_path)
    logger      = logging.getLogger(__name__)

    # hook_ref: ClipboardHook 객체를 생성 후 바인딩 (순환 참조 없이 콜백에 전달)
    hook_ref: list[Any] = [None]

    def on_text_pasted(
        text: str,
        process_name: str,
        clipboard_sequence: int,
    ) -> bool:
        """True 반환 시 붙여넣기 차단.

        정규식 히트 즉시 차단 → AI 비동기 분석 →
          block  : 팝업 + 로그 (차단 유지)
          review : 기존 클립보드로 Ctrl+V 재발행 후 경고
          allow  : 기존 클립보드로 Ctrl+V 재발행 (오탐/Fail-Open 복구)
        """
        hits = rule_filter.match(text)
        if not hits:
            return False

        destination_hwnd = hook_ref[0].get_intercepted_destination(
            clipboard_sequence,
            process_name,
        )

        def _ai_then_notify() -> None:
            hook = hook_ref[0]
            if hook is None:
                logger.error("[clipboard] 훅 참조 없음 — 붙여넣기 복구 불가")
                return

            run_clipboard_analysis(
                text=text,
                process_name=process_name,
                hits=hits,
                payload_builder=payload_builder,
                api_client=api_client,
                event_logger=event_logger,
                release_paste=lambda: hook.release_paste(
                    clipboard_sequence,
                    destination_hwnd,
                    process_name,
                ),
                notify_blocked=notify_blocked,
                notify_review=notify_clipboard_review,
                logger=logger,
            )

        threading.Thread(target=_ai_then_notify, daemon=True, name="ClipboardAI").start()
        return True  # 정규식 히트 즉시 차단

    hook = ClipboardHook(
        should_inspect=inspector.should_inspect,
        on_text_pasted=on_text_pasted,
        file_inspector=fi,
    )
    hook_ref[0] = hook
    return hook


def build_outlook_hook(
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    policy: dict[str, Any],
    fi: FileInspector,
) -> Any:
    from network_hook.outlook_hook import OutlookHook

    on_blocked = make_block_handler("outlook", rule_filter, event_logger, api_client, payload_builder)
    return OutlookHook(
        internal_domains=policy.get("internal_domains", []),
        inspect=rule_filter.match,
        on_blocked=on_blocked,
        file_inspector_extract=fi.extract_from_bytes,
    )


def build_smtp_proxy(
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    policy: dict[str, Any],
    fi: FileInspector,
) -> Any:
    from network_hook.smtp_proxy import SmtpProxy

    smtp_cfg = policy.get("smtp", {})
    relay    = smtp_cfg.get("relay", {})
    on_blocked = make_block_handler("smtp", rule_filter, event_logger, api_client, payload_builder)

    return SmtpProxy(
        listen_port=smtp_cfg.get("proxy_port", 2525),
        relay_host=relay.get("host", "localhost"),
        relay_port=relay.get("port", 587),
        relay_use_tls=relay.get("use_tls", True),
        relay_username=relay.get("username") or None,
        relay_password=relay.get("password") or None,
        internal_domains=policy.get("internal_domains", []),
        inspect=rule_filter.match,
        on_blocked=on_blocked,
        fi_extract=fi.extract_from_bytes,
    )


def build_http_monitor(
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    policy: dict[str, Any],
    fi: FileInspector,
) -> Any:
    from network_hook.http_monitor import HttpMonitor

    http_cfg   = policy.get("http", {})
    on_blocked = make_block_handler("http", rule_filter, event_logger, api_client, payload_builder)

    return HttpMonitor(
        inspect_ports=http_cfg.get("inspect_ports", [80, 8080]),
        inspect=rule_filter.match,
        on_blocked=on_blocked,
        fi_extract=fi.extract_from_bytes,
    )


def build_file_guard(
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    fi: FileInspector,
    policy: dict[str, Any],
) -> Any:
    from usb_minifilter.usb_guard_usermode import UsbGuardUserMode
    from clipboard_ctrl.notifier import notify_blocked as _notify

    cfg = policy.get("file_guard", {})
    max_mb = cfg.get("max_file_size_mb", 50)

    def on_blocked(file_path: str, hits: list) -> None:
        filename = file_path.split("\\")[-1]
        _notify(f"USB 복사 차단: {filename}", hits)

    return UsbGuardUserMode(
        rule_filter=rule_filter,
        payload_builder=payload_builder,
        api_client=api_client,
        event_logger=event_logger,
        file_inspector=fi,
        on_blocked=on_blocked,
        max_file_size=max_mb * 1024 * 1024,
    )


def build_web_proxy(
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    fi: FileInspector,
    policy: dict[str, Any],
) -> Any:
    """HTTPS MITM 웹 메일 DLP 채널 빌더."""
    from network_hook.web_proxy import WebProxy
    from clipboard_ctrl.notifier import notify_blocked as _notify

    wp_cfg = policy.get("web_proxy", {})

    def on_blocked(url: str, hits: list, process_name: str) -> None:
        _notify(process_name, hits)

    return WebProxy(
        port=wp_cfg.get("proxy_port", 8082),
        inspect_domains=wp_cfg.get("inspect_domains", []),
        rule_filter=rule_filter,
        payload_builder=payload_builder,
        api_client=api_client,
        event_logger=event_logger,
        file_inspector=fi,
        on_blocked=on_blocked,
        log_traffic=bool(wp_cfg.get("log_traffic", True)),
        skip_path_patterns=wp_cfg.get("skip_path_patterns", []),
        min_body_bytes=int(wp_cfg.get("min_body_bytes", 0)),
        drive_domains=wp_cfg.get("drive_domains", []),
        drive_upload_patterns=wp_cfg.get("drive_upload_patterns", []),
    )


# ── 채널 분류 ──────────────────────────────────────────────────────────────────
#
# SESSION_0_CHANNELS : Windows 서비스(Session 0)에서 실행 가능
#   smtp, http
#
# USER_SESSION_CHANNELS : 로그온 사용자 세션에서만 동작
#   clipboard (WH_KEYBOARD_LL + 메시지 펌프)
#   outlook   (COM 객체 — 사용자 Outlook 인스턴스 접근 필요)
#   file_guard (USB 감시 + 사용자 알림)
#   web_proxy (현재 사용자의 시스템 프록시)
#
# mode="all"    : 개발·테스트용. 모든 채널 시작 (단일 프로세스)
# mode="system" : sentry_service.py 가 호출. Session 0 채널만 시작
# mode="user"   : sentry_user_agent.py 가 호출. 유저 세션 채널만 시작


def _start_channels(
    mode: str,
    settings: dict[str, Any],
    channel_policy: dict[str, Any],
    rule_filter: RuleFilter,
    event_logger: EventLogger,
    api_client: ApiClient,
    payload_builder: PayloadBuilder,
    fi: FileInspector,
    active: list[Any],
) -> None:
    """mode에 따라 해당 채널을 시작하고 active 목록에 추가한다."""
    logger = logging.getLogger(__name__)
    run_user   = mode in ("all", "user")
    run_system = mode in ("all", "system")

    # ── 유저 세션 전용 채널 ────────────────────────────────────────────────────

    if run_user:
        # 1. 클립보드
        try:
            clipboard = build_clipboard_hook(rule_filter, event_logger, api_client, payload_builder, fi)
            clipboard.start()
            active.append(clipboard)
            logger.info("[채널] clipboard  ON")
        except Exception as exc:
            logger.warning("[채널] clipboard  SKIP (%s)", exc)

        # 2. Outlook
        if channel_policy.get("outlook", {}).get("enabled", False):
            try:
                outlook = build_outlook_hook(
                    rule_filter, event_logger, api_client, payload_builder, channel_policy, fi
                )
                outlook.start()
                active.append(outlook)
                logger.info("[채널] outlook    ON")
            except Exception as exc:
                logger.warning("[채널] outlook    SKIP (%s)", exc)
        else:
            logger.info("[채널] outlook    OFF  (channel_policy.json)")

    # ── Session 0 호환 채널 ────────────────────────────────────────────────────

    if run_system:
        # 3. SMTP 프록시

        if channel_policy.get("smtp", {}).get("enabled", False):
            try:
                smtp = build_smtp_proxy(
                    rule_filter, event_logger, api_client, payload_builder, channel_policy, fi
                )
                smtp.start()
                active.append(smtp)
                logger.info(
                    "[채널] smtp       ON  (port=%d)",
                    channel_policy["smtp"].get("proxy_port", 2525),
                )
            except Exception as exc:
                logger.warning("[채널] smtp       SKIP (%s)", exc)
        else:
            logger.info("[채널] smtp       OFF  (channel_policy.json)")

        # 4. HTTP 모니터
        if channel_policy.get("http", {}).get("enabled", False):
            try:
                http = build_http_monitor(
                    rule_filter, event_logger, api_client, payload_builder, channel_policy, fi
                )
                http.start()
                active.append(http)
                logger.info("[채널] http       ON")
            except Exception as exc:
                logger.warning("[채널] http       SKIP (%s)", exc)
        else:
            logger.info("[채널] http       OFF  (channel_policy.json)")

    # ── 유저 세션 + 프록시 채널 (시스템 프록시 설정은 현재 사용자 기준) ────────

    if run_user:
        # 5. FileGuard (USB 이동식 드라이브) — 유저모드, 알림 팝업 필요
        if channel_policy.get("file_guard", {}).get("enabled", False):
            try:
                fg = build_file_guard(
                    rule_filter, event_logger, api_client, payload_builder, fi, channel_policy
                )
                fg.start()
                active.append(fg)
                logger.info("[채널] file_guard ON  (USB 이동식 드라이브 감시)")
            except Exception as exc:
                logger.warning("[채널] file_guard SKIP (%s)", exc)
        else:
            logger.info("[채널] file_guard OFF  (channel_policy.json)")

        # 6. HTTPS MITM 웹 메일 프록시
        wp_cfg = channel_policy.get("web_proxy", {})
        if wp_cfg.get("enabled", False):
            try:
                # CA 인증서 자동 확인
                if wp_cfg.get("auto_check_cert", True):
                    pc = ProxyCert()
                    if not pc.is_installed():
                        logger.warning(
                            "[채널] web_proxy — CA 인증서가 설치되지 않았습니다.\n"
                            "  install\\setup_proxy.ps1 을 관리자 권한으로 실행하세요."
                        )
                wp = build_web_proxy(
                    rule_filter, event_logger, api_client, payload_builder, fi, channel_policy
                )
                wp.start()
                active.append(wp)
            except Exception as exc:
                logger.warning(
                    "[채널] web_proxy  SKIP (%s)\n"
                    "  → pip install mitmproxy  후 재시작하세요",
                    exc,
                )
        else:
            logger.info("[채널] web_proxy  OFF  (channel_policy.json)")


# ── 메인 ───────────────────────────────────────────────────────────────────────

def run(mode: str = "all", stop_event: Optional["threading.Event"] = None) -> None:
    """에이전트를 시작하고 stop_event가 set될 때까지 (또는 Ctrl+C) 실행한다.

    Parameters
    ----------
    mode:
        "all"    — 모든 채널 (직접 실행·개발용)
        "system" — Session 0 채널만 (Windows 서비스용)
        "user"   — 유저 세션 채널만 (Task Scheduler 로그온 트리거용)
    stop_event:
        서비스 관리자가 STOP을 보낼 때 set하는 이벤트. None이면 SIGINT/Ctrl+C만 처리.
    """
    import threading as _threading

    settings = load_settings()
    setup_logging(settings.get("agent", {}).get("log_level", "INFO"))
    logger = logging.getLogger(__name__)
    logger.info("Sentry Host Agent 시작 — mode=%s", mode)

    channel_policy  = load_channel_policy()
    patterns_path   = PROJECT_ROOT / settings.get("agent", {}).get(
        "regex_patterns", "config/regex_patterns.json"
    )
    rule_filter     = RuleFilter(patterns_path)
    event_logger    = build_event_logger(settings)
    api_client      = build_api_client(settings)
    payload_builder = build_payload_builder(settings)
    fi              = FileInspector()

    logger.info(
        "AI 모드: %s",
        "mock (severity 기반)" if api_client.is_mock else api_client._base_url,
    )

    active: list[Any] = []
    _start_channels(
        mode, settings, channel_policy,
        rule_filter, event_logger, api_client, payload_builder, fi,
        active,
    )

    logger.info("Sentry Host Agent running. Press Ctrl+C to stop.")

    def _shutdown() -> None:
        logger.info("종료 중...")
        for ch in reversed(active):
            try:
                ch.stop()
            except Exception:
                pass
        logger.info("Agent stopped.")

    def _sig_handler(signum: int = 0, frame: Any = None) -> None:
        _shutdown()
        sys.exit(0)

    # Windows 서비스는 run()을 작업 스레드에서 호출한다. signal 등록은
    # Python 메인 스레드에서만 허용되며, 서비스 종료는 stop_event가 담당한다.
    if _threading.current_thread() is _threading.main_thread():
        signal.signal(signal.SIGINT,  _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)
    else:
        logger.debug("메인 스레드가 아니므로 OS signal handler 등록 생략")

    try:
        if stop_event is not None:
            # 서비스 모드: stop_event가 set될 때까지 대기
            while not stop_event.wait(timeout=1):
                pass
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown()


def main() -> None:
    """직접 실행 진입점 — 모든 채널을 단일 프로세스에서 시작."""
    run(mode="all")


if __name__ == "__main__":
    main()
