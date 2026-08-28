"""review 판정 사용자 경고의 문구 생성과 UI 표시를 분리한다."""

from __future__ import annotations

import ctypes
import logging
import threading
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_MB_OK = 0x00000000
_MB_ICONWARNING = 0x00000030
_MB_TOPMOST = 0x00040000
_MB_SETFOREGROUND = 0x00010000
_MB_SYSTEMMODAL = 0x00001000
_HWND_TOPMOST = -1
_SWP_NOMOVE = 0x0002
_SWP_NOSIZE = 0x0001
_SWP_SHOWWINDOW = 0x0040

_CHANNEL_LABELS = {
    "clipboard": "클립보드 붙여넣기",
    "outlook": "Outlook 메일 전송",
    "smtp": "SMTP 메일 전송",
    "http": "HTTP 업로드",
    "web_mail": "웹메일 업로드",
    "drive_upload": "클라우드 드라이브 업로드",
    "file_guard": "USB 파일 복사",
    "usb": "USB 파일 복사",
}


@dataclass(frozen=True)
class ReviewNotice:
    title: str
    heading: str
    body: str


def _hit_names(hits: list[dict[str, Any]]) -> str:
    names = ", ".join(h.get("name") or h.get("id") or "알 수 없음" for h in hits[:3])
    if len(hits) > 3:
        names += f" 외 {len(hits) - 3}건"
    return names or "알 수 없음"


def build_review_notice(
    channel: str,
    target: str,
    hits: list[dict[str, Any]],
) -> ReviewNotice:
    """OS UI와 독립적으로 review 경고 문구를 만든다."""
    hit_names = _hit_names(hits)
    if channel == "clipboard":
        return ReviewNotice(
            title="Sentry DLP — 보안 경고",
            heading="민감정보 의심 항목이 감지되었습니다",
            body=(
                "민감정보가 의심되어 보안 이벤트로 기록했습니다. "
                "붙여넣기는 허용됩니다.\n\n"
                f"대상 프로그램 : {target}\n"
                f"탐지 항목     : {hit_names}\n\n"
                "외부 전달이 필요한 정보인지 다시 확인하십시오."
            ),
        )

    channel_label = _CHANNEL_LABELS.get(channel, channel or "알 수 없는 채널")
    return ReviewNotice(
        title="Sentry DLP — 전송 보안 경고",
        heading="민감정보 의심 작업이 허용되었습니다",
        body=(
            "민감정보가 의심되어 전송은 허용하되 보안 이벤트로 기록했습니다.\n\n"
            f"채널          : {channel_label}\n"
            f"대상          : {target}\n"
            f"탐지 항목     : {hit_names}\n\n"
            "외부 전달이 필요한 정보인지 다시 확인하십시오."
        ),
    )


def _show_messagebox(notice: ReviewNotice) -> None:
    ctypes.windll.user32.MessageBoxW(
        None,
        notice.body,
        notice.title,
        _MB_OK | _MB_ICONWARNING | _MB_TOPMOST | _MB_SETFOREGROUND | _MB_SYSTEMMODAL,
    )


def _force_topmost(hwnd: int) -> None:
    ctypes.windll.user32.SetWindowPos(
        hwnd,
        _HWND_TOPMOST,
        0,
        0,
        0,
        0,
        _SWP_NOMOVE | _SWP_NOSIZE | _SWP_SHOWWINDOW,
    )
    ctypes.windll.user32.SetForegroundWindow(hwnd)


def _show_tk_notice(notice: ReviewNotice) -> None:
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title(notice.title)
    root.resizable(False, False)
    root.attributes("-topmost", True)

    frame = ttk.Frame(root, padding=18)
    frame.grid(row=0, column=0, sticky="nsew")
    ttk.Label(frame, text=notice.heading, font=("", 11, "bold")).grid(
        row=0, column=0, sticky="w"
    )
    ttk.Label(frame, text=notice.body, justify="left", wraplength=460).grid(
        row=1, column=0, sticky="w", pady=(12, 16)
    )
    ok_button = ttk.Button(frame, text="확인", command=root.destroy)
    ok_button.grid(row=2, column=0, sticky="e")

    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() - width) // 2
    y = (root.winfo_screenheight() - height) // 2
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.lift()
    root.focus_force()
    ok_button.focus_set()
    _force_topmost(root.winfo_id())
    root.bell()
    root.after(150, lambda: (_force_topmost(root.winfo_id()), root.lift(), root.focus_force()))
    root.mainloop()


def _show_notice(notice: ReviewNotice) -> None:
    try:
        _show_tk_notice(notice)
    except Exception:
        try:
            _show_messagebox(notice)
        except Exception:
            logger.exception("review 사용자 경고 표시 실패")


def notify_review(channel: str, target: str, hits: list[dict[str, Any]]) -> None:
    """review 경고를 비동기로 표시해 차단/전송 처리 스레드를 멈추지 않는다."""
    try:
        notice = build_review_notice(channel, target, hits)
        thread = threading.Thread(
            target=_show_notice,
            args=(notice,),
            daemon=True,
            name="DLPReviewNotifier",
        )
        thread.start()
    except Exception:
        # UI 스레드 생성·시작 실패는 review(허용) 흐름을 깨지 않는다.
        try:
            logger.exception(
                "DLP review 사용자 경고 스레드 시작 실패 — 전송 허용 유지"
            )
        except Exception:
            pass
        return

    try:
        logger.warning(
            "DLP review WARNED/ALLOWED → channel=%s target='%s' hits=[%s]",
            channel,
            target,
            ", ".join(h.get("id", "?") for h in hits),
        )
    except Exception:
        pass
