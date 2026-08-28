"""Windows notifications for blocked paste events.

The notification is shown in a daemon thread so that it never stalls the
WH_KEYBOARD_LL hook callback (Windows will forcibly remove hooks that
block for too long).
"""

import ctypes
import logging
import threading
from typing import Any

from core_comm.review_notifier import notify_review as _notify_review

logger = logging.getLogger(__name__)

_MB_OK           = 0x00000000
_MB_ICONWARNING  = 0x00000030
_MB_TOPMOST      = 0x00040000
_MB_SETFOREGROUND = 0x00010000
_MB_SYSTEMMODAL = 0x00001000
_HWND_TOPMOST = -1
_SWP_NOMOVE = 0x0002
_SWP_NOSIZE = 0x0001
_SWP_SHOWWINDOW = 0x0040


def _show_messagebox(title: str, body: str) -> None:
    ctypes.windll.user32.MessageBoxW(
        None,
        body,
        title,
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


def _show_topmost_popup(title: str, body: str) -> None:
    """Show a small always-on-top dialog.

    MessageBoxW can still appear behind another app because of Windows focus
    stealing prevention. A real topmost owner window is more reliable.
    """
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception:
        _show_messagebox(title, body)
        return

    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)
    root.attributes("-topmost", True)

    frame = ttk.Frame(root, padding=18)
    frame.grid(row=0, column=0, sticky="nsew")

    title_label = ttk.Label(frame, text="붙여넣기가 차단되었습니다", font=("", 11, "bold"))
    title_label.grid(row=0, column=0, sticky="w")

    body_label = ttk.Label(frame, text=body, justify="left", wraplength=420)
    body_label.grid(row=1, column=0, sticky="w", pady=(12, 16))

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

    # Re-assert topmost after the target app processes Ctrl+V.
    root.after(150, lambda: (_force_topmost(root.winfo_id()), root.lift(), root.focus_force()))
    root.mainloop()


def notify_blocked(process_name: str, hits: list[dict[str, Any]]) -> None:
    """Fire-and-forget: show a warning dialog listing what was detected."""
    hit_names = ", ".join(h.get("name", "알 수 없음") for h in hits[:3])
    if len(hits) > 3:
        hit_names += f" 외 {len(hits) - 3}건"

    title = "Sentry DLP — 붙여넣기 차단"
    body = (
        f"민감한 정보가 감지되어 붙여넣기가 차단되었습니다.\n\n"
        f"대상 프로그램 : {process_name}\n"
        f"탐지 항목     : {hit_names}\n\n"
        f"해당 내용을 외부로 전달해야 한다면 보안 담당자에게 문의하십시오."
    )

    threading.Thread(
        target=_show_topmost_popup,
        args=(title, body),
        daemon=True,
        name="DLPNotifier",
    ).start()

    logger.warning(
        "Paste BLOCKED → process='%s' hits=[%s]",
        process_name,
        ", ".join(h.get("id", "?") for h in hits),
    )


def notify_review(process_name: str, hits: list[dict[str, Any]]) -> None:
    """Fire-and-forget: warn that a suspicious paste was allowed and recorded."""
    _notify_review("clipboard", process_name, hits)
