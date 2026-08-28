"""Clipboard paste interceptor.

Flow
----
1. A hidden message-only HWND registers as a clipboard format listener
   (AddClipboardFormatListener) to track clipboard sequence numbers.
2. A WH_KEYBOARD_LL global keyboard hook intercepts Ctrl+V *before* it
   reaches the target application.
3. On Ctrl+V the hook queries the foreground window's process name:
   - allowlist process  → pass through immediately (no inspection)
   - inspect-list / unknown process → read clipboard text → regex check
     - no regex hit → pass through
     - regex hit    → suppress keystroke + notify user (paste blocked)
"""

import ctypes
import ctypes.wintypes
import logging
import pathlib
import threading
from typing import Any, Callable, Optional

import win32api
import win32clipboard
import win32con
import win32gui
import win32process

from clipboard_ctrl.text_extractor import TextExtractor
from core_comm.clipboard_analysis import is_same_paste_destination

logger = logging.getLogger(__name__)

# ── Win32 constants ──────────────────────────────────────────────────────────
WM_CLIPBOARDUPDATE = 0x031D
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
VK_V = 0x56
VK_CONTROL = 0x11
# HWND_MESSAGE: message-only window parent (-3 as a signed pointer-sized int)
HWND_MESSAGE: int = ctypes.cast(ctypes.c_void_p(-3), ctypes.c_void_p).value  # type: ignore[assignment]

_user32 = ctypes.WinDLL("user32", use_last_error=True)
LRESULT = ctypes.c_ssize_t

# ── Keyboard hook struct ──────────────────────────────────────────────────────
LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    LRESULT,
    ctypes.c_int,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
)

_user32.SetWindowsHookExW.argtypes = [
    ctypes.c_int,
    LowLevelKeyboardProc,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
]
_user32.SetWindowsHookExW.restype = ctypes.c_void_p
_user32.CallNextHookEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
]
_user32.CallNextHookEx.restype = LRESULT
_user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
_user32.UnhookWindowsHookEx.restype = ctypes.wintypes.BOOL
_user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
_user32.GetAsyncKeyState.restype = ctypes.wintypes.SHORT
_user32.GetForegroundWindow.argtypes = []
_user32.GetForegroundWindow.restype = ctypes.wintypes.HWND
_user32.GetClipboardSequenceNumber.argtypes = []
_user32.GetClipboardSequenceNumber.restype = ctypes.wintypes.DWORD
_user32.PostThreadMessageW.argtypes = [
    ctypes.wintypes.DWORD,
    ctypes.wintypes.UINT,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
]
_user32.PostThreadMessageW.restype = ctypes.wintypes.BOOL
_user32.AddClipboardFormatListener.argtypes = [ctypes.wintypes.HWND]
_user32.AddClipboardFormatListener.restype = ctypes.wintypes.BOOL
_user32.RemoveClipboardFormatListener.argtypes = [ctypes.wintypes.HWND]
_user32.RemoveClipboardFormatListener.restype = ctypes.wintypes.BOOL


class _KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode",      ctypes.wintypes.DWORD),
        ("scanCode",    ctypes.wintypes.DWORD),
        ("flags",       ctypes.wintypes.DWORD),
        ("time",        ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


# ── Main hook class ───────────────────────────────────────────────────────────
class ClipboardHook:
    """Intercepts Ctrl+V in risky apps and blocks the paste when regex hits."""

    def __init__(
        self,
        should_inspect: Callable[[str], bool],
        on_text_pasted: Callable[[str, str, int], bool],
        file_inspector: Optional[Any] = None,
    ) -> None:
        """
        Parameters
        ----------
        should_inspect:
            Receives the foreground process name (lower-case exe, e.g. ``slack.exe``).
            Return True  → inspect clipboard content before allowing paste.
            Return False → allow paste without inspection.
        on_text_pasted:
            Receives (normalized_text, process_name, clipboard_sequence).
            Return True  → block the paste.
            Return False → allow the paste.
        file_inspector:
            FileInspector 인스턴스. 있으면 CF_HDROP(파일 복사) 시 파일 내용을 추출해 검사.
        """
        self._should_inspect = should_inspect
        self._on_text_pasted = on_text_pasted
        self._file_inspector = file_inspector

        self._thread: Optional[threading.Thread] = None
        self._thread_id: Optional[int] = None
        self._hwnd: Optional[int] = None
        self._hook_id: Optional[int] = None
        self._hook_proc_ref: Optional[LowLevelKeyboardProc] = None  # prevent GC

        # AI allow 판정 후 재붙여넣기할 때 훅이 스스로를 무시하는 플래그
        self._skip_next_paste: bool = False
        self._release_lock = threading.Lock()
        self._intercepted_destination: Optional[tuple[int, str, int]] = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the hook in a dedicated daemon thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("ClipboardHook already running")
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ClipboardHook"
        )
        self._thread.start()
        logger.info("ClipboardHook thread started")

    def stop(self) -> None:
        """Signal the hook thread to quit and wait for it."""
        if self._thread_id:
            _user32.PostThreadMessageW(self._thread_id, win32con.WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("ClipboardHook stopped")

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_process_name(self, hwnd: int) -> Optional[str]:
        if not hwnd:
            return None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        try:
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid,
            )
            path: str = win32process.GetModuleFileNameEx(handle, 0)
            win32api.CloseHandle(handle)
            return path.rsplit("\\", 1)[-1].lower()
        except Exception:
            return None

    def get_intercepted_destination(
        self,
        clipboard_sequence: int,
        process_name: str,
    ) -> int:
        """Return the HWND captured for the callback currently being handled."""
        destination = self._intercepted_destination
        if not destination:
            return 0
        hwnd, captured_process, captured_sequence = destination
        if (
            captured_sequence == clipboard_sequence
            and captured_process.casefold() == process_name.casefold()
        ):
            return hwnd
        return 0

    def _extract_file_texts(self) -> Optional[str]:
        """클립보드에 CF_HDROP(파일 목록)이 있으면 각 파일 내용을 추출해 반환."""
        if not self._file_inspector:
            return None
        try:
            win32clipboard.OpenClipboard()
            try:
                if not win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                    return None
                file_paths = win32clipboard.GetClipboardData(win32con.CF_HDROP)
            finally:
                win32clipboard.CloseClipboard()

            parts: list[str] = []
            for fp in file_paths:
                try:
                    text = self._file_inspector.extract_from_path(pathlib.Path(fp))
                    if text and text.strip():
                        fname = pathlib.Path(fp).name
                        parts.append(f"[파일: {fname}]\n{text}")
                        logger.info("CF_HDROP 파일 내용 추출: %s (%d chars)", fname, len(text))
                except Exception as exc:
                    logger.debug("CF_HDROP 파일 추출 실패 %s: %s", fp, exc)
            return "\n\n".join(parts) if parts else None
        except Exception as exc:
            logger.debug("CF_HDROP 처리 실패: %s", exc)
            return None

    def release_paste(
        self,
        expected_sequence: Optional[int] = None,
        expected_hwnd: int = 0,
        expected_process: str = "",
    ) -> bool:
        """Keep the original clipboard formats and re-issue Ctrl+V.

        Returns ``True`` only when all four keyboard events were injected.
        If the clipboard or foreground destination changed while AI analysis
        was pending, no input is injected because it would no longer be the
        user's original paste.
        """
        import time

        time.sleep(0.08)  # 훅 처리 안정화 대기

        with self._release_lock:
            current_sequence = int(_user32.GetClipboardSequenceNumber())
            if (
                expected_sequence
                and current_sequence
                and current_sequence != expected_sequence
            ):
                logger.warning(
                    "클립보드가 AI 분석 중 변경됨 — 재붙여넣기 취소 "
                    "(expected=%d current=%d)",
                    expected_sequence,
                    current_sequence,
                )
                return False

            current_hwnd = int(_user32.GetForegroundWindow() or 0)
            current_process = self._get_process_name(current_hwnd) or ""
            if not is_same_paste_destination(
                expected_hwnd,
                expected_process,
                current_hwnd,
                current_process,
            ):
                logger.warning(
                    "AI 분석 중 붙여넣기 대상 창이 변경됨 — 재발행 취소 "
                    "(expected_hwnd=%s current_hwnd=%s expected_process=%s "
                    "current_process=%s)",
                    expected_hwnd or "unknown",
                    current_hwnd or "unknown",
                    expected_process or "unknown",
                    current_process or "unknown",
                )
                return False

            # 클립보드를 비우거나 텍스트로 변환하지 않는다. 이로써
            # CF_HDROP, HTML, RTF 등 원본의 모든 클립보드 형식이 유지된다.
            self._skip_next_paste = True
            KEYEVENTF_KEYUP = 0x0002

            class _KEYBDINPUT(ctypes.Structure):
                _fields_ = [
                    ("wVk",         ctypes.c_ushort),
                    ("wScan",       ctypes.c_ushort),
                    ("dwFlags",     ctypes.c_ulong),
                    ("time",        ctypes.c_ulong),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
                ]

            class _INPUT(ctypes.Structure):
                _fields_ = [
                    ("type", ctypes.c_ulong),
                    ("ki",   _KEYBDINPUT),
                    ("_pad", ctypes.c_ubyte * 8),
                ]

            seq = (
                _INPUT(type=1, ki=_KEYBDINPUT(wVk=VK_CONTROL)),
                _INPUT(type=1, ki=_KEYBDINPUT(wVk=VK_V)),
                _INPUT(type=1, ki=_KEYBDINPUT(wVk=VK_V,       dwFlags=KEYEVENTF_KEYUP)),
                _INPUT(type=1, ki=_KEYBDINPUT(wVk=VK_CONTROL, dwFlags=KEYEVENTF_KEYUP)),
            )
            arr = (_INPUT * len(seq))(*seq)

            try:
                sent = int(
                    ctypes.windll.user32.SendInput(
                        len(seq), arr, ctypes.sizeof(_INPUT)
                    )
                )
            except Exception:
                self._skip_next_paste = False
                logger.exception("SendInput 예외 — 붙여넣기 재발행 실패")
                return False

            if sent != len(seq):
                self._skip_next_paste = False
                logger.error(
                    "SendInput 실패 — %d/%d 입력만 삽입됨 (error=%d)",
                    sent,
                    len(seq),
                    ctypes.get_last_error(),
                )
                return False

            logger.info("AI allow — 기존 클립보드 유지 후 붙여넣기 재발행 완료")
            return True

    def _handle_paste(self) -> bool:
        """Return True to block the paste, False to allow it."""
        # AI allow 판정 후 재발행된 Ctrl+V — 훅 무시
        if self._skip_next_paste:
            self._skip_next_paste = False
            return False

        destination_hwnd = int(_user32.GetForegroundWindow() or 0)
        process_name = self._get_process_name(destination_hwnd)
        if not process_name:
            return False

        if not self._should_inspect(process_name):
            return False

        clipboard_sequence = int(_user32.GetClipboardSequenceNumber())

        # 1) 텍스트/HTML 클립보드
        text = TextExtractor.extract()
        normalized = TextExtractor.normalize(text) if text else ""

        # 2) 파일 클립보드(CF_HDROP) — 파일 내용 추출
        file_text = self._extract_file_texts()
        if file_text:
            normalized = (normalized + "\n\n" + file_text).strip() if normalized else file_text

        if not normalized:
            return False

        current_sequence = int(_user32.GetClipboardSequenceNumber())
        if (
            clipboard_sequence
            and current_sequence
            and current_sequence != clipboard_sequence
        ):
            logger.warning(
                "클립보드 검사 중 내용이 변경됨 — 비동기 검사 생략 "
                "(before=%d after=%d)",
                clipboard_sequence,
                current_sequence,
            )
            return False
        if not clipboard_sequence:
            clipboard_sequence = current_sequence

        self._intercepted_destination = (
            destination_hwnd,
            process_name,
            clipboard_sequence,
        )
        try:
            return self._on_text_pasted(normalized, process_name, clipboard_sequence)
        finally:
            self._intercepted_destination = None

    def _keyboard_hook_proc(
        self, n_code: int, w_param: int, l_param: int
    ) -> int:
        if n_code >= 0 and w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
            kb = ctypes.cast(l_param, ctypes.POINTER(_KBDLLHOOKSTRUCT)).contents
            if kb.vkCode == VK_V:
                ctrl_down = bool(_user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
                if ctrl_down:
                    try:
                        if self._handle_paste():
                            return 1  # Suppress keystroke → paste is blocked
                    except Exception:
                        logger.exception("Error inside paste handler")

        return _user32.CallNextHookEx(self._hook_id, n_code, w_param, l_param)

    def _wnd_proc(self, hwnd: int, msg: int, w_param: int, l_param: int) -> int:
        if msg == WM_CLIPBOARDUPDATE:
            logger.debug("Clipboard sequence updated")
        elif msg == win32con.WM_DESTROY:
            _user32.RemoveClipboardFormatListener(hwnd)
            win32gui.PostQuitMessage(0)
        return win32gui.DefWindowProc(hwnd, msg, w_param, l_param)

    def _run(self) -> None:
        self._thread_id = win32api.GetCurrentThreadId()

        # Register hidden window class
        class_name = "SentryDLPClipboardListener"
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = class_name
        wc.lpfnWndProc = self._wnd_proc
        try:
            win32gui.RegisterClass(wc)
        except Exception:
            pass  # Already registered from a previous run in the same process

        # Create message-only HWND
        try:
            self._hwnd = win32gui.CreateWindow(
                class_name,
                "Sentry DLP Listener",
                0,
                0, 0, 0, 0,
                HWND_MESSAGE,
                0, 0, None,
            )
        except Exception:
            # Fallback: invisible top-level window (no WS_VISIBLE)
            self._hwnd = win32gui.CreateWindow(
                class_name, "Sentry DLP Listener",
                0, 0, 0, 0, 0, 0, 0, 0, None,
            )

        _user32.AddClipboardFormatListener(self._hwnd)

        # Install low-level keyboard hook
        self._hook_proc_ref = LowLevelKeyboardProc(self._keyboard_hook_proc)
        self._hook_id = _user32.SetWindowsHookExW(
            WH_KEYBOARD_LL,
            self._hook_proc_ref,
            None,
            0,
        )
        if not self._hook_id:
            err = ctypes.get_last_error()
            logger.error("Failed to install WH_KEYBOARD_LL (error=%d)", err)
            return

        logger.info(
            "Keyboard hook installed (hwnd=%s hook_id=%s)", self._hwnd, self._hook_id
        )

        try:
            win32gui.PumpMessages()  # Blocks until WM_QUIT
        finally:
            if self._hook_id:
                _user32.UnhookWindowsHookEx(self._hook_id)
                self._hook_id = None
            if self._hwnd:
                try:
                    win32gui.DestroyWindow(self._hwnd)
                except Exception:
                    pass
                self._hwnd = None
            logger.info("Keyboard hook uninstalled")
