"""
usb_guard_usermode.py — User-mode USB DLP (커널 드라이버 불필요)

동작 원리
---------
1. GetLogicalDrives + GetDriveType 폴링(2초)으로 이동식 드라이브 삽입 감지
2. 새 드라이브마다 ReadDirectoryChangesW 스레드를 띄워 파일 변경 감시
3. 새 파일 또는 수정된 파일 → 쓰기 완료 대기 → 텍스트 추출 → DLP 검사
4. 민감 정보 탐지 시 파일 삭제 + 이벤트 로그 + 팝업 알림

한계
----
- 탐지 방식이 "사후 삭제(detect-and-remediate)"이므로 초소형 파일(수 KB)은
  복사 완료 후 삭제될 수 있음. 완전한 사전 차단은 커널 드라이버 방식이 필요.
- pywin32(win32api, win32file, win32con) 필요. 추가 패키지 설치 불필요.
"""

from __future__ import annotations

import ctypes
import logging
import ntpath
import os
import threading
import time
from dataclasses import replace
from typing import Any, Callable, Optional
from uuid import uuid4

import win32api
import win32con
import win32file

from core_comm.analysis_events import record_analysis_result
from core_comm.payload_builder import AnalysisResult
from core_comm.review_notifier import notify_review

logger = logging.getLogger(__name__)

_POLL_INTERVAL_SEC       = 2.0
_FILE_STABLE_INTERVAL_SEC = 0.25
_FILE_STABLE_SAMPLES     = 5
_FILE_STABLE_TIMEOUT_SEC = 15.0
_MAX_FILE_SIZE_BYTES     = 50 * 1024 * 1024
_MIN_TEXT_LEN            = 20
_DELETE_ACCESS           = 0x00010000
_FILE_DISPOSITION_INFO_CLASS = 4
_READ_CHUNK_BYTES        = 1024 * 1024

# 드라이브 문자 기준으로 FIXED 볼륨을 외장으로 추정하면 내장 디스크를
# 삭제 대상으로 잘못 선택할 수 있다. 이번 시연은 Windows가 명시적으로
# DRIVE_REMOVABLE로 보고하는 매체만 감시한다.
_FileFingerprint = tuple[int, int, int, int, int]
_HandleFingerprint = tuple[int, int, int, int, Any, Any]


class _FileDispositionInfo(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_ubyte)]


def _stat_fingerprint(stat: Any) -> _FileFingerprint:
    return (
        stat.st_size,
        stat.st_mtime_ns,
        stat.st_ctime_ns,
        stat.st_dev,
        stat.st_ino,
    )


def _read_file_fingerprint(file_path: str) -> _FileFingerprint:
    return _stat_fingerprint(os.stat(file_path))


def _open_file_handle(file_path: str) -> Any:
    """Open one immutable inspection target with read and delete rights."""
    return win32file.CreateFile(
        file_path,
        win32con.GENERIC_READ | _DELETE_ACCESS,
        win32con.FILE_SHARE_READ,
        None,
        win32con.OPEN_EXISTING,
        win32file.FILE_FLAG_OPEN_REPARSE_POINT
        | win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )


def _handle_volume_serial(handle: Any) -> int:
    return int(win32file.GetFileInformationByHandle(handle)[4])


def _handle_fingerprint(handle: Any) -> _HandleFingerprint:
    """Identity and mutable state read from the already-open Windows handle."""
    info = win32file.GetFileInformationByHandle(handle)
    file_size = (int(info[5]) << 32) | int(info[6])
    file_index = (int(info[8]) << 32) | int(info[9])
    return (
        int(info[0]),
        int(info[4]),
        file_index,
        file_size,
        info[1],
        info[3],
    )


def _read_handle_bytes(handle: Any, file_size: int) -> bytes:
    """Read exactly ``file_size`` bytes from the inspection handle."""
    win32file.SetFilePointer(handle, 0, 0)  # FILE_BEGIN
    chunks: list[bytes] = []
    remaining = file_size
    while remaining:
        error, data = win32file.ReadFile(handle, min(remaining, _READ_CHUNK_BYTES))
        if error not in (0, None):
            raise OSError(error, "ReadFile failed")
        if not data:
            raise OSError("ReadFile reached EOF before the expected file size")
        if len(data) > remaining:
            raise OSError("ReadFile returned more data than requested")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def _mark_delete_on_close(handle: Any) -> None:
    """Set FileDispositionInfo on ``handle`` using the official Win32 API."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_file_information = kernel32.SetFileInformationByHandle
    set_file_information.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]
    set_file_information.restype = ctypes.c_int
    disposition = _FileDispositionInfo(1)
    if not set_file_information(
        ctypes.c_void_p(int(handle)),
        _FILE_DISPOSITION_INFO_CLASS,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error))


def _close_file_handle(handle: Any) -> Optional[Exception]:
    try:
        handle.Close()
    except Exception as exc:
        return exc
    return None


def _wait_for_stable_file(file_path: str) -> Optional[_FileFingerprint]:
    """파일 크기·수정 시간이 연속으로 같을 때 분석 전 지문을 반환한다."""
    deadline = time.monotonic() + _FILE_STABLE_TIMEOUT_SEC
    previous: Optional[tuple[int, int]] = None
    stable_samples = 0

    while True:
        try:
            stat = os.stat(file_path)
        except FileNotFoundError:
            logger.warning("[UsbGuard] 안정화 중 파일이 사라져 검사 종료: %s", file_path)
            return None
        except OSError as exc:
            logger.warning("[UsbGuard] 파일 상태 확인 실패로 검사 종료 %s: %s", file_path, exc)
            return None

        current = (stat.st_size, stat.st_mtime_ns)
        if current == previous:
            stable_samples += 1
        else:
            previous = current
            stable_samples = 1

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.warning("[UsbGuard] 파일 안정화 시간 초과로 검사 종료: %s", file_path)
            return None
        if stable_samples >= _FILE_STABLE_SAMPLES:
            return _stat_fingerprint(stat)
        time.sleep(min(_FILE_STABLE_INTERVAL_SEC, remaining))


class UsbGuardUserMode:
    """
    커널 드라이버 없이 동작하는 USB 파일 반출 탐지·차단 모듈.

    Parameters
    ----------
    rule_filter     : RuleFilter 인스턴스 (정규식 DLP 검사)
    payload_builder : PayloadBuilder 인스턴스 (AI 요청 페이로드 빌드)
    api_client      : ApiClient 인스턴스 (AI 판단)
    event_logger    : EventLogger 인스턴스 (JSONL 로컬 로그)
    file_inspector  : FileInspector 인스턴스 (파일→텍스트 추출)
    on_blocked      : 차단 발생 시 호출할 콜백 (file_path, hits) → None
    max_file_size   : 검사할 최대 파일 크기 (바이트). 기본 50 MB.
    """

    def __init__(
        self,
        rule_filter: Any,
        payload_builder: Any,
        api_client: Any,
        event_logger: Any,
        file_inspector: Any,
        on_blocked: Optional[Callable[[str, list], None]] = None,
        max_file_size: int = _MAX_FILE_SIZE_BYTES,
    ) -> None:
        self._rf          = rule_filter
        self._pb          = payload_builder
        self._ac          = api_client
        self._el          = event_logger
        self._fi          = file_inspector
        self._on_blocked  = on_blocked
        self._max_size    = max_file_size

        self._stop_ev     = threading.Event()
        self._watched:    dict[str, threading.Event] = {}  # drive → stop event
        self._inflight_paths: set[str] = set()
        self._lock        = threading.Lock()
        self._poll_thread: Optional[threading.Thread] = None

    # ── 시작 / 정지 ──────────────────────────────────────────────────────────

    def start(self) -> None:
        self._stop_ev.clear()
        self._poll_thread = threading.Thread(
            target=self._drive_poll_loop,
            name="UsbGuard-Poll",
            daemon=True,
        )
        self._poll_thread.start()
        logger.info("[UsbGuard] USB 드라이브 모니터 시작 (폴링 방식)")

    def stop(self) -> None:
        self._stop_ev.set()
        with self._lock:
            for ev in self._watched.values():
                ev.set()
        logger.info("[UsbGuard] 모니터 종료")

    # ── 드라이브 폴링 루프 ────────────────────────────────────────────────────

    def _drive_poll_loop(self) -> None:
        logger.info("[UsbGuard] DRIVE_REMOVABLE 매체만 감시합니다.")

        # 이미 꽂혀 있는 드라이브 중 외장으로 판단되는 것 즉시 감시 시작
        for drive, dtype in _iter_drives():
            if self._is_external(drive, dtype):
                logger.info("[UsbGuard] 기존 외장 드라이브 감지: %s (type=%d)", drive, dtype)
                self._start_drive_watcher(drive)

        # 이후 새로 나타나는 드라이브를 폴링
        prev_all: set[str] = _get_all_local_drives()

        while not self._stop_ev.is_set():
            current_all = _get_all_local_drives()

            inserted = current_all - prev_all
            removed  = prev_all  - current_all

            for drive in inserted:
                dtype = win32file.GetDriveType(drive + "\\")
                dtype_name = {2: "REMOVABLE", 3: "FIXED"}.get(dtype, f"type{dtype}")
                if self._is_external(drive, dtype):
                    logger.info("[UsbGuard] 새 외장 드라이브 감지: %s (%s)", drive, dtype_name)
                    self._start_drive_watcher(drive)
                else:
                    logger.debug("[UsbGuard] 내장 드라이브 제외: %s (%s)", drive, dtype_name)

            for drive in removed:
                logger.info("[UsbGuard] 드라이브 제거: %s", drive)
                with self._lock:
                    ev = self._watched.get(drive)
                    if ev:
                        ev.set()

            prev_all = current_all
            self._stop_ev.wait(_POLL_INTERVAL_SEC)

    def _is_external(self, drive: str, dtype: int) -> bool:
        """Windows가 DRIVE_REMOVABLE로 보고한 매체만 허용한다."""
        _ = drive
        return dtype == win32con.DRIVE_REMOVABLE

    # ── 드라이브별 파일 감시 스레드 ──────────────────────────────────────────

    def _start_drive_watcher(self, drive: str) -> None:
        with self._lock:
            if drive in self._watched:
                return
            stop_ev = threading.Event()
            self._watched[drive] = stop_ev

        t = threading.Thread(
            target=self._dir_watch_loop,
            args=(drive, stop_ev),
            name=f"UsbGuard-{drive}",
            daemon=True,
        )
        t.start()

    def _dir_watch_loop(self, drive: str, stop_ev: threading.Event) -> None:
        drive_path = drive + "\\"
        logger.info("[UsbGuard] %s 파일 감시 시작", drive_path)

        try:
            handle = win32file.CreateFile(
                drive_path,
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        except Exception as exc:
            logger.warning("[UsbGuard] %s 핸들 열기 실패: %s", drive, exc)
            with self._lock:
                self._watched.pop(drive, None)
            return

        try:
            try:
                expected_volume_serial = _handle_volume_serial(handle)
            except Exception as exc:
                logger.warning(
                    "[UsbGuard] %s 볼륨 일련번호 확인 실패로 감시 종료: %s",
                    drive,
                    exc,
                )
                return
            while not stop_ev.is_set():
                try:
                    # ReadDirectoryChangesW: 변경 이벤트 대기 (blocking)
                    changes = win32file.ReadDirectoryChangesW(
                        handle,
                        65536,
                        True,   # 하위 폴더 포함
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME
                        | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
                        | win32con.FILE_NOTIFY_CHANGE_SIZE,
                        None,
                        None,
                    )
                    for action, rel_path in changes:
                        # 1=파일 추가, 3=내용 수정, 5=이름 변경 후(rename 대상)
                        # Explorer 복사는 임시파일 생성 후 rename하므로 5가 핵심
                        if action in (1, 3, 5):
                            full_path = os.path.join(drive_path, rel_path)
                            # 숨김 임시 파일 (~로 시작하거나 .tmp) 은 건너뜀
                            fname = os.path.basename(full_path)
                            if fname.startswith("~") or fname.lower().endswith(".tmp"):
                                logger.info("[UsbGuard] 임시 파일 건너뜀: %s", fname)
                                continue
                            logger.info("[UsbGuard] 변경 감지 action=%d: %s", action, full_path)
                            threading.Thread(
                                target=self._inspect_file,
                                args=(full_path, drive, expected_volume_serial),
                                daemon=True,
                            ).start()

                except Exception as exc:
                    if stop_ev.is_set():
                        break
                    # 드라이브 제거 등으로 핸들이 무효화된 경우
                    logger.info("[UsbGuard] %s 감시 중단 (%s)", drive, exc)
                    break
        finally:
            try:
                win32api.CloseHandle(handle)
            except Exception:
                pass
            with self._lock:
                self._watched.pop(drive, None)
            logger.info("[UsbGuard] %s 파일 감시 종료", drive_path)

    # ── DLP 검사 ─────────────────────────────────────────────────────────────

    def _inspect_file(
        self,
        file_path: str,
        drive: str,
        expected_volume_serial: int,
    ) -> None:
        path_key = os.path.normcase(os.path.abspath(file_path))
        with self._lock:
            if path_key in self._inflight_paths:
                logger.debug("[UsbGuard] 중복 검사 생략: %s", file_path)
                return
            self._inflight_paths.add(path_key)

        try:
            self._inspect_stable_file(file_path, drive, expected_volume_serial)
        finally:
            with self._lock:
                self._inflight_paths.discard(path_key)

    def _inspect_stable_file(
        self,
        file_path: str,
        drive: str,
        expected_volume_serial: int,
    ) -> None:
        analysis_fingerprint = _wait_for_stable_file(file_path)
        if analysis_fingerprint is None:
            return
        file_size = analysis_fingerprint[0]
        if file_size == 0 or file_size > self._max_size:
            logger.debug("[UsbGuard] 건너뜀 (size=%d): %s", file_size, file_path)
            return

        try:
            file_handle = _open_file_handle(file_path)
        except Exception as exc:
            logger.warning("[UsbGuard] 검사 핸들 열기 실패로 검사 종료 %s: %s", file_path, exc)
            return

        try:
            try:
                handle_fingerprint = _handle_fingerprint(file_handle)
                attributes, volume_serial, _, handle_size, _, _ = handle_fingerprint
                if attributes & win32con.FILE_ATTRIBUTE_DIRECTORY:
                    logger.warning("[UsbGuard] 디렉터리는 검사하지 않음: %s", file_path)
                    return
                if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                    logger.warning("[UsbGuard] reparse point는 검사하지 않음: %s", file_path)
                    return
                if volume_serial != expected_volume_serial:
                    logger.error(
                        "[UsbGuard] 감시 볼륨과 파일 볼륨이 달라 검사 종료: %s",
                        file_path,
                    )
                    return
                if handle_size != file_size:
                    logger.error("[UsbGuard] 핸들 파일 크기 변경으로 검사 종료: %s", file_path)
                    return
                if _read_file_fingerprint(file_path) != analysis_fingerprint:
                    logger.error("[UsbGuard] 핸들 열기 전후 파일 변경으로 검사 종료: %s", file_path)
                    return
                file_bytes = _read_handle_bytes(file_handle, handle_size)
            except Exception as exc:
                logger.warning("[UsbGuard] 핸들 기반 파일 검증 실패로 검사 종료 %s: %s", file_path, exc)
                return

            logger.info("[UsbGuard] 검사: %s (%d bytes)", file_path, file_size)
            try:
                text = self._fi.extract_from_bytes(
                    file_bytes,
                    ntpath.basename(file_path),
                )
            except Exception as exc:
                logger.debug("[UsbGuard] 텍스트 추출 실패 %s: %s", file_path, exc)
                return

            if not text or len(text.strip()) < _MIN_TEXT_LEN:
                return

            hits = self._rf.match(text)
            if not hits:
                logger.debug("[UsbGuard] ALLOW (no hits): %s", file_path)
                return

            hit_ids = [h["id"] for h in hits]
            logger.warning("[UsbGuard] 민감 정보 탐지: %s  hits=%s", file_path, hit_ids)

            event_id = str(uuid4())
            payload = None
            result = None
            try:
                payload = self._pb.build(
                    text=text,
                    hits=hits,
                    channel="file_guard",
                    process_name=f"usb_copy@{drive}",
                )
                event_id = getattr(payload, "request_id", "") or event_id
                result = self._ac.analyze(payload)
                action = result.action
            except Exception as exc:
                logger.warning("[UsbGuard] AI 판단 실패 → Fail-Open 허용: %s", exc)
                result = AnalysisResult(
                    request_id=event_id,
                    confidence_score=0.0,
                    action="allow",
                    reason=f"AI 분석 실패: {exc} — Fail-Open 허용",
                    model_version="unavailable",
                    analysis_failed=True,
                )
                action = result.action

            logger.info("[UsbGuard] AI 판단: action=%s  file=%s", action, file_path)
            record_result = result
            action_failures: list[str] = []

            if action == "block":
                try:
                    if _handle_fingerprint(file_handle) != handle_fingerprint:
                        action_failures.append(
                            "AI block 판단 후 열린 파일 핸들 지문 변경 감지; "
                            "실제 차단 미확인, 경고 후 허용"
                        )
                    else:
                        _mark_delete_on_close(file_handle)
                except Exception as exc:
                    action_failures.append(
                        "AI block 판단 후 USB 파일 삭제 예약 실패"
                        f"({type(exc).__name__}); 실제 차단 미확인, "
                        "경고 후 허용"
                    )

            close_failure = _close_file_handle(file_handle)
            file_handle = None
            if close_failure is not None:
                if action == "block":
                    action_failures.append(
                        "검사 핸들 닫기 실패"
                        f"({type(close_failure).__name__}); 실제 차단 미확인, "
                        "경고 후 허용"
                    )
                else:
                    action_failures.append(
                        "검사 핸들 닫기 실패"
                        f"({type(close_failure).__name__}); 핸들 해제 상태 미확인, "
                        "경고 후 허용"
                    )

            if action_failures:
                record_result = replace(
                    result,
                    action="review",
                    reason=" — ".join([result.reason, *action_failures]),
                )

            if record_result.action == "review":
                try:
                    notify_review("file_guard", file_path, hits)
                except Exception:
                    logger.exception("[UsbGuard] review 경고 표시 실패(파일 허용 유지)")
                logger.warning("[UsbGuard] review 기록 — 파일 허용: %s", file_path)
            elif record_result.action == "block":
                logger.warning("[UsbGuard] 삭제 완료: %s", file_path)
                if self._on_blocked:
                    try:
                        self._on_blocked(file_path, hits)
                    except Exception:
                        pass

            try:
                record_analysis_result(
                    self._el,
                    record_result,
                    channel="file_guard",
                    process_name=f"usb_copy@{drive}",
                    hits=hits,
                    text=text[:500],
                    event_id=event_id,
                    detection_type=(
                        "RULE_BASED"
                        if getattr(self._ac, "is_mock", True)
                        else "HYBRID"
                    ),
                    metadata={
                        "file_path": file_path,
                        "file_size": file_size,
                        "drive": drive,
                    },
                )
            except Exception:
                logger.exception("[UsbGuard] 분석 결과 기록 실패(파일 조치 유지)")
        finally:
            if file_handle is not None:
                close_failure = _close_file_handle(file_handle)
                if close_failure is not None:
                    logger.error(
                        "[UsbGuard] 검사 중단 후 파일 핸들 닫기 실패 %s: %s",
                        file_path,
                        close_failure,
                    )


# ── 유틸 ─────────────────────────────────────────────────────────────────────

def _iter_drives():
    """(letter, dtype) 쌍 이터레이터. letter 예: 'C:', dtype 예: 3."""
    try:
        bitmask = win32api.GetLogicalDrives()
    except Exception:
        return
    for i in range(26):
        if bitmask & (1 << i):
            letter = chr(ord("A") + i) + ":"
            try:
                dtype = win32file.GetDriveType(letter + "\\")  # win32file 사용
                yield letter, dtype
            except Exception:
                pass


def _get_removable_drives() -> set[str]:
    """DRIVE_REMOVABLE(2) 드라이브만 반환."""
    return {letter for letter, dtype in _iter_drives()
            if dtype == win32con.DRIVE_REMOVABLE}


def _get_all_local_drives() -> set[str]:
    """FileGuard가 폴링할 DRIVE_REMOVABLE 드라이브 목록."""
    return _get_removable_drives()
