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

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

import win32api
import win32con
import win32file

from core_comm.analysis_events import record_analysis_result
from core_comm.payload_builder import AnalysisResult
from core_comm.review_notifier import notify_review

logger = logging.getLogger(__name__)

_POLL_INTERVAL_SEC   = 2.0    # 드라이브 목록 폴링 주기
_WRITE_SETTLE_SEC    = 2.0    # 파일 쓰기 완료 대기 시간 (rename 후 flush 포함)
_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024   # 50 MB 초과 파일은 건너뜀
_MIN_TEXT_LEN        = 20     # 추출 텍스트가 이 미만이면 검사 생략

# 모니터링 대상 드라이브 타입
# DRIVE_REMOVABLE(2): USB 플래시드라이브 → 항상 감시
# DRIVE_FIXED(3): 일부 USB는 Windows에서 Fixed로 보고됨 → 내장 기준 파일로 구분
_MONITOR_TYPES = {win32con.DRIVE_REMOVABLE, win32con.DRIVE_FIXED}

# 설치 시 생성되는 내장 드라이브 기준 파일
_INTERNAL_DRIVES_CONFIG = Path(__file__).resolve().parent.parent / "config" / "internal_drives.json"


def _load_internal_drives() -> set[str]:
    """설치 시 저장된 내장 드라이브 목록을 반환.

    파일이 없으면 현재 시점의 FIXED 드라이브를 내장으로 간주하고
    파일을 새로 생성한다 (첫 실행 자동 초기화).
    """
    if _INTERNAL_DRIVES_CONFIG.exists():
        try:
            data = json.loads(_INTERNAL_DRIVES_CONFIG.read_text(encoding="utf-8"))
            drives = set(data.get("internal_drives", []))
            logger.info("[UsbGuard] 내장 드라이브 기준 로드: %s", drives)
            return drives
        except Exception as exc:
            logger.warning("[UsbGuard] internal_drives.json 읽기 실패: %s", exc)

    # 파일 없음 → 현재 연결된 모든 드라이브를 내장으로 간주하고 파일 생성
    # (이동식 저장장치 제거 후 setup_agent.ps1 실행이 권장 절차이나, 미실행 시 안전하게 자동 초기화)
    all_drives = {letter for letter, _ in _iter_drives()}
    logger.warning(
        "[UsbGuard] internal_drives.json 없음 — 현재 드라이브를 모두 내장으로 저장: %s\n"
        "  권장: 이동식 저장장치 제거 후 install/setup_agent.ps1 실행",
        all_drives,
    )
    try:
        _INTERNAL_DRIVES_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        _INTERNAL_DRIVES_CONFIG.write_text(
            json.dumps(
                {
                    "internal_drives": sorted(all_drives),
                    "_comment": "자동 생성(setup_agent.ps1 미실행). 이동식 저장장치 제거 후 재설치 권장.",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("[UsbGuard] internal_drives.json 저장 실패: %s", exc)
    return all_drives


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
        self._lock        = threading.Lock()
        self._poll_thread: Optional[threading.Thread] = None
        # 설치 시 기록된 내장 드라이브 목록 — 에이전트 재시작과 무관하게 항상 동일한 기준 사용
        self._internal_drives: set[str] = _load_internal_drives()

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
        # 기준: config/internal_drives.json 에 등록된 내장 드라이브 제외
        # REMOVABLE은 항상 감시, FIXED는 내장 기준 파일로 판단
        logger.info("[UsbGuard] 내장 드라이브 제외 기준: %s", self._internal_drives)

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
        """외장 드라이브 여부 판단.

        기준: internal_drives.json 에 없으면 외장.
        FIXED/REMOVABLE 타입에 무관하게 설치 시 기록된 목록만 신뢰한다.
        네트워크(REMOTE), CD-ROM, RAM 디스크는 제외.
        """
        if dtype not in _MONITOR_TYPES:
            return False
        return drive not in self._internal_drives

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
                                args=(full_path, drive),
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

    def _inspect_file(self, file_path: str, drive: str) -> None:
        # 쓰기 완료까지 대기
        time.sleep(_WRITE_SETTLE_SEC)

        if not os.path.isfile(file_path):
            return

        try:
            file_size = os.path.getsize(file_path)
        except OSError:
            return

        if file_size == 0 or file_size > self._max_size:
            logger.debug("[UsbGuard] 건너뜀 (size=%d): %s", file_size, file_path)
            return

        logger.info("[UsbGuard] 검사: %s (%d bytes)", file_path, file_size)

        # 텍스트 추출 (FileInspector는 Path 객체 필요)
        try:
            text = self._fi.extract_from_path(Path(file_path))
        except Exception as exc:
            logger.debug("[UsbGuard] 텍스트 추출 실패 %s: %s", file_path, exc)
            return

        if not text or len(text.strip()) < _MIN_TEXT_LEN:
            return

        # 정규식 DLP 검사
        hits = self._rf.match(text)
        if not hits:
            logger.debug("[UsbGuard] ALLOW (no hits): %s", file_path)
            return

        hit_ids = [h["id"] for h in hits]
        logger.warning("[UsbGuard] 민감 정보 탐지: %s  hits=%s", file_path, hit_ids)

        # AI 판단 (mock 또는 실제)
        payload = None
        result  = None
        try:
            payload = self._pb.build(
                text=text,
                hits=hits,
                channel="file_guard",
                process_name=f"usb_copy@{drive}",
            )
            result = self._ac.analyze(payload)
            action = result.action
        except Exception as exc:
            logger.warning("[UsbGuard] AI 판단 실패 → Fail-Open 허용: %s", exc)
            result = AnalysisResult(
                request_id=payload.request_id if payload else "",
                confidence_score=0.0,
                action="allow",
                reason=f"AI 분석 실패: {exc} — Fail-Open 허용",
                model_version="unavailable",
                analysis_failed=True,
            )
            action = result.action

        # 이벤트 로그
        try:
            record_analysis_result(
                self._el,
                result,
                channel="file_guard",
                process_name=f"usb_copy@{drive}",
                hits=hits,
                text=text[:500],
                event_id=payload.request_id if payload else None,
                detection_type="RULE_BASED" if getattr(self._ac, "is_mock", True) else "HYBRID",
                metadata={
                    "file_path":      file_path,
                    "file_size":      file_size,
                    "drive":          drive,
                },
            )
        except Exception:
            # 저장소·대시보드 오류가 이미 확정된 파일 조치를 바꾸지 않게 한다.
            logger.exception("[UsbGuard] 분석 결과 기록 실패(파일 조치 유지)")

        logger.info("[UsbGuard] AI 판단: action=%s  file=%s", action, file_path)

        if action == "block":
            # USB에서 민감 파일 삭제
            try:
                os.remove(file_path)
                logger.warning("[UsbGuard] 삭제 완료: %s", file_path)
            except OSError as exc:
                logger.error("[UsbGuard] 삭제 실패 %s: %s", file_path, exc)

            # 사용자 알림
            if self._on_blocked:
                try:
                    self._on_blocked(file_path, hits)
                except Exception:
                    pass

        elif action == "review":
            try:
                notify_review("file_guard", file_path, hits)
            except Exception:
                logger.exception("[UsbGuard] review 경고 실패(파일 허용 유지)")
            logger.warning("[UsbGuard] review 기록 — 파일 허용: %s", file_path)


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


def _get_fixed_drives() -> set[str]:
    """DRIVE_FIXED(3) 드라이브만 반환 (내장 C:, D: 등)."""
    return {letter for letter, dtype in _iter_drives()
            if dtype == win32con.DRIVE_FIXED}


def _get_all_local_drives() -> set[str]:
    """REMOVABLE + FIXED 드라이브 목록 반환 (폴링용)."""
    return {letter for letter, dtype in _iter_drives()
            if dtype in _MONITOR_TYPES}
