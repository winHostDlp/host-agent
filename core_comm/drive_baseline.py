"""Validate the machine-local drive baseline used by USB FileGuard."""

from __future__ import annotations

import json
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_BASELINE_PATH = PROJECT_ROOT / "config" / "internal_drives.local.json"
SETUP_GUIDANCE = (
    "이동식 저장장치를 모두 제거한 뒤 관리자 PowerShell에서 "
    r".\install\setup_agent.ps1 을 실행해 "
    r"config\internal_drives.local.json을 다시 생성하세요."
)


class DriveBaselineError(RuntimeError):
    """The local baseline is absent or unsafe to use."""


def load_internal_drives(
    path: Path = LOCAL_BASELINE_PATH,
    system_drive: str | None = None,
) -> set[str]:
    """Return validated drive letters without inventing a fallback baseline."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        raw_drives = data.get("internal_drives") if isinstance(data, dict) else None
        if not isinstance(raw_drives, list) or not raw_drives:
            raise ValueError("internal_drives는 비어 있지 않은 목록이어야 합니다")

        drives: set[str] = set()
        for raw_drive in raw_drives:
            value = raw_drive.strip().upper() if isinstance(raw_drive, str) else ""
            if len(value) != 2 or value[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" or value[1] != ":":
                raise ValueError(f"잘못된 드라이브 문자: {raw_drive!r}")
            drives.add(value)

        expected_system_drive = (
            os.environ.get("SystemDrive", "") if system_drive is None else system_drive
        ).strip().upper()
        if (
            len(expected_system_drive) != 2
            or expected_system_drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            or expected_system_drive[1] != ":"
        ):
            raise ValueError("Windows SystemDrive를 확인할 수 없습니다")
        if expected_system_drive not in drives:
            raise ValueError(f"시스템 드라이브 {expected_system_drive}가 누락되었습니다")
    except Exception as exc:
        raise DriveBaselineError(
            f"USB 내장 드라이브 기준을 사용할 수 없습니다 ({path}): {exc}. "
            f"{SETUP_GUIDANCE}"
        ) from exc

    return drives
