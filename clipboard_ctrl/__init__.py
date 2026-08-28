"""Clipboard control module — paste interception and local filtering."""

from clipboard_ctrl.clipboard_hook import ClipboardHook
from clipboard_ctrl.notifier import notify_blocked, notify_review
from clipboard_ctrl.paste_inspector import PasteInspector
from clipboard_ctrl.rule_filter import RuleFilter
from clipboard_ctrl.text_extractor import TextExtractor

__all__ = [
    "ClipboardHook",
    "PasteInspector",
    "RuleFilter",
    "TextExtractor",
    "notify_blocked",
    "notify_review",
]
