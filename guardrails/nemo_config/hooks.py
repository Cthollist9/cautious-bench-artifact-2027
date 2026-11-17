"""Per-call capture bridge between the rail action and the driver.

The driver (adapt_nemo.py) replaces `record` with its own collector before any
generate call; this default no-op keeps the config loadable standalone
(nemoguardrails CLI / server). Records carry the exact prompt string the
framework sent, the raw LLM output, the framework-parsed outcome and metadata.
"""
from typing import Any, Dict, List

_records: List[Dict[str, Any]] = []


def record(payload: Dict[str, Any]) -> None:
    _records.append(payload)


def drain() -> List[Dict[str, Any]]:
    out = list(_records)
    _records.clear()
    return out
