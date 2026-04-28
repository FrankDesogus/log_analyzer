from __future__ import annotations

from typing import Any


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def clamp_score(score: float) -> int:
    return max(0, min(100, int(round(score))))


def level_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def level_rank(level: str) -> int:
    normalized = (level or "info").strip().lower()
    try:
        return SEVERITY_ORDER.index(normalized)
    except ValueError:
        return 0


def confidence_from_reason_count(reason_count: int, bonus: float = 0.0) -> float:
    base = 0.45 + min(reason_count, 6) * 0.08 + bonus
    return max(0.0, min(1.0, round(base, 2)))


def to_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float | None = None) -> float | None:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
