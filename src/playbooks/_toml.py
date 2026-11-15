"""Small helpers that read typed values out of parsed TOML and collect problems instead of raising."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any


class Reader:
    def __init__(self, source: str) -> None:
        self.source = source
        self.problems: list[str] = []

    def bad(self, where: str, message: str) -> None:
        self.problems.append(f"{self.source}{where}: {message}")

    def table(self, value: Any, where: str) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        self.bad(where, "expected a table")
        return {}

    def string(self, t: dict[str, Any], key: str, where: str, *, allow_empty: bool = False) -> str:
        value = t.get(key, "" if allow_empty else None)
        if isinstance(value, str) and (value or allow_empty):
            return value
        self.bad(where, f"`{key}` must be {'a string' if allow_empty else 'a non-empty string'}")
        return ""

    def integer(
        self, t: dict[str, Any], key: str, where: str, *, default: int | None = None
    ) -> int:
        value = t.get(key, default)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        self.bad(where, f"`{key}` must be an integer")
        return 0

    def boolean(
        self, t: dict[str, Any], key: str, where: str, *, default: bool | None = None
    ) -> bool:
        value = t.get(key, default)
        if isinstance(value, bool):
            return value
        self.bad(where, f"`{key}` must be true or false")
        return False

    def strings(
        self, t: dict[str, Any], key: str, where: str, *, default: list[str] | None = None
    ) -> tuple[str, ...]:
        value = t.get(key, default)
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return tuple(value)
        self.bad(where, f"`{key}` must be a list of strings")
        return ()

    def day(self, t: dict[str, Any], key: str, where: str, *, required: bool = True) -> date | None:
        value = t.get(key)
        if value is None and not required:
            return None
        if isinstance(value, date) and not isinstance(value, datetime):
            return value
        self.bad(where, f"`{key}` must be a date such as 2026-11-15")
        return None

    def moment(self, t: dict[str, Any], key: str, where: str) -> datetime | None:
        """A date and time that says its offset, such as 2026-11-15T09:30:00Z."""
        value = t.get(key)
        if isinstance(value, datetime) and value.tzinfo is not None:
            return value
        self.bad(
            where, f"`{key}` must be a date and time with an offset, such as 2026-11-15T09:30:00Z"
        )
        return None
