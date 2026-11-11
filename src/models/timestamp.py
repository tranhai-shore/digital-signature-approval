"""UTC timestamp helpers for signing metadata."""

from __future__ import annotations

from datetime import datetime, timezone

MAX_TIMESTAMP_CHARACTERS = 64


def utc_now_iso() -> str:
    """Return the current UTC time in canonical form, e.g. ``2026-11-11T08:30:00Z``."""

    return format_utc(datetime.now(timezone.utc))


def format_utc(value: datetime) -> str:
    """Format an aware datetime as canonical UTC with second precision."""

    if value.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def canonicalize_timestamp(value: str) -> str:
    """Validate an ISO-8601 timestamp and normalize it to UTC ``...Z`` form.

    Naive timestamps are rejected because they would make the signed metadata
    ambiguous.  Offsets are accepted and converted to UTC.
    """

    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")

    text = value.strip()
    if len(text) > MAX_TIMESTAMP_CHARACTERS:
        raise ValueError(
            f"timestamp is too long (max {MAX_TIMESTAMP_CHARACTERS} characters)"
        )
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return format_utc(parsed)
