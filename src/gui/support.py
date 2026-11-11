"""Small helpers shared by the Tkinter user interface."""

from __future__ import annotations

from pathlib import Path


def format_size(size: int) -> str:
    """Format a byte count for display."""

    if size < 0:
        raise ValueError("size must be non-negative")
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def default_tampered_path(document: str | Path) -> Path:
    """Return ``<stem>-tampered<suffix>`` next to the document."""

    path = Path(document)
    return path.with_name(f"{path.stem}-tampered{path.suffix}")


def parse_integer(
    text: str,
    *,
    label: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Parse an integer with a user-facing validation message."""

    try:
        value = int(str(text).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} phải là số nguyên") from exc

    if minimum is not None and value < minimum:
        raise ValueError(f"{label} phải lớn hơn hoặc bằng {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} phải nhỏ hơn hoặc bằng {maximum}")
    return value


def shorten(value: str, *, head: int = 16, tail: int = 8) -> str:
    """Shorten a long fingerprint or digest for compact display."""

    if len(value) <= head + tail + 1:
        return value
    return f"{value[:head]}…{value[-tail:]}"
