"""Strict JSON parsing for security-sensitive package and key files.

The standard :func:`json.loads` accepts duplicate object keys, ``NaN`` and
``Infinity``, and has no input-size limit.  Those behaviours are convenient for
general-purpose data but undesirable for files that control a verification
decision.  This module centralises a small, predictable policy:

* input is capped at :data:`DEFAULT_MAX_JSON_BYTES` (1 MiB);
* duplicate object keys are rejected instead of silently keeping the last one;
* ``NaN``, ``Infinity`` and ``-Infinity`` are rejected;
* invalid UTF-8, excessive nesting and malformed numbers become one exception
  type (:class:`JSONSupportError`).
"""

from __future__ import annotations

import json
import math
import os
from typing import Any

DEFAULT_MAX_JSON_BYTES = 1024 * 1024  # 1 MiB
MAX_JSON_INTEGER_DIGITS = 4096


class JSONSupportError(ValueError):
    """Raised when JSON input is malformed or violates the size policy."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JSONSupportError("duplicate key in JSON object")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> Any:
    raise JSONSupportError(f"non-finite number is not allowed: {value}")


def _parse_finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise JSONSupportError("non-finite number is not allowed")
    return number


def _parse_bounded_int(value: str) -> int:
    if len(value.lstrip("-")) > MAX_JSON_INTEGER_DIGITS:
        raise JSONSupportError("integer in JSON is too large")
    return int(value)


def _ensure_size(size: int, max_bytes: int) -> None:
    if size > max_bytes:
        raise JSONSupportError(
            f"JSON input exceeds the {max_bytes}-byte limit"
        )


def loads_strict(
    text: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> Any:
    """Parse JSON with duplicate-key, non-finite and size checks enabled."""

    if isinstance(text, bytes):
        _ensure_size(len(text), max_bytes)
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JSONSupportError("JSON input is not valid UTF-8") from exc
    elif isinstance(text, str):
        _ensure_size(len(text), max_bytes)
        try:
            encoded_size = len(text.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise JSONSupportError("JSON input contains invalid Unicode") from exc
        _ensure_size(encoded_size, max_bytes)
    else:
        raise TypeError("JSON input must be str or bytes")

    try:
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_non_finite,
            parse_float=_parse_finite_float,
            parse_int=_parse_bounded_int,
        )
    except JSONSupportError:
        raise
    except json.JSONDecodeError as exc:
        raise JSONSupportError(f"JSON is not valid: {exc.msg}") from exc
    except RecursionError as exc:
        raise JSONSupportError("JSON nesting is too deep") from exc
    except ValueError as exc:
        raise JSONSupportError("JSON contains invalid values") from exc


def read_json_file(
    path: str | os.PathLike[str],
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> Any:
    """Read and strictly parse a JSON file without trusting its size.

    At most ``max_bytes + 1`` bytes are read, so an oversized file is rejected
    without being loaded into memory.  ``OSError`` from opening or reading the
    file is intentionally allowed to propagate so callers can distinguish
    "unreadable" from "malformed".
    """

    with open(path, "rb") as handle:
        data = handle.read(max_bytes + 1)
    _ensure_size(len(data), max_bytes)
    return loads_strict(data, max_bytes=max_bytes)
