"""JSON extraction + repair ladder, model coercion, schema-instruction builder.

LLMs return JSON wrapped in prose, fenced, truncated, or with trailing commas.
``extract_json`` walks a repair ladder; each rung logs on success and anything
past rung 1 marks the result as repaired.
"""

from __future__ import annotations

import json
import re
from enum import Enum
from types import UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel, ValidationError

from app.api.errors import ProviderError
from app.core.logging import get_logger

log = get_logger(__name__)

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)
_LINE_COMMENT_RE = re.compile(r"//[^\n\r]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


class ParseResult:
    """extract_json result carrying the winning rung (for the ``repaired`` flag)."""

    def __init__(self, data: dict | list, rung: int) -> None:
        self.data = data
        self.rung = rung

    @property
    def repaired(self) -> bool:
        return self.rung > 1


def _strip_fences(text: str) -> str:
    s = text.strip()
    if s.startswith("`"):
        s = _FENCE_RE.sub("", s)
        s = s.strip().strip("`").strip()
    return s


def _find_balanced(text: str) -> str | None:
    """Return the outermost balanced {...}/[...] span, tracking string escapes.

    If EOF is reached while still open (truncation), return from the opening
    bracket to EOF so the truncation-repair rung can close it.
    """
    start = -1
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            break
    if start == -1:
        return None

    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def _minor_repairs(candidate: str) -> str:
    s = candidate.lstrip("﻿").strip()
    s = _BLOCK_COMMENT_RE.sub("", s)
    s = _LINE_COMMENT_RE.sub("", s)
    s = _single_to_double_quotes(s)
    s = _TRAILING_COMMA_RE.sub(r"\1", s)
    return s


def _single_to_double_quotes(s: str) -> str:
    """Convert single-quoted strings to double, leaving already-double alone."""
    out: list[str] = []
    in_dq = False
    in_sq = False
    escape = False
    for ch in s:
        if escape:
            out.append(ch)
            escape = False
            continue
        if ch == "\\":
            out.append(ch)
            escape = True
            continue
        if in_dq:
            out.append(ch)
            if ch == '"':
                in_dq = False
            continue
        if in_sq:
            if ch == "'":
                out.append('"')
                in_sq = False
            elif ch == '"':
                out.append('\\"')
            else:
                out.append(ch)
            continue
        if ch == '"':
            in_dq = True
            out.append(ch)
        elif ch == "'":
            in_sq = True
            out.append('"')
        else:
            out.append(ch)
    return "".join(out)


def _close_truncated(candidate: str) -> str:
    """Close a truncated candidate: finish an open string, then close brackets."""
    stack: list[str] = []
    in_str = False
    escape = False
    for ch in candidate:
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]" and stack:
            stack.pop()

    result = candidate
    if in_str:
        result += '"'
    result = result.rstrip()
    while result.endswith(","):
        result = result[:-1].rstrip()
    if result.endswith(":"):
        result += "null"
    for opener in reversed(stack):
        result += "}" if opener == "{" else "]"
    return result


def _extract(text: str) -> ParseResult:
    raw = text if isinstance(text, str) else str(text)

    try:
        return ParseResult(json.loads(raw.strip()), 1)
    except (json.JSONDecodeError, ValueError):
        pass

    defenced = _strip_fences(raw)
    if defenced != raw.strip():
        try:
            return ParseResult(json.loads(defenced), 2)
        except (json.JSONDecodeError, ValueError):
            pass

    candidate = _find_balanced(defenced)
    if candidate is not None:
        try:
            return ParseResult(json.loads(candidate), 3)
        except (json.JSONDecodeError, ValueError):
            pass

        repaired = _minor_repairs(candidate)
        try:
            return ParseResult(json.loads(repaired), 4)
        except (json.JSONDecodeError, ValueError):
            pass

        closed = _close_truncated(repaired)
        try:
            return ParseResult(json.loads(closed), 5)
        except (json.JSONDecodeError, ValueError):
            pass

    raise ProviderError("could not extract JSON from model output", detail=raw[:500])


def extract_json(text: str) -> dict | list:
    """Repair-ladder JSON extractor. Raises ProviderError if nothing parses."""
    result = _extract(text)
    log.info("parsing.extract_json", rung=result.rung, repaired=result.repaired)
    return result.data


def extract_json_meta(text: str) -> ParseResult:
    """Like :func:`extract_json` but returns the winning rung for the caller."""
    result = _extract(text)
    log.info("parsing.extract_json", rung=result.rung, repaired=result.repaired)
    return result


def _unwrap_optional(ann: Any) -> Any:
    origin = get_origin(ann)
    if origin is Union or origin is UnionType:
        args = [a for a in get_args(ann) if a is not type(None)]
        if len(args) == 1:
            return args[0]
        return args[0] if args else ann
    return ann


def _enum_type(ann: Any) -> type[Enum] | None:
    ann = _unwrap_optional(ann)
    if isinstance(ann, type) and issubclass(ann, Enum):
        return ann
    return None


def _list_inner(ann: Any) -> Any | None:
    ann = _unwrap_optional(ann)
    if get_origin(ann) in (list, list):
        args = get_args(ann)
        return args[0] if args else Any
    return None


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.strip().lower()).strip("_")


def _match_enum(enum_cls: type[Enum], value: Any) -> Any:
    if isinstance(value, enum_cls):
        return value
    s = str(value)
    try:
        return enum_cls(s)
    except ValueError:
        pass
    target = _norm(s)
    for member in enum_cls:
        if _norm(str(member.value)) == target or member.name.lower() == s.lower():
            return member
    return value


def _has_unit_upper_bound(field: Any) -> bool:
    for meta in getattr(field, "metadata", []):
        le = getattr(meta, "le", None)
        lt = getattr(meta, "lt", None)
        if (le is not None and le <= 1) or (lt is not None and lt <= 1):
            return True
    return False


def _coerce_value(value: Any, ann: Any, field: Any) -> Any:
    inner_list = _list_inner(ann)
    if inner_list is not None:
        if not isinstance(value, list):
            value = [value]
        return [_coerce_value(v, inner_list, field) for v in value]

    enum_cls = _enum_type(ann)
    if enum_cls is not None and not isinstance(value, enum_cls):
        return _match_enum(enum_cls, value)

    base = _unwrap_optional(ann)
    if base is int and isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return value
    if base is float:
        if isinstance(value, str):
            try:
                value = float(value)
            except ValueError:
                return value
        if isinstance(value, (int, float)) and _has_unit_upper_bound(field) and value > 1:
            return value / 100.0
    return value


def coerce_to_model(data: Any, model: type[BaseModel]) -> BaseModel:
    """Validate ``data`` into ``model``, with one targeted coercion pass on failure."""
    try:
        return model.model_validate(data)
    except ValidationError:
        pass

    if not isinstance(data, dict):
        raise ProviderError(
            "model output is not an object", detail=str(data)[:500]
        )

    coerced = dict(data)
    for name, field in model.model_fields.items():
        key = name if name in coerced else (field.alias if field.alias in coerced else None)
        if key is None:
            continue
        coerced[key] = _coerce_value(coerced[key], field.annotation, field)

    try:
        return model.model_validate(coerced)
    except ValidationError as exc:
        raise ProviderError(
            "model output failed schema validation", detail=exc.errors()
        ) from exc


def _descriptor(ann: Any) -> Any:
    enum_cls = _enum_type(ann)
    if enum_cls is not None:
        return "one of: " + "|".join(str(m.value) for m in enum_cls)
    inner = _list_inner(ann)
    if inner is not None:
        return [_descriptor(inner)]
    base = _unwrap_optional(ann)
    if isinstance(base, type) and issubclass(base, BaseModel):
        return _schema_map(base)
    return {int: "int", float: "float", bool: "bool", str: "string"}.get(base, "any")


def _schema_map(model: type[BaseModel]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, field in model.model_fields.items():
        desc = _descriptor(field.annotation)
        if not field.is_required():
            desc = f"{desc} (optional)" if isinstance(desc, str) else desc
        out[name] = desc
    return out


def build_schema_instruction(model: type[BaseModel]) -> str:
    """Compact schema string (with enum literals) to append to a prompt."""
    mapping = _schema_map(model)
    return (
        "Return ONLY a single JSON object matching this schema exactly. "
        "Enum values must match the given literals verbatim:\n"
        + json.dumps(mapping)
    )
