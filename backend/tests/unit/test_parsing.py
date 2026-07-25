"""Exhaustive tests for the JSON repair ladder + model coercion."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, Field

from app.api.errors import ProviderError
from app.providers.parsing import (
    build_schema_instruction,
    coerce_to_model,
    extract_json,
    extract_json_meta,
)
from app.schemas import AttackType, Severity


def test_clean_json() -> None:
    assert extract_json('{"a": 1, "b": [1, 2]}') == {"a": 1, "b": [1, 2]}
    assert extract_json_meta('{"a": 1}').repaired is False


def test_fenced_json() -> None:
    text = "```json\n{\"a\": 1}\n```"
    assert extract_json(text) == {"a": 1}
    assert extract_json_meta(text).repaired is True


def test_prose_around_json() -> None:
    text = 'Sure! Here is the result:\n{"severity": "high"}\nHope that helps.'
    assert extract_json(text) == {"severity": "high"}


def test_braces_inside_string_do_not_break_scanner() -> None:
    text = 'prefix {"msg": "this } has braces { inside", "n": {"x": 1}} suffix'
    out = extract_json(text)
    assert out == {"msg": "this } has braces { inside", "n": {"x": 1}}


def test_trailing_commas() -> None:
    assert extract_json('{"a": 1, "b": [1, 2,],}') == {"a": 1, "b": [1, 2]}


def test_single_quotes() -> None:
    assert extract_json("{'a': 'hello', 'b': 2}") == {"a": "hello", "b": 2}


def test_line_and_block_comments() -> None:
    text = '{\n  "a": 1, // inline\n  /* block */ "b": 2\n}'
    assert extract_json(text) == {"a": 1, "b": 2}


def test_bom_stripped() -> None:
    text = "﻿{\"a\": 1}"
    assert extract_json(text) == {"a": 1}


def test_truncated_mid_string() -> None:
    out = extract_json('{"summary": "the attacker was scanning por')
    assert out["summary"].startswith("the attacker was scanning por")
    assert extract_json_meta('{"summary": "trunc').repaired is True


def test_truncated_mid_array() -> None:
    out = extract_json('{"items": [1, 2, 3')
    assert out == {"items": [1, 2, 3]}


def test_truncated_trailing_comma_array() -> None:
    out = extract_json('{"items": [1, 2, 3,')
    assert out == {"items": [1, 2, 3]}


def test_unrecoverable_garbage_raises() -> None:
    with pytest.raises(ProviderError):
        extract_json("this is not json at all, no brackets, nothing")


class _Clf(BaseModel):
    severity: Severity
    attack_type: AttackType
    confidence: float = Field(ge=0.0, le=1.0)
    tags: list[str] = []


def test_coerce_enum_case_insensitive() -> None:
    m = coerce_to_model(
        {"severity": "HIGH", "attack_type": "Port Scan", "confidence": 0.5}, _Clf
    )
    assert isinstance(m, _Clf)
    assert m.severity is Severity.HIGH
    assert m.attack_type is AttackType.PORT_SCAN


def test_coerce_confidence_0_100_to_0_1() -> None:
    m = coerce_to_model(
        {"severity": "high", "attack_type": "port_scan", "confidence": 87}, _Clf
    )
    assert m.confidence == pytest.approx(0.87)


def test_coerce_scalar_to_list() -> None:
    m = coerce_to_model(
        {"severity": "low", "attack_type": "benign", "confidence": 0.1, "tags": "solo"}, _Clf
    )
    assert m.tags == ["solo"]


def test_coerce_numeric_string() -> None:
    m = coerce_to_model(
        {"severity": "info", "attack_type": "unknown", "confidence": "0.42"}, _Clf
    )
    assert m.confidence == pytest.approx(0.42)


def test_coerce_unrecoverable_raises() -> None:
    with pytest.raises(ProviderError):
        coerce_to_model(
            {"severity": "not_a_severity", "attack_type": "port_scan", "confidence": 0.5}, _Clf
        )


def test_schema_instruction_includes_enum_literals() -> None:
    instr = build_schema_instruction(_Clf)
    assert "critical" in instr and "high" in instr
    assert "port_scan" in instr
    assert "confidence" in instr
