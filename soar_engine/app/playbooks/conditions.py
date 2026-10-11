"""Evaluation of playbook conditions against a flat alert context."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from app.playbooks.models import Condition, Operator

_MISSING = object()


def resolve_field(context: dict[str, Any], path: str) -> Any:
    """Resolve ``a.b.c`` paths; returns a sentinel when the path does not exist."""
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _coerce_pair(left: Any, right: Any) -> tuple[Any, Any]:
    """Compare numbers numerically even if one side arrived as a string (e.g. rule.id)."""
    if isinstance(right, int | float) and isinstance(left, str):
        try:
            return float(left), right
        except ValueError:
            return left, right
    if isinstance(left, int | float) and isinstance(right, str):
        try:
            return left, float(right)
        except ValueError:
            return left, right
    return left, right


def _compare(op: Operator, actual: Any, expected: Any) -> bool:
    if op is Operator.EXISTS:
        return (actual is not _MISSING and actual is not None) == bool(
            True if expected is None else expected
        )
    if actual is _MISSING or actual is None:
        return op in (Operator.NE, Operator.NOT_IN)

    if op in (Operator.IN, Operator.NOT_IN):
        values = expected if isinstance(expected, list | tuple | set) else [expected]
        hit = any(_coerce_pair(actual, v)[0] == _coerce_pair(actual, v)[1] for v in values)
        return hit if op is Operator.IN else not hit
    if op is Operator.CONTAINS:
        if isinstance(actual, list | tuple | set):
            return expected in actual
        return str(expected) in str(actual)
    if op is Operator.ICONTAINS:
        if isinstance(actual, list | tuple | set):
            return str(expected).lower() in {str(a).lower() for a in actual}
        return str(expected).lower() in str(actual).lower()
    if op is Operator.REGEX:
        return _compile(str(expected)).search(str(actual)) is not None

    left, right = _coerce_pair(actual, expected)
    try:
        match op:
            case Operator.EQ:
                return bool(left == right)
            case Operator.NE:
                return bool(left != right)
            case Operator.GT:
                return bool(left > right)
            case Operator.GTE:
                return bool(left >= right)
            case Operator.LT:
                return bool(left < right)
            case Operator.LTE:
                return bool(left <= right)
    except TypeError:
        return False
    return False


def evaluate(condition: Condition, context: dict[str, Any]) -> bool:
    if condition.all is not None:
        return all(evaluate(c, context) for c in condition.all)
    if condition.any is not None:
        return any(evaluate(c, context) for c in condition.any)
    if condition.not_ is not None:
        return not evaluate(condition.not_, context)
    assert condition.field is not None and condition.op is not None
    return _compare(condition.op, resolve_field(context, condition.field), condition.value)
