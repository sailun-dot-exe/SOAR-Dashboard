"""Typed playbook definition (loaded from YAML)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Operator(StrEnum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    ICONTAINS = "icontains"
    REGEX = "regex"
    EXISTS = "exists"


class Condition(BaseModel):
    """Either a leaf comparison (field/op/value) or a boolean group (all/any/not)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    field: str | None = None
    op: Operator | None = None
    value: Any = None
    all: list[Condition] | None = None
    any: list[Condition] | None = None
    not_: Condition | None = Field(default=None, alias="not")

    @model_validator(mode="after")
    def _exactly_one_form(self) -> Condition:
        forms = [self.field is not None, self.all is not None, self.any is not None,
                 self.not_ is not None]
        if sum(forms) != 1:
            raise ValueError("condition must define exactly one of: field, all, any, not")
        if self.field is not None and self.op is None:
            raise ValueError(f"condition on '{self.field}' requires 'op'")
        return self


class Threshold(BaseModel):
    """Sliding-window counter: fire only when ``count > gt`` within ``window_seconds``."""

    model_config = ConfigDict(extra="forbid")

    count_when: Condition
    group_by: str = "source_ip"
    gt: int = Field(..., ge=0)
    window_seconds: int = Field(..., gt=0)


class OnTimeout(StrEnum):
    DENY = "deny"
    EXECUTE = "execute"


class HitlPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    timeout_seconds: int | None = Field(None, gt=0)
    on_timeout: OnTimeout = OnTimeout.DENY
    auto_execute_above_level: int | None = Field(
        None, description="If rule_level is strictly greater, auto-execute on timeout."
    )


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    responders: list[str] = Field(..., min_length=1, description="Tried in order until success.")
    params: dict[str, Any] = Field(default_factory=dict)
    continue_on_failure: bool = False


class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., pattern=r"^[a-z0-9][a-z0-9_-]*$")
    name: str
    description: str = ""
    enabled: bool = True
    threat_type: str
    trigger: Condition
    threshold: Threshold | None = None
    required_fields: list[str] = Field(default_factory=list)
    extract: dict[str, str] = Field(default_factory=dict)
    suppression_seconds: int = Field(600, ge=0)
    hitl: HitlPolicy = Field(default_factory=HitlPolicy)
    actions: list[Action] = Field(..., min_length=1)


Condition.model_rebuild()
