"""SCM scope handling for folder, snippet, and device resources."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl


VALID_SCOPE_TYPES = {"folder", "snippet", "device"}


@dataclass(frozen=True)
class Scope:
    scope_type: str
    scope_value: str

    def __post_init__(self):
        if self.scope_type not in VALID_SCOPE_TYPES:
            valid = ", ".join(sorted(VALID_SCOPE_TYPES))
            raise ValueError(f"Invalid SCM scope type '{self.scope_type}'. Expected one of: {valid}")
        if not self.scope_value:
            raise ValueError("SCM scope value cannot be empty")

    @classmethod
    def from_param(cls, scope_param: str) -> "Scope":
        pairs = dict(parse_qsl(scope_param.lstrip("&?")))
        matching_keys = [key for key in pairs if key in VALID_SCOPE_TYPES]
        if len(matching_keys) != 1:
            raise ValueError("SCM scope must include exactly one of: folder, snippet, device")
        scope_type = matching_keys[0]
        return cls(scope_type, pairs[scope_type])

    def as_query_params(self) -> dict[str, str]:
        return {self.scope_type: self.scope_value}

    def apply_to_payload(self, payload: dict) -> dict:
        scoped_payload = payload.copy()
        for scope_type in VALID_SCOPE_TYPES:
            scoped_payload.pop(scope_type, None)
        scoped_payload[self.scope_type] = self.scope_value
        return scoped_payload
