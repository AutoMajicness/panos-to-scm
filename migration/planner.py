"""Dry-run migration planner.

The planner compares parsed configuration payloads with current SCM objects and
returns an explicit plan. It intentionally has no network or credential access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


ParsedData = Mapping[str, list[dict[str, Any]]]
CurrentData = Mapping[str, list[dict[str, Any]]]


@dataclass(frozen=True)
class Change:
    """A planned create/update/skip/conflict operation for one SCM entity."""

    action: str
    object_type: str
    name: str
    desired: dict[str, Any] | None = None
    current: dict[str, Any] | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "object_type": self.object_type,
            "name": self.name,
            "reason": self.reason,
            "desired": self.desired,
            "current": self.current,
        }


@dataclass(frozen=True)
class MigrationPlan:
    """Dry-run output grouped by operation type."""

    creates: list[Change] = field(default_factory=list)
    updates: list[Change] = field(default_factory=list)
    skips: list[Change] = field(default_factory=list)
    conflicts: list[Change] = field(default_factory=list)
    unsupported: list[Change] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.creates) + len(self.updates) + len(self.conflicts) + len(self.unsupported)

    def summary(self) -> dict[str, int]:
        return {
            "creates": len(self.creates),
            "updates": len(self.updates),
            "skips": len(self.skips),
            "conflicts": len(self.conflicts),
            "unsupported": len(self.unsupported),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "creates": _serialize_changes(self.creates),
            "updates": _serialize_changes(self.updates),
            "skips": _serialize_changes(self.skips),
            "conflicts": _serialize_changes(self.conflicts),
            "unsupported": _serialize_changes(self.unsupported),
        }


def build_plan(
    parsed_data: ParsedData,
    current_data: CurrentData | None = None,
    object_types: list[str] | None = None,
    conflict_policy: str = "fail",
) -> MigrationPlan:
    """Compare parsed data with existing SCM state.

    Args:
        parsed_data: Parser output keyed by SCM object/rule type.
        current_data: Current SCM state keyed by the same type names.
        object_types: Optional allow-list of object types to plan.
        conflict_policy: One of ``fail``, ``replace``, ``ignore``.

    Returns:
        A dry-run plan with creates, updates, skips, conflicts, and unsupported.
    """

    if conflict_policy not in {"fail", "replace", "ignore"}:
        raise ValueError("conflict_policy must be one of: fail, replace, ignore")

    current_data = current_data or {}
    selected_types = object_types or list(parsed_data.keys())

    creates: list[Change] = []
    updates: list[Change] = []
    skips: list[Change] = []
    conflicts: list[Change] = []
    unsupported: list[Change] = []

    for object_type in selected_types:
        desired_entries = parsed_data.get(object_type, [])
        if not isinstance(desired_entries, list):
            unsupported.append(
                Change(
                    action="unsupported",
                    object_type=object_type,
                    name=object_type,
                    desired={"value": desired_entries},
                    reason="parsed data value is not a list",
                )
            )
            continue

        current_by_name = {
            item["name"]: item
            for item in current_data.get(object_type, [])
            if isinstance(item, dict) and "name" in item
        }

        seen_names: set[str] = set()
        for desired in desired_entries:
            if not isinstance(desired, dict):
                unsupported.append(
                    Change(
                        action="unsupported",
                        object_type=object_type,
                        name=object_type,
                        desired={"value": desired},
                        reason="parsed entry is not an object",
                    )
                )
                continue

            name = desired.get("name")
            if not name:
                unsupported.append(
                    Change(
                        action="unsupported",
                        object_type=object_type,
                        name="",
                        desired=desired,
                        reason="parsed entry is missing a name",
                    )
                )
                continue

            if name in seen_names:
                conflicts.append(
                    Change(
                        action="conflict",
                        object_type=object_type,
                        name=name,
                        desired=desired,
                        reason="duplicate desired object name",
                    )
                )
                continue
            seen_names.add(name)

            current = current_by_name.get(name)
            if current is None:
                creates.append(Change("create", object_type, name, desired=desired))
                continue

            if _normalize(desired) == _normalize(current):
                skips.append(Change("skip", object_type, name, desired=desired, current=current))
            elif conflict_policy == "replace":
                updates.append(
                    Change(
                        "update",
                        object_type,
                        name,
                        desired=desired,
                        current=current,
                        reason="desired object differs from current object",
                    )
                )
            elif conflict_policy == "ignore":
                skips.append(
                    Change(
                        "skip",
                        object_type,
                        name,
                        desired=desired,
                        current=current,
                        reason="desired object differs and conflict_policy=ignore",
                    )
                )
            else:
                conflicts.append(
                    Change(
                        "conflict",
                        object_type,
                        name,
                        desired=desired,
                        current=current,
                        reason="desired object differs from current object",
                    )
                )

    return MigrationPlan(
        creates=creates,
        updates=updates,
        skips=skips,
        conflicts=conflicts,
        unsupported=unsupported,
    )


def _normalize(value: Any) -> Any:
    """Normalize API payloads enough for deterministic dry-run comparison."""

    if isinstance(value, dict):
        ignored_keys = {"id", "folder", "snippet", "device"}
        return {
            key: _normalize(item)
            for key, item in sorted(value.items())
            if key not in ignored_keys and item not in (None, [], {})
        }
    if isinstance(value, list):
        return sorted((_normalize(item) for item in value), key=repr)
    return value


def _serialize_changes(changes: list[Change]) -> list[dict[str, Any]]:
    return [
        change.to_dict()
        for change in sorted(changes, key=lambda item: (item.object_type, item.name, item.action))
    ]
