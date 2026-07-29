"""Dry-run migration planner.

The planner compares parsed configuration payloads with current SCM objects and
returns an explicit plan. It intentionally has no network or credential access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from scm.process import NETWORK_OBJECT_DEPENDENCY_ORDER


ParsedData = Mapping[str, list[dict[str, Any]]]
CurrentData = Mapping[str, list[dict[str, Any]]]

_POSTING_ORDER_INDEX = {
    object_type: index
    for index, object_type in enumerate(NETWORK_OBJECT_DEPENDENCY_ORDER)
}


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
class PlanWarning:
    """A non-blocking validation warning for schema-sensitive payloads."""

    object_type: str
    name: str
    message: str
    path: str = ""
    code: str = "schema-sensitive"
    severity: str = "warning"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "object_type": self.object_type,
            "name": self.name,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True)
class MigrationPlan:
    """Dry-run output grouped by operation type."""

    creates: list[Change] = field(default_factory=list)
    updates: list[Change] = field(default_factory=list)
    skips: list[Change] = field(default_factory=list)
    conflicts: list[Change] = field(default_factory=list)
    unsupported: list[Change] = field(default_factory=list)
    warnings: list[PlanWarning] = field(default_factory=list)

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
            "warnings": len(self.warnings),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "warning_summary": _warning_summary(self.warnings),
            "remediation": _remediation_report(self.warnings),
            "posting_preview": self.posting_preview(),
            "creates": _serialize_changes(self.creates),
            "updates": _serialize_changes(self.updates),
            "skips": _serialize_changes(self.skips),
            "conflicts": _serialize_changes(self.conflicts),
            "unsupported": _serialize_changes(self.unsupported),
            "warnings": _serialize_warnings(self.warnings),
        }

    def posting_preview(self) -> dict[str, list[dict[str, Any]]]:
        """Preview dependency-ordered create/update batches without payload details."""

        return {
            "creates": _posting_batches(self.creates),
            "updates": _posting_batches(self.updates),
        }


@dataclass(frozen=True)
class NetworkReport:
    """Offline report for parsed network payloads and migration warnings."""

    objects: dict[str, list[dict[str, Any]]]
    warnings: list[PlanWarning] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        summary = {
            object_type: len(entries)
            for object_type, entries in sorted(self.objects.items())
        }
        summary["warnings"] = len(self.warnings)
        return summary

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "warning_summary": _warning_summary(self.warnings),
            "remediation": _remediation_report(self.warnings),
            "objects": self.objects,
            "warnings": _serialize_warnings(self.warnings),
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
    warnings: list[PlanWarning] = []
    warnings.extend(_parser_warnings(parsed_data.get("_migration_warnings", [])))
    warnings.extend(_network_reference_warnings(parsed_data, current_data, selected_types))

    for object_type in selected_types:
        if object_type == "_migration_warnings":
            continue
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
                warnings.extend(_schema_warnings_for_entry(object_type, name, desired))
                continue

            if _normalize(desired) == _normalize(current):
                skips.append(Change("skip", object_type, name, desired=desired, current=current))
                warnings.extend(_schema_warnings_for_entry(object_type, name, desired))
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
                warnings.extend(_schema_warnings_for_entry(object_type, name, desired))
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
                warnings.extend(_schema_warnings_for_entry(object_type, name, desired))
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
                warnings.extend(_schema_warnings_for_entry(object_type, name, desired))

    return MigrationPlan(
        creates=creates,
        updates=updates,
        skips=skips,
        conflicts=conflicts,
        unsupported=unsupported,
        warnings=warnings,
    )


def build_network_report(
    parsed_data: ParsedData,
    object_types: list[str],
    current_data: CurrentData | None = None,
) -> NetworkReport:
    """Build an offline report for parsed network payloads without SCM comparison."""

    current_data = current_data or {}
    network_objects = {
        object_type: parsed_data.get(object_type, [])
        for object_type in object_types
        if object_type != "_migration_warnings"
    }
    warnings = _parser_warnings(parsed_data.get("_migration_warnings", []))
    warnings.extend(_network_reference_warnings(parsed_data, current_data, object_types))
    for object_type, entries in network_objects.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("name"):
                warnings.extend(_schema_warnings_for_entry(object_type, entry["name"], entry))

    return NetworkReport(objects=network_objects, warnings=warnings)


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


def _serialize_warnings(warnings: list[PlanWarning]) -> list[dict[str, Any]]:
    return [
        warning.to_dict()
        for warning in sorted(warnings, key=lambda item: (item.object_type, item.name, item.path, item.code))
    ]


def _warning_summary(warnings: list[PlanWarning]) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for warning in warnings:
        code_summary = summary.setdefault(
            warning.code,
            {
                "count": 0,
                "object_types": {},
            },
        )
        code_summary["count"] += 1
        object_types = code_summary["object_types"]
        object_types[warning.object_type] = object_types.get(warning.object_type, 0) + 1

    return {
        code: {
            "count": data["count"],
            "object_types": dict(sorted(data["object_types"].items())),
        }
        for code, data in sorted(summary.items())
    }


def _remediation_report(warnings: list[PlanWarning]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for warning in sorted(warnings, key=lambda item: (item.code, item.object_type, item.name, item.path)):
        code_group = grouped.setdefault(
            warning.code,
            {
                "code": warning.code,
                "count": 0,
                "action": _remediation_action(warning.code),
                "object_types": {},
                "examples": [],
            },
        )
        code_group["count"] += 1
        object_types = code_group["object_types"]
        object_types[warning.object_type] = object_types.get(warning.object_type, 0) + 1
        if len(code_group["examples"]) < 5:
            code_group["examples"].append(
                {
                    "object_type": warning.object_type,
                    "name": warning.name,
                    "path": warning.path,
                    "message": warning.message,
                }
            )

    return [
        {
            "code": code,
            "count": data["count"],
            "action": data["action"],
            "object_types": dict(sorted(data["object_types"].items())),
            "examples": data["examples"],
        }
        for code, data in sorted(grouped.items())
    ]


def _remediation_action(code: str) -> str:
    actions = {
        "missing-network-reference": (
            "Include the referenced network object type in the migration, add it to --current-data, "
            "or create it in the target SCM snippet before posting."
        ),
        "missing-policy-reference": (
            "Include referenced policy dependency objects such as zones, addresses, services, "
            "applications, schedules, profile groups, or decryption profiles, or provide them in --current-data."
        ),
        "unsupported-panos-routing-node": (
            "Review the source PAN-OS routing node and manually model the unsupported behavior in SCM Logical Router/ARE."
        ),
        "unsupported-panos-config-layout": (
            "Parse this XML with the matching --panos-config-type or extract the local firewall configuration before migration."
        ),
        "logical-router-static-route-option": (
            "Validate generated Logical Router static route options against the current SCM schema before posting."
        ),
        "logical-router-bgp-reference": (
            "Validate generated Logical Router BGP profile and route-map references against current SCM data before posting."
        ),
        "generated-bgp-filtering-profile": (
            "Review generated BGP filtering profiles from PAN-OS import/export policy before posting."
        ),
        "bgp-address-family-profile": (
            "Validate BGP address-family profile payloads against the current SCM schema before posting."
        ),
    }
    return actions.get(code, "Review the warning examples and validate the generated payload before posting.")


def _posting_batches(changes: list[Change]) -> list[dict[str, Any]]:
    names_by_type: dict[str, list[str]] = {}
    for change in changes:
        names_by_type.setdefault(change.object_type, []).append(change.name)

    batches = []
    for object_type in sorted(names_by_type, key=_posting_sort_key):
        names = sorted(names_by_type[object_type])
        batches.append(
            {
                "object_type": object_type,
                "count": len(names),
                "names": names,
            }
        )
    return batches


def _posting_sort_key(object_type: str) -> tuple[int, int, str]:
    if object_type in _POSTING_ORDER_INDEX:
        return (0, _POSTING_ORDER_INDEX[object_type], object_type)
    return (1, len(_POSTING_ORDER_INDEX), object_type)


def _parser_warnings(entries: Any) -> list[PlanWarning]:
    if not isinstance(entries, list):
        return []

    warnings = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        warnings.append(
            PlanWarning(
                object_type=entry.get("object_type", ""),
                name=entry.get("name", ""),
                path=entry.get("path", ""),
                code=entry.get("code", "parser-warning"),
                severity=entry.get("severity", "warning"),
                message=entry.get("message", ""),
            )
        )
    return warnings


def _schema_warnings_for_entry(object_type: str, name: str, desired: dict[str, Any]) -> list[PlanWarning]:
    warnings: list[PlanWarning] = []

    if object_type == "BgpFilteringProfile":
        warnings.append(
            PlanWarning(
                object_type=object_type,
                name=name,
                path="",
                code="generated-bgp-filtering-profile",
                message=(
                    "BGP filtering profile was generated from PAN-OS import/export policy artifacts; "
                    "validate route-map and network-filter references against SCM current data before posting."
                ),
            )
        )

    if object_type == "BgpAddressFamilyProfile":
        warnings.append(
            PlanWarning(
                object_type=object_type,
                name=name,
                path="",
                code="bgp-address-family-profile",
                message=(
                    "BGP address family profile fields are schema-sensitive and may vary by SCM release; "
                    "validate the generated payload with dry-run current data or a tenant response before posting."
                ),
            )
        )

    if object_type == "LogicalRouter":
        warnings.extend(_logical_router_schema_warnings(object_type, name, desired))

    return warnings


def _logical_router_schema_warnings(object_type: str, name: str, desired: dict[str, Any]) -> list[PlanWarning]:
    warnings: list[PlanWarning] = []
    for path, key, _ in _walk_payload(desired):
        if key in {"address_family_profile", "filtering_profile", "import_route_map", "export_route_map"}:
            warnings.append(
                PlanWarning(
                    object_type=object_type,
                    name=name,
                    path=path,
                    code="logical-router-bgp-reference",
                    message=(
                        f"Logical Router BGP field '{key}' is schema-sensitive; validate this peer "
                        "address-family reference against SCM current data before posting."
                    ),
                )
            )
        elif key in {"route_table", "option"} and ".routing_table." in path:
            warnings.append(
                PlanWarning(
                    object_type=object_type,
                    name=name,
                    path=path,
                    code="logical-router-static-route-option",
                    message=(
                        f"Static route field '{key}' is migrated from PAN-OS routing-table options; "
                        "validate the generated Logical Router static route payload before posting."
                    ),
                )
            )
    return warnings


def _network_reference_warnings(
    parsed_data: ParsedData,
    current_data: CurrentData,
    object_types: list[str],
) -> list[PlanWarning]:
    """Warn when generated network references are absent from desired/current data."""

    available_names = _merge_names_by_type(
        _names_by_type(parsed_data, allowed_types=set(object_types)),
        _names_by_type(current_data),
    )
    warnings: list[PlanWarning] = []
    seen: set[tuple[str, str, str, str, tuple[str, ...]]] = set()

    for object_type in object_types:
        if object_type == "_migration_warnings":
            continue
        entries = parsed_data.get(object_type, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not name:
                continue
            for path, key, value in _walk_payload(entry):
                if isinstance(value, list):
                    warnings.extend(
                        _missing_reference_warnings_for_values(
                            object_type,
                            name,
                            path,
                            key,
                            value,
                            available_names,
                            seen,
                        )
                    )
                    continue
                if not isinstance(value, str) or not value:
                    continue
                warnings.extend(
                    _missing_reference_warnings_for_values(
                        object_type,
                        name,
                        path,
                        key,
                        [value],
                        available_names,
                        seen,
                    )
                )

    return warnings


def _missing_reference_warnings_for_values(
    object_type: str,
    name: str,
    path: str,
    key: str,
    values: list[Any],
    available_names: dict[str, set[str]],
    seen: set[tuple[str, str, str, str, tuple[str, ...]]],
) -> list[PlanWarning]:
    target_types = _network_reference_targets(object_type, path, key)
    if not target_types:
        return []

    warnings = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value:
            continue
        if _is_builtin_reference(value):
            continue
        if any(value in available_names.get(target_type, set()) for target_type in target_types):
            continue

        value_path = path if len(values) == 1 else f"{path}[{index}]"
        dedupe_key = (object_type, name, value_path, value, target_types)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        target_label = " or ".join(target_types)
        warnings.append(
            PlanWarning(
                object_type=object_type,
                name=name,
                path=value_path,
                code=_reference_warning_code(object_type),
                message=(
                    f"Reference '{value}' was not found in generated payloads or current SCM data "
                    f"for {target_label}; include that object type in the migration or verify it "
                    "already exists in the target tenant before posting."
                ),
            )
        )
    return warnings


def _reference_warning_code(object_type: str) -> str:
    if object_type in _POLICY_REFERENCE_OBJECT_TYPES:
        return "missing-policy-reference"
    return "missing-network-reference"


def _names_by_type(
    data_map: Mapping[str, Any],
    allowed_types: set[str] | None = None,
) -> dict[str, set[str]]:
    names: dict[str, set[str]] = {}
    for object_type, entries in data_map.items():
        if object_type == "_migration_warnings" or not isinstance(entries, list):
            continue
        if allowed_types is not None and object_type not in allowed_types:
            continue
        object_names = names.setdefault(object_type, set())
        for entry in entries:
            if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                object_names.add(entry["name"])
            if isinstance(entry, dict) and isinstance(entry.get("default_value"), str):
                object_names.add(entry["default_value"])
    return names


def _merge_names_by_type(*name_maps: dict[str, set[str]]) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for name_map in name_maps:
        for object_type, names in name_map.items():
            merged.setdefault(object_type, set()).update(names)
    return merged


def _network_reference_targets(object_type: str, path: str, key: str) -> tuple[str, ...]:
    if object_type not in _REFERENCE_OBJECT_TYPES:
        return ()

    if key == "address_family_profile":
        return ("BgpAddressFamilyProfile",)
    if key == "filtering_profile":
        return ("BgpFilteringProfile",)
    if key == "authentication_profile":
        if ".ospf" in path:
            return ("OSPFAuthProfile",)
        if ".bgp" in path:
            return ("BgpAuthProfile",)
    if key in {"import_route_map", "export_route_map", "route_map"}:
        return ("BgpRouteMap", "BgpRouteMapRedistribution")
    if key in {"inbound", "outbound"} and ".route_maps." in path:
        return ("BgpRouteMap", "BgpRouteMapRedistribution")
    if key == "redistribution_profile" and ".bgp" in path:
        return ("BgpRedistributionProfile",)

    if object_type in {"BgpRouteMap", "BgpRouteMapRedistribution"}:
        if key == "prefix_list":
            return ("RoutePrefixList",)
        if key == "access_list":
            return ("RouteAccessList",)
        if key == "as_path_access_list":
            return ("RoutePathAccessList",)
        if key == "regular_community" and ".match." in path:
            return ("RouteCommunityList",)

    if object_type == "BgpFilteringProfile":
        if key == "prefix_list":
            return ("RoutePrefixList",)
        if key == "distribute_list":
            return ("RouteAccessList",)

    if object_type == "IKEGateway":
        if key == "ike_crypto_profile":
            return ("IKECryptoProfile",)

    if object_type == "IPsecTunnel":
        if key == "tunnel_interface":
            return ("TunnelInterface",)
        if key == "ipsec_crypto_profile":
            return ("IPsecCryptoProfile",)
        if key == "name" and "auto_key.ike_gateway[" in path:
            return ("IKEGateway",)

    if object_type == "Zones":
        if key in {"layer2", "layer3"} and "network." in path:
            return _INTERFACE_REFERENCE_TYPES

    if object_type == "LogicalRouter":
        if key == "interface":
            return _INTERFACE_REFERENCE_TYPES

    if object_type == "PbfRule":
        if key in {"egress_interface", "symmetric_return_interface"}:
            return _INTERFACE_REFERENCE_TYPES

    if object_type in _POLICY_REFERENCE_OBJECT_TYPES:
        if key in {"from", "to"}:
            return ("Zones",)
        if key in {"source", "destination", "translated_address"} and not _is_nat_type_path(path):
            return ("Address", "AddressGroup")
        if key == "service":
            return ("Service", "ServiceGroup")
        if key == "application" and object_type in {"app_override_pre_rules", "app_override_post_rules"}:
            return ("Application", "ApplicationGroup")
        if key == "schedule" and object_type in {
            "security_pre_rules",
            "security_post_rules",
            "decryption_pre_rules",
            "decryption_post_rules",
        }:
            return ("Schedule",)
        if key == "group" and path.endswith("profile_setting.group"):
            return ("ProfileGroup",)
        if key == "profile" and object_type in {"decryption_pre_rules", "decryption_post_rules"}:
            return ("DecryptionProfile",)
        if key == "translated_address" and _is_nat_type_path(path):
            return ("Address", "AddressGroup")

    return ()


def _is_nat_type_path(path: str) -> bool:
    return "translation" in path


def _is_builtin_reference(value: str) -> bool:
    lowered = value.lower()
    if lowered in _BUILTIN_REFERENCE_VALUES:
        return True
    if _looks_like_ip_or_cidr(value):
        return True
    return False


def _looks_like_ip_or_cidr(value: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


_NETWORK_REFERENCE_OBJECT_TYPES = {
    "BgpFilteringProfile",
    "BgpRedistributionProfile",
    "BgpRouteMap",
    "BgpRouteMapRedistribution",
    "IKEGateway",
    "IPsecTunnel",
    "LogicalRouter",
    "PbfRule",
    "Zones",
}

_POLICY_REFERENCE_OBJECT_TYPES = {
    "security_pre_rules",
    "security_post_rules",
    "app_override_pre_rules",
    "app_override_post_rules",
    "decryption_pre_rules",
    "decryption_post_rules",
    "nat_pre_rules",
    "nat_post_rules",
}

_REFERENCE_OBJECT_TYPES = _NETWORK_REFERENCE_OBJECT_TYPES | _POLICY_REFERENCE_OBJECT_TYPES

_INTERFACE_REFERENCE_TYPES = (
    "AggregateInterface",
    "EthernetInterface",
    "Layer2Subinterface",
    "Layer3Subinterface",
    "VlanInterface",
    "TunnelInterface",
    "LoopbackInterface",
)

_BUILTIN_REFERENCE_VALUES = {
    "any",
    "application-default",
    "default",
    "none",
}


def _walk_payload(value: Any, path: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            next_path = f"{path}.{key}" if path else key
            yield next_path, key, item
            yield from _walk_payload(item, next_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk_payload(item, f"{path}[{index}]")
