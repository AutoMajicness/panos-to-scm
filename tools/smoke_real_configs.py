"""Run sanitized parser/planner smoke checks against local PAN-OS XML files."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from main import (
    load_current_data,
    strict_local_firewall_warning_settings,
    validation_summary,
)
from migration import build_plan
from parse.parse_panos import XMLParser


DEFAULT_CONFIG_DIR = Path("/home/hawkinsd/As-Built_Document_Helper")


def discover_xml_configs(config_dir: Path, limit: int = 0) -> list[Path]:
    configs = sorted(path for path in config_dir.rglob("*.xml") if path.is_file())
    if limit > 0:
        return configs[:limit]
    return configs


def run_smoke(
    config_paths: list[Path],
    current_data: dict[str, list[dict[str, Any]]] | None = None,
    strict_local_firewall: bool = False,
    fail_on_blockers: bool = False,
) -> dict[str, Any]:
    current_data = current_data or {}
    warnings_as_errors, warning_codes = strict_local_firewall_warning_settings(
        strict_local_firewall=strict_local_firewall,
    )
    results = []

    for config_path in config_paths:
        results.append(
            smoke_one_config(
                config_path,
                current_data=current_data,
                warnings_as_errors=warnings_as_errors,
                warning_codes=warning_codes,
            )
        )

    totals = {
        "configs": len(results),
        "ok": sum(1 for result in results if result["status"] == "ok"),
        "errors": sum(1 for result in results if result["status"] == "error"),
        "blockers": sum(result.get("validation_summary", {}).get("blockers", 0) for result in results),
        "warnings": sum(result.get("validation_summary", {}).get("warnings", 0) for result in results),
    }
    exit_code = 1 if totals["errors"] or (fail_on_blockers and totals["blockers"]) else 0

    return {
        "summary": totals,
        "strict_local_firewall": strict_local_firewall,
        "fail_on_blockers": fail_on_blockers,
        "exit_code": exit_code,
        "results": results,
    }


def smoke_one_config(
    config_path: Path,
    current_data: dict[str, list[dict[str, Any]]],
    warnings_as_errors: bool,
    warning_codes: set[str],
) -> dict[str, Any]:
    try:
        parsed = XMLParser(str(config_path), "local").parse_all()
        plan = build_plan(parsed, current_data=current_data)
        plan_dict = plan.to_dict()
        return {
            "path": str(config_path),
            "status": "ok",
            "parsed_object_counts": _parsed_object_counts(parsed),
            "validation_summary": validation_summary(
                plan,
                warnings_as_errors=warnings_as_errors,
                warning_codes=warning_codes,
            ),
            "warning_summary": plan_dict["warning_summary"],
            "remediation": plan_dict["remediation"],
            "warning_codes": sorted({warning.code for warning in plan.warnings}),
        }
    except Exception as err:
        return {
            "path": str(config_path),
            "status": "error",
            "error": f"{type(err).__name__}: {err}",
        }


def _parsed_object_counts(parsed: dict[str, Any]) -> dict[str, int]:
    counts = {}
    for object_type, entries in parsed.items():
        if object_type == "_migration_warnings":
            counts[object_type] = len(entries) if isinstance(entries, list) else 0
        elif isinstance(entries, list) and entries:
            counts[object_type] = len(entries)
    return dict(sorted(counts.items()))


def write_report(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, sort_keys=True)
        file.write("\n")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=DEFAULT_CONFIG_DIR,
        help=f"Directory to recursively scan for PAN-OS XML files. Defaults to {DEFAULT_CONFIG_DIR}.",
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        action="append",
        default=[],
        help="Specific PAN-OS XML file to smoke. Can be supplied multiple times.",
    )
    parser.add_argument("--output", type=Path, default=Path("smoke-real-configs.json"))
    parser.add_argument("--limit", type=int, default=0, help="Maximum discovered XML configs to process.")
    parser.add_argument("--current-data", default="", help="Optional current SCM data JSON.")
    parser.add_argument("--strict-local-firewall", action="store_true")
    parser.add_argument("--fail-on-blockers", action="store_true")
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()
    config_paths = args.config_file or discover_xml_configs(args.config_dir, limit=args.limit)
    current_data = load_current_data(args.current_data)
    report = run_smoke(
        config_paths,
        current_data=current_data,
        strict_local_firewall=args.strict_local_firewall,
        fail_on_blockers=args.fail_on_blockers,
    )
    write_report(report, args.output)
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
