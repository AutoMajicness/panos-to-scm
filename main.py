import logging
from logging.handlers import TimedRotatingFileHandler
import time
import os
from config import AppConfig, ConfigurationManager
from parse.parse_panos import XMLParser
from parse.parse_cisco import CiscoParser
from parse.parse_pfsense import PfSenseParser
from scm.process import Processor, SCMObjectManager
from migration import build_network_report, build_plan
import scm.obj as obj
import argparse
import json
import sys
import getpass
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import re

logger = logging.getLogger(__name__)


STRICT_LOCAL_FIREWALL_WARNING_CODES = {
    "missing-network-reference",
    "missing-policy-reference",
    "unsupported-panos-config-layout",
    "unsupported-panos-routing-node",
}

CURRENT_DATA_KEY_ALIASES = {
    "address": "Address",
    "addresses": "Address",
    "addressgroup": "AddressGroup",
    "addressgroups": "AddressGroup",
    "address-group": "AddressGroup",
    "address-groups": "AddressGroup",
    "service": "Service",
    "services": "Service",
    "servicegroup": "ServiceGroup",
    "servicegroups": "ServiceGroup",
    "service-group": "ServiceGroup",
    "service-groups": "ServiceGroup",
    "application": "Application",
    "applications": "Application",
    "applicationgroup": "ApplicationGroup",
    "applicationgroups": "ApplicationGroup",
    "application-group": "ApplicationGroup",
    "application-groups": "ApplicationGroup",
    "profilegroup": "ProfileGroup",
    "profilegroups": "ProfileGroup",
    "profile-group": "ProfileGroup",
    "profile-groups": "ProfileGroup",
    "decryptionprofile": "DecryptionProfile",
    "decryptionprofiles": "DecryptionProfile",
    "decryption-profile": "DecryptionProfile",
    "decryption-profiles": "DecryptionProfile",
    "zone": "Zones",
    "zones": "Zones",
    "schedule": "Schedule",
    "schedules": "Schedule",
}

POLICY_DEPENDENCY_OBJECT_TYPE_NAMES = [
    "Address",
    "AddressGroup",
    "Application",
    "ApplicationGroup",
    "DecryptionProfile",
    "ProfileGroup",
    "Schedule",
    "Service",
    "ServiceGroup",
    "Zones",
]


class CliError(Exception):
    """Raised for invalid non-interactive CLI usage."""

def setup_logging(log_path="debug-log.txt"):
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)

    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = TimedRotatingFileHandler(str(log_path), utc=True, when="midnight", interval=1, backupCount=1)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)


_GENERIC_CUSTOMER_NAMES = {
    "", "running_config", "running-config", "config", "configuration",
    "input", "sample", "parsed", "current-data",
}


def _safe_customer_name(value):
    """Convert an inferred customer identifier into a safe readable folder name."""
    value = str(value or "").strip()
    if value.lower().startswith(("folder:", "snippet:", "device:")):
        value = value.split(":", 1)[1].strip()
    value = re.sub(r"\.(?:xml|json|txt|conf|cfg)$", "", value, flags=re.IGNORECASE).strip()
    if value.lower() in _GENERIC_CUSTOMER_NAMES:
        return ""
    value = re.sub(r"[^A-Za-z0-9._ -]+", "_", value)
    value = re.sub(r"\s+", " ", value).strip(" ._-")
    return value or ""


def infer_customer_name(*, target_folder="", config_file="", json_file=""):
    """Infer a customer folder name from the most customer-specific input."""
    candidates = [
        target_folder,
        Path(config_file).name if config_file else "",
        Path(json_file).name if json_file else "",
    ]
    for candidate in candidates:
        name = _safe_customer_name(candidate)
        if name:
            return name
    return "SCM_Customer"


def resolve_output_directory(*, output_folder="", target_folder="", config_file="", json_file="", cwd=None):
    """Return and create the single directory used for default artifacts."""
    base = Path(cwd) if cwd else Path.cwd()
    output_dir = Path(output_folder) if output_folder else base / infer_customer_name(
        target_folder=target_folder,
        config_file=config_file,
        json_file=json_file,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def default_output_path(output_dir, explicit_path, filename):
    """Use an explicit artifact path or place the default filename in output_dir."""
    return str(Path(explicit_path)) if explicit_path else str(Path(output_dir) / filename)

def scope_param_from_cli(scope_arg):
    try:
        scope_type, scope_value = scope_arg.split(':', 1)
    except ValueError as err:
        raise CliError("Scope must use the format '<folder|snippet|device>:<value>'") from err

    from scm.scope import Scope

    return f"&{Scope(scope_type, scope_value).scope_type}={scope_value}"


def prompt_for_scope(prompt_label):
    scope_type = input("Do you want to use a folder, snippet, or device? Enter 'folder', 'snippet', or 'device': ").strip().lower()
    scope_value = input(prompt_label.format(scope_type=scope_type)).strip()
    return f"&{scope_type}={scope_value}"


def require_scope(scope_arg, interactive, prompt_label):
    if scope_arg:
        return scope_param_from_cli(scope_arg)
    if interactive:
        return prompt_for_scope(prompt_label)
    raise CliError("Missing required --scope. Use a value like --scope folder:All")


def require_effective_scope(scope_arg, fallback_scope_arg, interactive, prompt_label, scope_flag, example_scope='folder:All'):
    if scope_arg:
        return scope_param_from_cli(scope_arg)
    if fallback_scope_arg:
        return scope_param_from_cli(fallback_scope_arg)
    if interactive:
        return prompt_for_scope(prompt_label)
    raise CliError(f"Missing required {scope_flag} or --scope. Use a value like {scope_flag} {example_scope}")


def get_network_obj_types(config):
    return getattr(config, 'network_obj_types', [])


def get_supported_obj_types(config):
    return config.obj_types + get_network_obj_types(config)


def split_selected_obj_types(config, run_objects_list):
    supported_obj_types = get_supported_obj_types(config)
    selected_obj_types = [obj_type for obj_type in supported_obj_types if obj_type.__name__ in run_objects_list] if run_objects_list else supported_obj_types
    network_type_names = {obj_type.__name__ for obj_type in get_network_obj_types(config)}
    regular_obj_types = [obj_type for obj_type in selected_obj_types if obj_type.__name__ not in network_type_names]
    network_obj_types = [obj_type for obj_type in selected_obj_types if obj_type.__name__ in network_type_names]
    return regular_obj_types, network_obj_types


def resolve_category_scopes(
    scope,
    object_scope,
    policy_scope,
    network_scope,
    interactive,
    needs_object_scope,
    needs_policy_scope,
    needs_network_scope,
):
    scopes = {}
    if needs_object_scope:
        scopes['object'] = require_effective_scope(
            object_scope,
            scope,
            interactive,
            'Enter the object {scope_type} name (Use "All" for "Global"): ',
            '--object-scope',
        )
    if needs_policy_scope:
        scopes['policy'] = require_effective_scope(
            policy_scope,
            scope,
            interactive,
            'Enter the policy {scope_type} name (Use "All" for "Global"): ',
            '--policy-scope',
        )
    if needs_network_scope:
        scopes['network'] = require_effective_scope(
            network_scope,
            scope,
            interactive,
            'Enter the network {scope_type} name (Use "All" for "Global"): ',
            '--network-scope',
            'snippet:Network-Stack',
        )
    return scopes


def resolve_folder_scope(
    api_session,
    target_folder="",
    target_snippet="",
    network_scope="",
    folder_path="",
    folder_id="",
    interactive=False,
    leaf_only=False,
    include_descendants=False,
):
    """Resolve a selected folder's effective hierarchy and linked snippets.

    By default this is the selected folder plus its ancestors. Descendants are
    separate configuration targets and are only included on explicit request.
    """
    from scm.setup import resolve_folder_hierarchy, resolve_snippets_from_folder

    try:
        result = resolve_folder_hierarchy(
            api_session,
            folder_name=target_folder,
            folder_path=folder_path,
            folder_id=folder_id,
            interactive=interactive,
        )
    except ValueError as err:
        raise CliError(str(err)) from err
    folder_chain = result["folders"][-1:] if leaf_only else result["folders"]
    collection_folders = list(folder_chain)
    if include_descendants:
        seen_folder_ids = set()
        for folder in collection_folders:
            folder_id = str(folder.get("id", ""))
            if folder_id:
                seen_folder_ids.add(folder_id)
        for folder_record in result.get("descendant_folders", []):
            leaf = folder_record.get("folders", [])[-1]
            folder_id = str(leaf.get("id", ""))
            if folder_id and folder_id in seen_folder_ids:
                continue
            if folder_id:
                seen_folder_ids.add(folder_id)
            collection_folders.append(leaf)

    direct_snippets = []
    snippets_by_folder = {}
    scope_nodes = []
    for folder in collection_folders:
        snippet_result = resolve_snippets_from_folder(folder)
        names = snippet_result["snippet_names"]
        folder_path = next(
            (
                record.get("path", "")
                for record in result.get("descendant_folders", [])
                if record.get("folder_ids", []) and record["folder_ids"][-1] == folder.get("id")
            ),
            "/".join(result["folder_names"]),
        )
        snippets_by_folder[folder_path] = names
        scope_nodes.append({
            "scope": f"&folder={folder['name']}",
            "source_type": "folder",
            "source_name": folder.get("name", ""),
            "source_id": folder.get("id", ""),
            "source_path": folder_path,
            "hierarchy_index": len(scope_nodes),
        })
        for snippet in snippet_result["snippets"]:
            name = snippet["name"]
            if name not in direct_snippets:
                direct_snippets.append(name)
            scope_nodes.append({
                "scope": f"&snippet={name}",
                "source_type": "snippet",
                "source_name": name,
                "source_id": "",
                "source_path": folder_path,
                "hierarchy_index": len(scope_nodes),
                "association_priority": snippet.get("priority"),
            })
    if target_snippet:
        names = [target_snippet]
    elif network_scope:
        names = [scope_resource_name(network_scope, "snippet") or network_scope]
    else:
        names = direct_snippets
    if not names:
        raise CliError(f"SCM folder '{result['path']}' has no associated snippets")
    return {
        **result,
        "collection_folders": collection_folders,
        "snippet_names": names,
        "network_scopes": [node["scope"] for node in scope_nodes if node["scope"].startswith("&snippet=")],
        "snippets_by_folder": snippets_by_folder,
        "scope_nodes": scope_nodes,
        # Keep the CLI form separate from the internal API query form.  The
        # category resolver accepts folder:<name>; managers consume &folder=<name>.
        "folder_scope": f"folder:{result['folder']['name']}",
        "folder_scope_param": f"&folder={result['folder']['name']}",
    }


def merge_scoped_snapshot_results(results, include_provenance=False, dedupe_names=True):
    """Merge ordered per-snippet snapshots, retaining higher-priority values."""
    merged = {}
    for source, snapshot in results:
        scope_name = source.get("scope", "") if isinstance(source, dict) else source
        for object_type, entries in snapshot.items():
            destination = merged.setdefault(object_type, [])
            existing_names = {entry.get("name") for entry in destination if isinstance(entry, dict)}
            for entry in entries:
                if not isinstance(entry, dict):
                    destination.append(entry)
                    continue
                name = entry.get("name")
                if dedupe_names and name and name in existing_names:
                    continue
                enriched = dict(entry)
                if include_provenance:
                    enriched.setdefault("_scm_scope", scope_name)
                    if isinstance(source, dict):
                        enriched.setdefault("_scm_provenance", {
                            key: value for key, value in source.items() if key != "scope"
                        })
                destination.append(enriched)
                if dedupe_names and name:
                    existing_names.add(name)
    return merged


def scope_resource_name(scope, resource_type):
    """Return the named folder/snippet from a typed SCM scope."""
    prefix = f"{resource_type}:"
    if isinstance(scope, str) and scope.startswith(prefix):
        value = scope[len(prefix):].strip()
        return value or None
    return None


def prepare_import_target(
    api_session,
    scopes,
    target_folder,
    target_snippet,
    parent_folder,
    associate_snippet,
):
    """Create missing local-firewall import resources and return the setup result."""
    folder_name = target_folder or scope_resource_name(scopes.get("object"), "folder")
    policy_folder = scope_resource_name(scopes.get("policy"), "folder")
    if not folder_name and policy_folder:
        folder_name = policy_folder
    snippet_name = target_snippet or scope_resource_name(scopes.get("network"), "snippet")

    # A caller may intentionally use different scopes for different categories.
    # Only auto-provision when the import has a complete folder/snippet target.
    if not folder_name or not snippet_name:
        return None

    from scm.setup import SetupTargetRequest, ensure_setup_target

    result = ensure_setup_target(
        api_session,
        SetupTargetRequest(
            folder_name=folder_name,
            snippet_name=snippet_name,
            parent_folder=parent_folder,
            associate_snippet=associate_snippet,
            create=True,
        ),
    )
    if not result["summary"]["ready"]:
        raise CliError(
            "SCM import target is not ready: "
            + ", ".join(result["summary"].get("missing", []))
        )
    logger.info("SCM import target verified: %s", json.dumps(result["summary"], sort_keys=True))
    return result


def infer_panos_config_type(file_path):
    with open(file_path, "r", encoding="utf-8", errors="replace") as file:
        sample = file.read(12000).lstrip()
    if sample.startswith("config {") or "config {" in sample[:1200]:
        return "local"
    root = ET.parse(file_path).getroot()
    if root.find('.//devices/entry/device-group') is not None:
        raise CliError(
            "PAN-OS XML appears to contain Panorama device-groups. "
            "Specify --panos-config-type panorama/shared or panorama/device-group."
        )
    return 'local'


def get_file_path_and_type(config, logger, parser_type=None, config_file="", fetch_panos_config=False, interactive=False):
    if parser_type:
        config_choice = parser_type
    elif interactive and os.path.exists('cisco_config.txt'):
        config_choice = input("Do you want to parse Cisco, PANOS, or pfSense configuration? (cisco/panos/pfsense): ").strip().lower()
    else:
        config_choice = 'panos'

    if config_choice not in {'panos', 'cisco', 'pfsense'}:
        raise CliError("--parser must be 'panos', 'cisco', or 'pfsense'")

    if config_choice == 'panos':
        if interactive and not fetch_panos_config and not config_file:
            user_choice = input("Do you want to retrieve new config from Palo Alto NGFW? (yes/no): ").strip().lower()
            fetch_panos_config = user_choice == 'yes'

        file_path = config_file or "running_config.xml"

        if fetch_panos_config:
            from api.palo_token import PaloToken
            from panos import PaloConfigManager

            palo_token_manager = PaloToken()
            token = palo_token_manager.retrieve_token()
            palo_config_manager = PaloConfigManager(token, palo_token_manager.ngfw_url)
            running_config = palo_config_manager.get_running_config()

            with open(file_path, "w") as file:
                file.write(running_config)
            logger.info("New running configuration retrieved and saved.")
        else:
            file_path = config_file or config.xml_file_path
            logger.info(f"Using local XML file: {file_path}")
    elif config_choice == 'cisco':
        file_path = config_file or config.cisco_file_path
        logger.info(f"Using Cisco configuration file: {file_path}")
    else:
        file_path = config_file or "config.xml"
        logger.info(f"Using pfSense configuration file: {file_path}")

    return file_path, config_choice

def prompt_scm_credentials():
    """Prompt for per-run SCM credentials without persisting them."""
    print("Enter SCM credentials for this run. They will not be saved.")
    tenant_id = input("SCM Tenant ID: ").strip()
    client_id = input("SCM Client ID: ").strip()
    client_secret = getpass.getpass("SCM Client Secret: ").strip()
    missing = [
        label
        for label, value in (
            ("Tenant ID", tenant_id),
            ("Client ID", client_id),
            ("Client Secret", client_secret),
        )
        if not value
    ]
    if missing:
        raise CliError("Missing SCM credential value(s): " + ", ".join(missing))
    return {
        "tsg_id": tenant_id,
        "client_id": client_id,
        "client_secret": client_secret,
    }


def initialize_api_session(*, use_config=False):
    from api import PanApiSession

    runtime_config = None
    if sys.stdin.isatty() and not use_config:
        runtime_config = prompt_scm_credentials()
    session = PanApiSession(runtime_config=runtime_config)
    session.authenticate()
    return session

def setup_scm_object_manager(session, obj_types, sec_obj, nat_obj, scope_param, conflict_policy="fail", interactive=False):
    return SCMObjectManager(
        session,
        scope_param,
        obj,
        obj_types,
        sec_obj,
        nat_obj,
        conflict_policy=conflict_policy,
        interactive=interactive,
    )

def process_obj_types(api_session, selected_obj_types, parsed_data, scope_param, device_group_name, config, conflict_policy="fail", interactive=False, current_data=None):
    if not selected_obj_types:
        return None
    scm_obj_manager = setup_scm_object_manager(
        api_session,
        selected_obj_types,
        config.sec_obj,
        config.nat_obj,
        scope_param,
        conflict_policy=conflict_policy,
        interactive=interactive,
    )
    scm_obj_manager.process_objects(
        parsed_data,
        scope_param,
        device_group_name,
        max_workers=6,
        limit=config.limit,
        current_data=current_data,
    )
    return scm_obj_manager


def selected_type_names_for_plan(
    parsed_data,
    selected_obj_types,
    run_all=False,
    run_security=False,
    run_app_override=False,
    run_decrypt_rules=False,
    run_nat=False,
    include_selected_objects=False,
):
    if run_all:
        return list(parsed_data.keys())
    if include_selected_objects and any([run_security, run_app_override, run_decrypt_rules, run_nat]):
        selected = [obj_type.__name__ for obj_type in selected_obj_types]
        selected.extend(
            name
            for name in selected_policy_type_names(
                run_security=run_security,
                run_app_override=run_app_override,
                run_decrypt_rules=run_decrypt_rules,
                run_nat=run_nat,
            )
            if name not in selected
        )
        return selected
    if run_security:
        return ['security_pre_rules', 'security_post_rules']
    if run_app_override:
        return ['app_override_pre_rules', 'app_override_post_rules']
    if run_decrypt_rules:
        return ['decryption_pre_rules', 'decryption_post_rules']
    if run_nat:
        return ['nat_pre_rules', 'nat_post_rules']
    return [obj_type.__name__ for obj_type in selected_obj_types]


def selected_type_names_for_parse(
    run_objects_list,
    run_all=False,
    run_security=False,
    run_app_override=False,
    run_decrypt_rules=False,
    run_nat=False,
):
    if run_all or not run_objects_list:
        return run_objects_list

    selected = list(dict.fromkeys(run_objects_list))
    selected.extend(
        name
        for name in selected_policy_type_names(
            run_security=run_security,
            run_app_override=run_app_override,
            run_decrypt_rules=run_decrypt_rules,
            run_nat=run_nat,
        )
        if name not in selected
    )
    return selected


def load_current_data(current_data_file):
    if not current_data_file:
        return {}
    try:
        with open(current_data_file, 'r') as file:
            return normalize_current_data(json.load(file))
    except Exception as err:
        logger.error(f"Error while loading current data json file {err}")
        sys.exit(1)


def normalize_current_data(current_data):
    if not isinstance(current_data, dict):
        return {}

    normalized = {}
    if isinstance(current_data.get("data"), list):
        _add_current_entries(normalized, "data", current_data["data"])

    for key, value in current_data.items():
        if key == "data":
            continue
        entries = _extract_current_entries(value)
        if entries is None:
            continue
        _add_current_entries(normalized, key, entries)

    return normalized


def _extract_current_entries(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        return value["data"]
    return None


def _add_current_entries(normalized, key, entries):
    fallback_type = canonical_current_data_key(key)
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        object_type = canonical_current_data_key(
            entry.get("object_type")
            or entry.get("type")
            or entry.get("@type")
            or fallback_type
        )
        if not object_type:
            continue
        normalized.setdefault(object_type, []).append(entry)


def canonical_current_data_key(key):
    if not isinstance(key, str) or not key:
        return ""
    if key in CURRENT_DATA_KEY_ALIASES.values():
        return key
    key = key.rstrip("/").split("/")[-1]
    normalized_key = key.replace("_", "-").strip().lower()
    return CURRENT_DATA_KEY_ALIASES.get(normalized_key, key)


def write_plan_output(plan, plan_output, label):
    if not plan_output:
        return
    try:
        Path(plan_output).parent.mkdir(parents=True, exist_ok=True)
        with open(plan_output, 'w') as file:
            json.dump(plan.to_dict(), file, indent=2, sort_keys=True)
            file.write('\n')
    except Exception as err:
        logger.error(f"Error while writing plan output json file {err}")
        sys.exit(1)
    logger.info(f"{label} written to {plan_output}")


def write_remediation_output(report_source, remediation_output, label):
    if not remediation_output:
        return
    write_json_file(remediation_output, report_source.to_dict()["remediation"], label)


def write_json_file(output_path, payload, label):
    if not output_path:
        raise CliError(f"{label} output path is required")
    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as file:
            json.dump(payload, file, indent=2, sort_keys=True)
            file.write('\n')
    except Exception as err:
        logger.error(f"Error while writing {label} json file {err}")
        sys.exit(1)
    logger.info(f"{label} written to {output_path}")


def build_current_data_snapshot(api_session, selected_obj_types, scope_param, config):
    manager = setup_scm_object_manager(
        api_session,
        selected_obj_types,
        config.sec_obj,
        config.nat_obj,
        scope_param,
    )
    current_objects = manager.get_current_objects(manager.obj_types, max_workers=6, limit=config.limit)
    snapshot = {
        obj_type.__name__: current_objects.get(obj_type, [])
        for obj_type in manager.obj_types
    }
    if manager.fetch_failures:
        snapshot["fetch_failures"] = list(manager.fetch_failures)
    return snapshot


def _device_folder_values(device):
    """Return normalized folder identifiers exposed by an SCM device record."""
    values = []
    for key in ("folder", "folder_name", "folder_path", "folder_id", "parent_folder"):
        value = device.get(key)
        if isinstance(value, dict):
            value = value.get("id") or value.get("name") or value.get("path")
        if isinstance(value, list):
            values.extend(str(item).strip() for item in value if item)
        elif value:
            values.append(str(value).strip())
    folders = device.get("folders")
    if isinstance(folders, list):
        for item in folders:
            if isinstance(item, dict):
                item = item.get("id") or item.get("name") or item.get("path")
            if item:
                values.append(str(item).strip())
    return {value for value in values if value}


def collect_device_inventory(api_session, folder_resolution=None, limit=200):
    """Collect SCM onboarded-device inventory and optionally filter by folder hierarchy."""
    endpoint = "/config/setup/v1/devices"
    devices = []
    failures = []
    offset = 0
    while True:
        try:
            page = api_session.get(endpoint, params={"limit": limit, "offset": offset})
        except Exception as exc:  # noqa: BLE001
            failures.append({
                "object_type": "DeviceInventory",
                "endpoint": endpoint,
                "scope": "setup",
                "error": str(exc),
            })
            break
        if not isinstance(page, list):
            page = []
        devices.extend(item for item in page if isinstance(item, dict))
        if len(page) < limit:
            break
        offset += limit

    if not folder_resolution:
        return devices, failures

    records = folder_resolution.get("descendant_folders", [])
    folder_names = set(folder_resolution.get("folder_names", []))
    folder_ids = set(folder_resolution.get("folder_ids", []))
    folder_paths = set()
    for record in records:
        folder_names.update(record.get("folder_names", []))
        folder_ids.update(record.get("folder_ids", []))
        if record.get("path"):
            folder_paths.add(record["path"])

    filtered = []
    for device in devices:
        values = _device_folder_values(device)
        if not values or values.intersection(folder_names | folder_ids | folder_paths):
            filtered.append(device)
    return filtered, failures


def _snapshot_scope_label(scope_param):
    """Convert an internal SCM query scope to the public CLI form."""
    text = str(scope_param or "").lstrip("&")
    if "=" not in text:
        return text
    scope_type, scope_value = text.split("=", 1)
    return f"{scope_type}:{scope_value}"


def build_policy_snapshot(api_session, policy_scope, config, limit="10000"):
    """Fetch SCM policy rulebases in their current pre/post order."""
    def _rule_payloads(entries):
        """Exclude folder/snippet container records returned by rule endpoints."""
        rule_fields = {
            "action", "from", "to", "source", "destination", "service",
            "application", "category", "source_translation",
            "destination_translation", "position", "disabled", "description",
        }
        return [
            item for item in entries
            if isinstance(item, dict) and item.get("name")
            and any(field in item for field in rule_fields)
        ]
    manager = setup_scm_object_manager(
        api_session,
        [],
        config.sec_obj,
        config.nat_obj,
        policy_scope,
    )
    policy_types = (
        ("security", config.sec_obj),
        ("nat", config.nat_obj),
        ("decryption", config.decryption_rule_obj),
        ("app_override", config.app_override_obj),
    )
    snapshot = {}
    fetch_failures = []
    for label, rule_type in policy_types:
        for position in ("pre", "post"):
            key = f"{label}_pre_rules" if position == "pre" else f"{label}_post_rules"
            try:
                snapshot[key] = _rule_payloads(manager.fetch_rules(rule_type, limit=limit, position=position))
            except Exception as exc:  # noqa: BLE001
                snapshot[key] = []
                failure = {
                    "object_type": rule_type.__name__,
                    "position": position,
                    "scope": policy_scope,
                    "error": str(exc),
                }
                fetch_failures.append(failure)
                manager.logger.error(
                    "Unable to fetch current %s %s rules from SCM; continuing with an empty rulebase: %s",
                    label,
                    position,
                    exc,
                )
    return snapshot, fetch_failures


def parse_warning_codes(warning_codes):
    if not warning_codes:
        return set()
    return {
        warning_code.strip()
        for warning_code in warning_codes.split(',')
        if warning_code.strip()
    }


def strict_local_firewall_warning_settings(warnings_as_errors=False, warning_codes="", strict_local_firewall=False):
    warning_code_filter = parse_warning_codes(warning_codes)
    if strict_local_firewall:
        warning_code_filter.update(STRICT_LOCAL_FIREWALL_WARNING_CODES)
        warnings_as_errors = True
    return warnings_as_errors, warning_code_filter


def warning_blocker_count(plan, warnings_as_errors=False, warning_codes=None):
    if not warnings_as_errors:
        return 0
    warning_codes = warning_codes or set()
    if not warning_codes:
        return len(plan.warnings)
    return sum(1 for warning in plan.warnings if warning.code in warning_codes)


def validation_blocker_count(plan, warnings_as_errors=False, warning_codes=None):
    return (
        len(plan.conflicts)
        + len(plan.unsupported)
        + warning_blocker_count(plan, warnings_as_errors, warning_codes)
    )


def validation_summary(plan, warnings_as_errors=False, warning_codes=None):
    summary = plan.summary()
    summary["warning_blockers"] = warning_blocker_count(plan, warnings_as_errors, warning_codes)
    summary["blockers"] = validation_blocker_count(plan, warnings_as_errors, warning_codes)
    return summary


def selected_policy_type_names(
    run_all=False,
    run_security=False,
    run_app_override=False,
    run_decrypt_rules=False,
    run_nat=False,
):
    selected = []
    if run_all or run_security:
        selected.extend(['security_pre_rules', 'security_post_rules'])
    if run_all or run_app_override:
        selected.extend(['app_override_pre_rules', 'app_override_post_rules'])
    if run_all or run_decrypt_rules:
        selected.extend(['decryption_pre_rules', 'decryption_post_rules'])
    if run_all or run_nat:
        selected.extend(['nat_pre_rules', 'nat_post_rules'])
    return selected


def should_default_full_import(
    *,
    parser_type,
    config_file,
    fetch_panos_config,
    run_objects,
    run_security,
    run_app_override,
    run_decrypt_rules,
    run_nat,
    run_all,
):
    """Use the complete local-firewall migration when no selection was supplied."""

    if run_objects or run_security or run_app_override or run_decrypt_rules or run_nat or run_all:
        return False
    if parser_type not in (None, "panos", "pfsense"):
        return False
    return fetch_panos_config or config_file.lower().endswith(".xml")


def validate_post_plan(
    parsed_data,
    current_data,
    object_type_names,
    conflict_policy,
    warnings_as_errors,
    warning_codes,
    label,
):
    if not object_type_names:
        return None
    plan = build_plan(
        parsed_data,
        current_data=current_data,
        object_types=object_type_names,
        conflict_policy=conflict_policy,
    )
    summary = validation_summary(
        plan,
        warnings_as_errors=warnings_as_errors,
        warning_codes=warning_codes,
    )
    logger.info(f"{label} validation summary: {json.dumps(summary, sort_keys=True)}")
    if summary["blockers"]:
        print(json.dumps(summary, indent=2, sort_keys=True))
        sys.exit(1)
    return plan


def write_live_plan_output(validation_plans, plan_output):
    if not plan_output:
        return
    payload = {
        "mode": "live-post",
        "validation_plans": {
            label: plan.to_dict()
            for label, plan in validation_plans.items()
        },
    }
    write_json_file(plan_output, payload, "Live validation plan")


def write_live_remediation_output(validation_plans, remediation_output):
    if not remediation_output:
        return
    remediation = []
    for label, plan in validation_plans.items():
        for item in plan.to_dict()["remediation"]:
            remediation.append({"phase": label, **item})
    write_json_file(remediation_output, remediation, "Live remediation report")


def build_snapshot_summary(api_session, selected_obj_types, scope_param, config, parsed_data=None):
    if not selected_obj_types:
        return {"counts": {}, "fetch_failures": []}
    manager = setup_scm_object_manager(
        api_session,
        selected_obj_types,
        config.sec_obj,
        config.nat_obj,
        scope_param,
    )
    current_objects = manager.get_current_objects(
        manager.obj_types,
        max_workers=6,
        limit=config.limit,
        parsed_data=parsed_data,
    )
    return {
        "counts": {
            obj_type.__name__: len(current_objects.get(obj_type, []))
            for obj_type in manager.obj_types
        },
        "fetch_failures": manager.fetch_failures,
    }


def build_live_report(
    *,
    api_session,
    config,
    file_path,
    scopes,
    selected_regular_obj_types,
    selected_network_obj_types,
    parsed_data=None,
    validation_plans,
    managers,
):
    object_snapshot = build_snapshot_summary(
        api_session,
        selected_regular_obj_types,
        scopes.get("object"),
        config,
        parsed_data=parsed_data,
    )
    network_snapshot = build_snapshot_summary(
        api_session,
        selected_network_obj_types,
        scopes.get("network"),
        config,
        parsed_data=parsed_data,
    )
    rule_order_verification = []
    fetch_failures = []
    for manager in managers:
        if not manager:
            continue
        rule_order_verification.extend(manager.rule_order_verification)
        fetch_failures.extend(manager.fetch_failures)
    fetch_failures.extend(object_snapshot["fetch_failures"])
    fetch_failures.extend(network_snapshot["fetch_failures"])
    fetch_failures = dedupe_fetch_failures(fetch_failures)

    summary = {
        "validation_phases": len(validation_plans),
        "object_snapshot_types": len(object_snapshot["counts"]),
        "network_snapshot_types": len(network_snapshot["counts"]),
        "rule_order_checks": len(rule_order_verification),
        "rule_order_verified": sum(1 for item in rule_order_verification if item["verified"]),
        "rule_order_unverified": sum(1 for item in rule_order_verification if not item["verified"]),
        "fetch_failures": len(fetch_failures),
    }
    return {
        "mode": "live-post",
        "source_config": file_path,
        "scopes": scopes,
        "summary": summary,
        "validation": {
            label: {
                "summary": validation_summary(plan),
                "warning_summary": plan.to_dict()["warning_summary"],
            }
            for label, plan in validation_plans.items()
        },
        "final_snapshots": {
            "objects": object_snapshot["counts"],
            "network": network_snapshot["counts"],
        },
        "rule_order_verification": rule_order_verification,
        "fetch_failures": fetch_failures,
    }


def markdown_report_path(file_path, output_dir=None):
    if not file_path or not file_path.lower().endswith(".xml"):
        return ""
    if output_dir:
        return str(Path(output_dir) / "migration-report.md")
    return os.path.splitext(file_path)[0] + ".md"


def _markdown_table(rows, headers):
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        values = [str(row.get(header, "")).replace("|", "\\|").replace("\n", " ") for header in headers]
        lines.append("| " + " | ".join(values) + " |")
    return lines


def write_markdown_import_report(
    *,
    file_path,
    parsed_data,
    scopes,
    validation_plans,
    live_report,
    output_dir=None,
):
    """Write an LLM-friendly import record in the resolved output directory."""

    output_path = markdown_report_path(file_path, output_dir=output_dir)
    if not output_path:
        return ""

    lines = [
        "# PAN-OS to Strata Cloud Manager Import Report",
        "",
        f"- Source configuration: `{file_path}`",
        f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
        "- Import mode: live SCM migration",
        "",
        "## Outcome",
        "",
    ]
    summary = live_report.get("summary", {})
    lines.extend(_markdown_table(
        [{"Metric": key, "Value": value} for key, value in sorted(summary.items())],
        ["Metric", "Value"],
    ))
    lines.extend(["", "## SCM Scopes", ""])
    lines.extend(_markdown_table(
        [{"Category": key, "Scope": value} for key, value in sorted(scopes.items())],
        ["Category", "Scope"],
    ))

    lines.extend(["", "## Parsed Configuration", ""])
    parsed_counts = [
        {"Object type": key, "Count": len(value)}
        for key, value in sorted(parsed_data.items())
        if key != "_migration_warnings" and isinstance(value, list) and value
    ]
    lines.extend(_markdown_table(parsed_counts, ["Object type", "Count"]) if parsed_counts else ["No parsed entries were present."])

    lines.extend(["", "## Validation and Changes", ""])
    for phase, plan in validation_plans.items():
        lines.extend([f"### {phase.title()}", ""])
        lines.extend(_markdown_table(
            [{"Metric": key, "Value": value} for key, value in sorted(plan.summary().items())],
            ["Metric", "Value"],
        ))
        for label, changes in (("Created", plan.creates), ("Updated", plan.updates), ("Skipped", plan.skips), ("Conflicts", plan.conflicts), ("Unsupported", plan.unsupported)):
            if not changes:
                continue
            lines.extend(["", f"#### {label}", ""])
            lines.extend(_markdown_table(
                [{"Object type": item.object_type, "Name": item.name, "Reason": item.reason} for item in changes],
                ["Object type", "Name", "Reason"],
            ))

        if plan.warnings:
            lines.extend(["", "#### Warnings", ""])
            lines.extend(_markdown_table(
                [{
                    "Code": warning.code,
                    "Classification": warning.classification,
                    "Object type": warning.object_type,
                    "Name": warning.name,
                    "Path": warning.path,
                    "Message": warning.message,
                } for warning in plan.warnings],
                ["Code", "Classification", "Object type", "Name", "Path", "Message"],
            ))

    lines.extend(["", "## Manual Follow-up", ""])
    remediation_items = []
    for plan in validation_plans.values():
        remediation_items.extend(plan.to_dict()["remediation"])
    if remediation_items:
        lines.extend(_markdown_table(
            [{
                "Code": item["code"],
                "Classification": item["classification"],
                "Count": item["count"],
                "Action": item["action"],
                "Examples": "; ".join(example["name"] for example in item["examples"]),
            } for item in remediation_items],
            ["Code", "Classification", "Count", "Action", "Examples"],
        ))
    else:
        lines.append("No validation remediation items were generated.")

    lines.extend(["", "## SCM Verification", ""])
    lines.extend(_markdown_table(
        [{"Category": category, "Object type": object_type, "Count": count}
         for category, objects in live_report.get("final_snapshots", {}).items()
         for object_type, count in sorted(objects.items())],
        ["Category", "Object type", "Count"],
    ) or ["No final SCM snapshot counts were available."])
    fetch_failures = live_report.get("fetch_failures", [])
    if fetch_failures:
        lines.extend(["", "### SCM Fetch Failures", ""])
        lines.extend(_markdown_table(fetch_failures, ["object_type", "scope", "error"]))
    lines.extend(["", "## Notes", "", "This report is designed as source material for LLM-generated PPTX, DOCX, remediation plans, and manual configuration checklists.", ""])

    try:
        with open(output_path, "w") as file:
            file.write("\n".join(lines))
    except OSError as err:
        logger.error(f"Error while writing Markdown import report {err}")
        return ""
    logger.info(f"Markdown import report written to {output_path}")
    return output_path


def dedupe_fetch_failures(fetch_failures):
    deduped = []
    seen = set()
    for item in fetch_failures:
        key = (
            item.get("object_type"),
            item.get("scope"),
            item.get("error"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped

def main(
    config,
    run_objects=None,
    run_security=False,
    run_app_override=False,
    run_decrypt_rules=False,
    run_nat=False,
    run_all=False,
    json_file="",
    dry_run=False,
    validate_only=False,
    snapshot_current_data=False,
    snapshot_output="",
    snapshot_policy=False,
    snapshot_policy_dependencies=False,
    output_folder="",
    setup_scm_target=False,
    create_scm_target=False,
    resolve_folder="",
    target_folder="",
    folder_path="",
    folder_id="",
    leaf_only=False,
    include_descendants=False,
    target_snippet="",
    parent_folder="ngfw-shared",
    associate_snippet=True,
    post_objects=False,
    post_policy=False,
    post_network=False,
    warnings_as_errors=False,
    warning_codes="",
    strict_local_firewall=False,
    network_report=False,
    conflict_policy="fail",
    plan_output="",
    report_output="",
    remediation_output="",
    current_data_file="",
    parser_type=None,
    config_file="",
    scope="",
    object_scope="",
    policy_scope="",
    network_scope="",
    fetch_panos_config=False,
    interactive=False,
    panos_config_type="",
    device_group_name="",
    use_config=False,
):
    try:
        start_time = time.time()
        file_path = json_file or config_file
        output_dir = resolve_output_directory(
            output_folder=output_folder,
            target_folder=target_folder or folder_path or folder_id,
            config_file=config_file or getattr(config, "xml_file_path", ""),
            json_file=json_file,
        )
        snapshot_output = default_output_path(output_dir, snapshot_output, "current-data.json") if snapshot_current_data else snapshot_output
        if network_report:
            report_output = default_output_path(output_dir, report_output, "network-report.json")
        elif snapshot_current_data and snapshot_policy:
            report_output = report_output
        if validate_only:
            plan_output = default_output_path(output_dir, plan_output, "validation-plan.json")
            remediation_output = default_output_path(output_dir, remediation_output, "remediation.json")
        elif dry_run:
            plan_output = default_output_path(output_dir, plan_output, "migration-plan.json")
            remediation_output = default_output_path(output_dir, remediation_output, "remediation.json")
        elif not snapshot_current_data and not network_report:
            plan_output = default_output_path(output_dir, plan_output, "live-validation-plan.json")
            remediation_output = default_output_path(output_dir, remediation_output, "live-remediation.json")
            report_output = default_output_path(output_dir, report_output, "live-report.json")
        if fetch_panos_config and not config_file:
            config_file = str(output_dir / "running_config.xml")
        logger.info(f"Script started at {time.ctime(start_time)}")
        logger.info(f"Output directory: {output_dir}")
        warnings_as_errors, warning_code_filter = strict_local_firewall_warning_settings(
            warnings_as_errors,
            warning_codes,
            strict_local_firewall,
        )

        if run_objects:
            run_objects_list = run_objects.split(',')
            logger.info(f'Running specific objects: {run_objects_list}')
        else:
            run_objects_list = []  # Initialize as empty list

        if should_default_full_import(
            parser_type=parser_type,
            config_file=config_file,
            fetch_panos_config=fetch_panos_config,
            run_objects=run_objects,
            run_security=run_security,
            run_app_override=run_app_override,
            run_decrypt_rules=run_decrypt_rules,
            run_nat=run_nat,
            run_all=run_all,
        ):
            run_all = True
            logger.info("No selection flags supplied for local PAN-OS XML; defaulting to a full standalone import.")

        if snapshot_policy_dependencies:
            dependency_names = set(POLICY_DEPENDENCY_OBJECT_TYPE_NAMES)
            run_objects_list = list(dict.fromkeys(run_objects_list + POLICY_DEPENDENCY_OBJECT_TYPE_NAMES))
            run_objects = ",".join(run_objects_list)
            logger.info(f"Including policy dependency snapshot object types: {sorted(dependency_names)}")

        selected_regular_obj_types, selected_network_obj_types = split_selected_obj_types(config, run_objects_list)
        selected_obj_types = selected_regular_obj_types + selected_network_obj_types
        if run_objects and not selected_obj_types:
            logger.warning(f"No valid objects found to run for {run_objects_list}")

        if setup_scm_target:
            if not target_folder or not target_snippet:
                raise CliError("--target-folder and --target-snippet are required with --setup-scm-target")
            from scm import PanApiHandler
            from scm.setup import SetupTargetRequest, ensure_setup_target

            api_session = PanApiHandler(initialize_api_session(use_config=use_config))
            setup_result = ensure_setup_target(
                api_session,
                SetupTargetRequest(
                    folder_name=target_folder,
                    snippet_name=target_snippet,
                    parent_folder=parent_folder,
                    associate_snippet=associate_snippet,
                    create=create_scm_target,
                ),
            )
            logger.info(f"SCM target setup summary: {json.dumps(setup_result['summary'], sort_keys=True)}")
            print(json.dumps(setup_result, indent=2, sort_keys=True))
            if not setup_result["summary"]["ready"]:
                sys.exit(1)
            return setup_result

        if resolve_folder:
            from scm import PanApiHandler

            api_session = PanApiHandler(initialize_api_session(use_config=use_config))
            resolution = resolve_folder_scope(
                api_session,
                target_folder=resolve_folder,
                folder_path=folder_path,
                folder_id=folder_id,
                interactive=interactive,
                leaf_only=leaf_only,
                include_descendants=include_descendants,
            )
            print(json.dumps(resolution, indent=2, sort_keys=True))
            return resolution

        if snapshot_current_data:
            if not selected_obj_types:
                selected_obj_types = get_supported_obj_types(config)
                selected_regular_obj_types, selected_network_obj_types = split_selected_obj_types(
                    config,
                    [obj_type.__name__ for obj_type in selected_obj_types],
                )
            needs_object_scope = bool(selected_regular_obj_types)
            needs_policy_scope = bool(snapshot_policy)
            needs_network_scope = bool(selected_network_obj_types)
            from scm import PanApiHandler

            api_session = PanApiHandler(initialize_api_session(use_config=use_config))
            folder_resolution = None
            folder_selector_supplied = bool(target_folder or folder_path or folder_id)
            if folder_selector_supplied and (
                (needs_network_scope and not network_scope and not target_snippet)
                or (needs_object_scope and not object_scope)
                or (needs_policy_scope and not policy_scope)
            ):
                folder_resolution = resolve_folder_scope(
                    api_session,
                    target_folder=target_folder,
                    folder_path=folder_path,
                    folder_id=folder_id,
                    interactive=interactive,
                    leaf_only=leaf_only,
                    include_descendants=include_descendants,
                )
                network_scope = f"snippet:{folder_resolution['snippet_names'][0]}"
            scopes = resolve_category_scopes(
                scope,
                object_scope or (folder_resolution["folder_scope"] if folder_resolution else f"folder:{target_folder}" if target_folder else ""),
                policy_scope or (folder_resolution["folder_scope"] if folder_resolution else f"folder:{target_folder}" if target_folder else ""),
                network_scope,
                interactive,
                needs_object_scope,
                needs_policy_scope,
                needs_network_scope,
            )
            snapshot = {}
            if selected_regular_obj_types:
                if folder_resolution:
                    object_results = []
                    for source in folder_resolution["scope_nodes"]:
                        object_results.append((
                            source,
                            build_current_data_snapshot(
                                api_session,
                                selected_regular_obj_types,
                                source["scope"],
                                config,
                            ),
                        ))
                    snapshot.update(merge_scoped_snapshot_results(object_results, include_provenance=True, dedupe_names=False))
                else:
                    snapshot.update(build_current_data_snapshot(
                        api_session,
                        selected_regular_obj_types,
                        scopes.get("object"),
                        config,
                    ))
            if selected_network_obj_types:
                if folder_resolution:
                    network_snapshot = merge_scoped_snapshot_results([
                        (
                            source,
                            build_current_data_snapshot(
                                api_session,
                                selected_network_obj_types,
                                source["scope"],
                                config,
                            ),
                        )
                        for source in folder_resolution["scope_nodes"]
                    ], include_provenance=True, dedupe_names=False)
                else:
                    network_snapshot = build_current_data_snapshot(
                        api_session,
                        selected_network_obj_types,
                        scopes.get("network"),
                        config,
                    )
                prior_failures = snapshot.get("fetch_failures", [])
                snapshot.update(network_snapshot)
                if prior_failures and network_snapshot.get("fetch_failures"):
                    snapshot["fetch_failures"] = prior_failures + network_snapshot["fetch_failures"]
            if snapshot_policy:
                if folder_resolution:
                    policy_results = []
                    fetch_failures = []
                    for source in folder_resolution["scope_nodes"]:
                        policy_snapshot, failures = build_policy_snapshot(
                            api_session,
                            source["scope"],
                            config,
                            limit=config.limit,
                        )
                        policy_results.append((
                            source,
                            policy_snapshot,
                        ))
                        fetch_failures.extend(failures)
                    snapshot.update(merge_scoped_snapshot_results(policy_results, include_provenance=True, dedupe_names=False))
                else:
                    policy_snapshot, fetch_failures = build_policy_snapshot(
                        api_session,
                        scopes.get("policy"),
                        config,
                        limit=config.limit,
                    )
                    snapshot.update(policy_snapshot)
                existing_fetch_failures = snapshot.get("fetch_failures", [])
                snapshot["fetch_failures"] = existing_fetch_failures + fetch_failures
                snapshot["metadata"] = {
                    "source": "panos-to-scm",
                    "snapshot_type": "current-data-with-policy",
                    "scopes": {
                        category: _snapshot_scope_label(value)
                        for category, value in scopes.items()
                    },
                }
            device_inventory, inventory_failures = collect_device_inventory(
                api_session,
                folder_resolution=folder_resolution,
                limit=min(int(config.limit or 200), 2000),
            )
            snapshot["device_inventory"] = device_inventory
            if inventory_failures:
                snapshot["fetch_failures"] = snapshot.get("fetch_failures", []) + inventory_failures
            if folder_resolution:
                snapshot.setdefault("metadata", {
                    "source": "panos-to-scm",
                    "snapshot_type": "current-data-with-policy" if snapshot_policy else "current-data",
                    "scopes": {},
                })
                snapshot["metadata"]["scopes"]["folder"] = folder_resolution["path"]
                snapshot["metadata"]["scopes"]["folder_id"] = folder_resolution["folder"].get("id", "")
                snapshot["metadata"]["scopes"]["parent_folders"] = folder_resolution["folder_names"][:-1]
                snapshot["metadata"]["scopes"]["snippets"] = folder_resolution["snippet_names"]
                snapshot["metadata"]["scopes"]["collection_folders"] = [
                    folder.get("name", "") for folder in folder_resolution.get("collection_folders", [])
                ]
                snapshot["metadata"]["scopes"]["scope_nodes"] = folder_resolution["scope_nodes"]
                snapshot["metadata"]["scopes"]["descendant_folders"] = [
                    record.get("path", "") for record in folder_resolution.get("descendant_folders", [])
                ]
                snapshot["metadata"]["scopes"]["inventory"] = "folder-hierarchy"
                snapshot["metadata"]["folder_snippets"] = folder_resolution["snippets_by_folder"]
            snapshot.setdefault("metadata", {
                "source": "panos-to-scm",
                "snapshot_type": "current-data-with-policy" if snapshot_policy else "current-data",
                "scopes": {},
            })
            snapshot["metadata"]["management_mode"] = "scm_managed"
            write_json_file(snapshot_output, snapshot, "Current data snapshot")
            summary = {
                object_type: len(entries)
                for object_type, entries in sorted(snapshot.items())
                if isinstance(entries, list)
            }
            if snapshot_policy:
                summary["fetch_failures"] = len(snapshot.get("fetch_failures", []))
            logger.info(f"Current data snapshot summary: {json.dumps(summary, sort_keys=True)}")
            print(json.dumps(summary, indent=2, sort_keys=True))
            return snapshot

        if not json_file and config_file.lower().endswith('.json'):
            json_file = config_file

        if json_file != "":
            config_type = 'local'
            device_group_name = None
            try:
                with open(json_file, 'r') as file:
                    parsed_data = json.load(file)
            except Exception as err:
                logger.error(f"Error while loading json file {err}")
                sys.exit(1)
        else:
            file_path, config_type = get_file_path_and_type(
                config,
                logger,
                parser_type=parser_type,
                config_file=config_file,
                fetch_panos_config=fetch_panos_config,
                interactive=interactive,
            )

            logger.info(f"File path: {file_path}, Config type: {config_type}")

            if config_type == 'panos':
                parser = XMLParser(file_path, config_type)
                if interactive and not scope and not panos_config_type:
                    fallback_scope_param, config_type, device_group_name = parser.parse_config_and_set_scope(file_path)
                    scope = fallback_scope_param.replace('&', '').replace('=', ':', 1)
                else:
                    config_type = panos_config_type or infer_panos_config_type(file_path)
                    if config_type == 'panorama/device-group' and not device_group_name:
                        raise CliError("--device-group is required with --panos-config-type panorama/device-group")
                logger.info(f'PANOS: {config_type}, Device Group: {device_group_name}')
                parser.config_type = config_type
                parser.device_group_name = device_group_name
                if run_objects:
                    parsed_data = parser.parse_specific_types(
                        selected_type_names_for_parse(
                            run_objects_list,
                            run_all=run_all,
                            run_security=run_security,
                            run_app_override=run_app_override,
                            run_decrypt_rules=run_decrypt_rules,
                            run_nat=run_nat,
                        )
                    )
                else:
                    run_objects_list = []  # Initialize as empty list
                    parsed_data = parser.parse_all()
                
            elif config_type == 'cisco':
                parser = CiscoParser(file_path)
                parser.parse()
                parsed_data = parser.get_parsed_data()
                device_group_name = None
                run_objects_list = run_objects.split(',') if run_objects else []
            else:
                parser = PfSenseParser(file_path)
                if run_objects:
                    parsed_data = parser.parse_specific_types(
                        selected_type_names_for_parse(
                            run_objects_list,
                            run_all=run_all,
                            run_security=run_security,
                            run_app_override=run_app_override,
                            run_decrypt_rules=run_decrypt_rules,
                            run_nat=run_nat,
                        )
                    )
                else:
                    run_objects_list = []
                    parsed_data = parser.parse_all()
                device_group_name = None

            logger.debug(f"Parse Data: {json.dumps(parsed_data,indent=4)}")
            logger.debug(f"Parsed data keys: {list(parsed_data.keys())}")

        has_rule_flag = any([run_security, run_app_override, run_decrypt_rules, run_nat])
        if has_rule_flag and not run_all and not run_objects:
            selected_regular_obj_types = []
            selected_network_obj_types = []
            selected_obj_types = []
        needs_object_scope = bool(selected_regular_obj_types) and (bool(run_objects) or not has_rule_flag)
        needs_network_scope = bool(selected_network_obj_types) and (bool(run_objects) or not has_rule_flag)
        needs_policy_scope = run_all or run_security or run_app_override or run_decrypt_rules or run_nat
        if run_all:
            needs_object_scope = bool(selected_regular_obj_types)
            needs_network_scope = bool(selected_network_obj_types)

        if network_report:
            if not run_objects:
                selected_type_names = [obj_type.__name__ for obj_type in get_network_obj_types(config)]
                migration_warnings = parsed_data.get("_migration_warnings", [])
                parsed_data = {
                    object_type: parsed_data.get(object_type, [])
                    for object_type in selected_type_names
                }
                parsed_data["_migration_warnings"] = migration_warnings
            else:
                selected_type_names = [obj_type.__name__ for obj_type in selected_network_obj_types]

            report = build_network_report(parsed_data, selected_type_names)
            output = report.to_dict()
            if report_output:
                try:
                    with open(report_output, 'w') as file:
                        json.dump(output, file, indent=2, sort_keys=True)
                        file.write('\n')
                except Exception as err:
                    logger.error(f"Error while writing network report json file {err}")
                    sys.exit(1)
                logger.info(f"Network migration report written to {report_output}")
            write_remediation_output(report, remediation_output, "Network remediation report")
            logger.info(f"Network migration report summary: {json.dumps(report.summary(), sort_keys=True)}")
            print(json.dumps(report.summary(), indent=2, sort_keys=True))
            return report

        if validate_only:
            current_data = load_current_data(current_data_file)
            selected_type_names = selected_type_names_for_plan(
                parsed_data,
                selected_obj_types,
                run_all=run_all,
                run_security=run_security,
                run_app_override=run_app_override,
                run_decrypt_rules=run_decrypt_rules,
                run_nat=run_nat,
                include_selected_objects=bool(run_objects),
            )
            plan = build_plan(
                parsed_data,
                current_data=current_data,
                object_types=selected_type_names,
                conflict_policy=conflict_policy,
            )
            write_plan_output(plan, plan_output, "Validation plan")
            write_remediation_output(plan, remediation_output, "Validation remediation report")
            summary = validation_summary(
                plan,
                warnings_as_errors=warnings_as_errors,
                warning_codes=warning_code_filter,
            )
            logger.info(f"Validation summary: {json.dumps(summary, sort_keys=True)}")
            print(json.dumps(summary, indent=2, sort_keys=True))
            if summary["blockers"]:
                sys.exit(1)
            return plan

        folder_selector_supplied = bool(target_folder or folder_path or folder_id)
        defer_folder_network_scope = bool(folder_selector_supplied and not network_scope and not target_snippet)
        scopes = resolve_category_scopes(
            scope,
            object_scope or (f"folder:{target_folder}" if target_folder and not folder_path and not folder_id else ""),
            policy_scope or (f"folder:{target_folder}" if target_folder and not folder_path and not folder_id else ""),
            network_scope or (f"snippet:{target_snippet}" if target_snippet else ""),
            interactive,
            needs_object_scope,
            needs_policy_scope,
            needs_network_scope and not defer_folder_network_scope,
        )

        if dry_run:
            current_data = load_current_data(current_data_file)
            selected_type_names = selected_type_names_for_plan(
                parsed_data,
                selected_obj_types,
                run_all=run_all,
                run_security=run_security,
                run_app_override=run_app_override,
                run_decrypt_rules=run_decrypt_rules,
                run_nat=run_nat,
                include_selected_objects=bool(run_objects),
            )
            plan = build_plan(
                parsed_data,
                current_data=current_data,
                object_types=selected_type_names,
                conflict_policy=conflict_policy,
            )
            write_plan_output(plan, plan_output, "Dry-run migration plan")
            write_remediation_output(plan, remediation_output, "Dry-run remediation report")
            logger.info(f"Dry-run migration plan summary: {json.dumps(plan.summary(), sort_keys=True)}")
            print(json.dumps(plan.summary(), indent=2, sort_keys=True))
            return plan

        current_data = None

        validation_plans = {}
        if selected_regular_obj_types:
            if not post_objects:
                raise CliError(
                    "Object/profile posting requires --post-objects. Run --validate-only first, "
                    "or add --post-objects to acknowledge live SCM object changes."
                )
            current_data = load_current_data(current_data_file)
            validation_plans["objects"] = validate_post_plan(
                parsed_data,
                current_data,
                [obj_type.__name__ for obj_type in selected_regular_obj_types],
                conflict_policy,
                warnings_as_errors,
                warning_code_filter,
                "Object post",
            )

        if needs_policy_scope:
            if not post_policy:
                raise CliError(
                    "Policy/NAT posting requires --post-policy. Run --validate-only first, "
                    "or add --post-policy to acknowledge live SCM policy changes."
                )
            if current_data is None:
                current_data = load_current_data(current_data_file)
            validation_plans["policy"] = validate_post_plan(
                parsed_data,
                current_data,
                selected_policy_type_names(
                    run_all=run_all,
                    run_security=run_security,
                    run_app_override=run_app_override,
                    run_decrypt_rules=run_decrypt_rules,
                    run_nat=run_nat,
                ),
                conflict_policy,
                warnings_as_errors,
                warning_code_filter,
                "Policy post",
            )

        if selected_network_obj_types:
            if not post_network:
                raise CliError(
                    "Network object posting requires --post-network. Run --validate-only first, "
                    "or add --post-network to acknowledge live SCM network changes."
                )
            if current_data is None:
                current_data = load_current_data(current_data_file)
            network_type_names = [obj_type.__name__ for obj_type in selected_network_obj_types]
            validation_plans["network"] = validate_post_plan(
                parsed_data,
                current_data,
                network_type_names,
                conflict_policy,
                warnings_as_errors,
                warning_code_filter,
                "Network post",
            )

        from scm import PanApiHandler

        api_session = PanApiHandler(initialize_api_session(use_config=use_config))
        folder_resolution = None
        if folder_selector_supplied and (
            (needs_network_scope and not network_scope and not target_snippet)
            or (needs_object_scope and not object_scope)
            or (needs_policy_scope and not policy_scope)
        ):
            folder_resolution = resolve_folder_scope(
                api_session,
                target_folder=target_folder,
                folder_path=folder_path,
                folder_id=folder_id,
                interactive=interactive,
                leaf_only=leaf_only,
                include_descendants=include_descendants,
            )
            scopes["object"] = scopes.get("object") or folder_resolution["folder_scope_param"]
            scopes["policy"] = scopes.get("policy") or folder_resolution["folder_scope_param"]
            scopes["network"] = folder_resolution["network_scopes"][0]
            if len(folder_resolution["network_scopes"]) > 1 and selected_network_obj_types:
                raise CliError(
                    "Folder resolves to multiple snippets. Live network posting requires an explicit "
                    "--target-snippet or --network-scope; use --snapshot-current-data to collect all "
                    "associated snippets."
                )
            logger.info(
                "Resolved SCM folder '%s' to snippets: %s",
                target_folder,
                ", ".join(folder_resolution["snippet_names"]),
            )
        prepare_import_target(
            api_session,
            scopes,
            target_folder,
            target_snippet,
            parent_folder,
            associate_snippet,
        )
        managers = []

        if run_all:
            regular_manager = process_obj_types(api_session, selected_regular_obj_types, parsed_data, scopes.get('object'), device_group_name, config, conflict_policy=conflict_policy, interactive=interactive, current_data=current_data)
            network_manager = process_obj_types(api_session, selected_network_obj_types, parsed_data, scopes.get('network'), device_group_name, config, conflict_policy=conflict_policy, interactive=interactive, current_data=current_data)
            managers.extend([regular_manager, network_manager])
            policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'], conflict_policy=conflict_policy, interactive=interactive)
            policy_manager.process_rules(config.sec_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='security')
            policy_manager.process_rules(config.app_override_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='application-override')
            policy_manager.process_rules(config.decryption_rule_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='decryption')
            policy_manager.configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
            policy_manager.process_rules(config.nat_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='nat')
            managers.append(policy_manager)
        elif run_objects:
            regular_manager = process_obj_types(api_session, selected_regular_obj_types, parsed_data, scopes.get('object'), device_group_name, config, conflict_policy=conflict_policy, interactive=interactive, current_data=current_data)
            network_manager = process_obj_types(api_session, selected_network_obj_types, parsed_data, scopes.get('network'), device_group_name, config, conflict_policy=conflict_policy, interactive=interactive, current_data=current_data)
            managers.extend([regular_manager, network_manager])
        else:
            if run_security:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'], conflict_policy=conflict_policy, interactive=interactive)
                policy_manager.process_rules(config.sec_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='security')
                managers.append(policy_manager)
            elif run_app_override:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'], conflict_policy=conflict_policy, interactive=interactive)
                policy_manager.process_rules(config.app_override_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='application-override')
                managers.append(policy_manager)
            elif run_decrypt_rules:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'], conflict_policy=conflict_policy, interactive=interactive)
                policy_manager.process_rules(config.decryption_rule_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='decryption')
                managers.append(policy_manager)
            elif run_nat:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'], conflict_policy=conflict_policy, interactive=interactive)
                policy_manager.configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
                policy_manager.process_rules(config.nat_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='nat')
                managers.append(policy_manager)
            else:
                regular_manager = process_obj_types(api_session, selected_regular_obj_types, parsed_data, scopes.get('object'), device_group_name, config, conflict_policy=conflict_policy, interactive=interactive, current_data=current_data)
                network_manager = process_obj_types(api_session, selected_network_obj_types, parsed_data, scopes.get('network'), device_group_name, config, conflict_policy=conflict_policy, interactive=interactive, current_data=current_data)
                managers.extend([regular_manager, network_manager])

        if validation_plans:
            write_live_plan_output(validation_plans, plan_output)
            write_live_remediation_output(validation_plans, remediation_output)

        live_report = build_live_report(
            api_session=api_session,
            config=config,
            file_path=file_path,
            scopes=scopes,
            selected_regular_obj_types=selected_regular_obj_types,
            selected_network_obj_types=selected_network_obj_types,
            parsed_data=parsed_data,
            validation_plans=validation_plans,
            managers=managers,
        )
        markdown_path = write_markdown_import_report(
            file_path=file_path,
            parsed_data=parsed_data,
            scopes=scopes,
            validation_plans=validation_plans,
            live_report=live_report,
            output_dir=output_dir,
        )
        live_report["markdown_report"] = markdown_path

        if report_output:
            write_json_file(report_output, live_report, "Live migration report")
            logger.info(f"Live migration report summary: {json.dumps(live_report['summary'], sort_keys=True)}")
            print(json.dumps(live_report["summary"], indent=2, sort_keys=True))
            return live_report

        logger.info(f"Live migration report summary: {json.dumps(live_report['summary'], sort_keys=True)}")
        print(json.dumps(live_report["summary"], indent=2, sort_keys=True))
        return live_report

        end_time = time.time()
        logger.info(f"Script execution time: {end_time - start_time:.2f} seconds")
        logger.info(f"Script ended at {time.ctime(end_time)}")

    except CliError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)
    
    complete_time = time.time()
    script_begin_time = globals().get('begin_time', start_time)
    logger.info(f"Final Script execution time: {complete_time - script_begin_time:.2f} seconds")

if __name__ == "__main__":
    begin_time = time.time()
    parser_config = AppConfig()

    obj_type_names = [obj.__name__ for obj in get_supported_obj_types(parser_config)]
    obj_type_help = "Specify the objects to run, separated by commas. Supported objects: " + ", ".join(obj_type_names)
    
    parser = argparse.ArgumentParser(description="Run specific objects or policies in the project")
    parser.add_argument('-o', '--objects', type=str, help=obj_type_help)
    parser.add_argument('-s', '--security-rules', action='store_true', help="Run security rules")
    parser.add_argument('-p', '--app-override-rules', action='store_true', help="Run application override rules")
    parser.add_argument('-d', '--decryption-rules', action='store_true', help="Run decryption rules")
    parser.add_argument('-n', '--nat-rules', action='store_true', help="Run NAT rules")
    parser.add_argument('-a', '--all', action='store_true', help="Run all: Object types as well as Security, App Override, Decryption and NAT policies")
    parser.add_argument('-j', '--json', action='store', default="", help="Take input from local JSON configuration")
    parser.add_argument('--parser', choices=['panos', 'cisco', 'pfsense'], default=None, help="Configuration parser to use")
    parser.add_argument('--config-file', action='store', default="", help="Configuration source file for PAN-OS XML, Cisco config, or pfSense config.xml")
    parser.add_argument('--scope', action='store', default="", help="SCM scope in the format folder:All, snippet:Shared, or device:name")
    parser.add_argument('--object-scope', action='store', default="", help="SCM scope for objects and profiles. Falls back to --scope.")
    parser.add_argument('--policy-scope', action='store', default="", help="SCM scope for policy and NAT rulebases. Falls back to --scope.")
    parser.add_argument('--network-scope', action='store', default="", help="SCM scope for network stack objects such as zones. Falls back to --scope.")
    parser.add_argument('--fetch-panos-config', action='store_true', help="Retrieve running PAN-OS config before parsing")
    parser.add_argument('--interactive', action='store_true', help="Allow legacy prompts for missing CLI values")
    parser.add_argument('--use-config', action='store_true', help="Use PANAPI_CONFIG credentials instead of prompting for SCM credentials in an interactive terminal")
    parser.add_argument('--panos-config-type', choices=['local', 'panorama/shared', 'panorama/device-group'], default="", help="PAN-OS XML scope type for non-interactive parsing")
    parser.add_argument('--device-group', action='store', default="", help="Panorama device-group name when using panorama/device-group")
    parser.add_argument('--dry-run', action='store_true', help="Build a local migration plan without authenticating to SCM or writing changes")
    parser.add_argument('--validate-only', action='store_true', help="Run parser/planner validation without SCM authentication or scope prompts; exits 1 on conflicts or unsupported entries")
    parser.add_argument('--snapshot-current-data', action='store_true', help="Fetch current SCM objects into --current-data compatible JSON and exit")
    parser.add_argument('--snapshot-output', action='store', default="", help="Write --snapshot-current-data JSON to this path")
    parser.add_argument('--snapshot-policy', action='store_true', help="With --snapshot-current-data, include pre/post security, NAT, decryption, and application-override rulebases")
    parser.add_argument('--snapshot-policy-dependencies', action='store_true', help="With --snapshot-current-data, include common policy dependency object types")
    parser.add_argument('--output-folder', action='store', default="", help="Directory for all default generated artifacts; otherwise a customer folder is created in the current working directory")
    parser.add_argument('--setup-scm-target', action='store_true', help="Check or create the target SCM folder/snippet pair and print the resulting scopes")
    parser.add_argument('--create-scm-target', action='store_true', help="With --setup-scm-target, create missing folder/snippet setup resources")
    parser.add_argument('--resolve-folder', action='store', default="", metavar='FOLDER', help="Show the snippets associated with an SCM folder and exit")
    parser.add_argument('--target-folder', '--folder', dest='target_folder', action='store', default="", help="SCM folder containing the object and policy scope; associated snippets are resolved automatically")
    parser.add_argument('--folder-path', action='store', default="", help="Exact SCM folder path, for example CSM-PA440/PA-440/PA-440")
    parser.add_argument('--folder-id', action='store', default="", help="Exact SCM folder UUID")
    parser.add_argument('--leaf-only', action='store_true', help="With a nested folder, collect only the selected leaf folder instead of inherited parent folders")
    parser.add_argument('--include-descendants', action='store_true', help="With --folder-path, also collect descendant folders and their linked snippets")
    parser.add_argument('--target-snippet', action='store', default="", help="Target SCM snippet name for migrated network stack objects")
    parser.add_argument('--parent-folder', action='store', default="ngfw-shared", help="Parent folder for --setup-scm-target creation. Defaults to ngfw-shared, the API value for All Firewalls.")
    parser.add_argument('--no-associate-snippet', action='store_true', help="Do not associate the target snippet when creating the target folder")
    parser.add_argument('--post-objects', action='store_true', help="Allow live object/profile posting after validation blockers are checked")
    parser.add_argument('--post-policy', action='store_true', help="Allow live policy/NAT posting after validation blockers are checked")
    parser.add_argument('--post-network', action='store_true', help="Allow live network object posting after validation blockers are checked")
    parser.add_argument('--warnings-as-errors', action='store_true', help="In validate-only mode, promote warnings to blockers and exit 1 when matching warnings exist")
    parser.add_argument('--warning-codes', action='store', default="", help="Comma-separated warning codes to promote with --warnings-as-errors. Defaults to all warnings")
    parser.add_argument('--strict-local-firewall', action='store_true', help="Promote recommended local firewall migration warnings to blockers")
    parser.add_argument('--network-report', action='store_true', help="Emit parsed network payloads and migration warnings without SCM comparison or authentication")
    parser.add_argument('--conflict-policy', choices=['fail', 'replace', 'ignore'], default='fail', help="How dry-run planning handles changed existing objects")
    parser.add_argument('--plan-output', action='store', default="", help="Write full dry-run or validation migration plan JSON to this path")
    parser.add_argument('--report-output', action='store', default="", help="Write full network report JSON to this path")
    parser.add_argument('--remediation-output', action='store', default="", help="Write grouped warning remediation JSON without full payloads")
    parser.add_argument('--current-data', action='store', default="", help="Offline current SCM data JSON for dry-run or validation comparison")
    args = parser.parse_args()
    cli_output_dir = resolve_output_directory(
        output_folder=args.output_folder,
        target_folder=args.target_folder,
        config_file=args.config_file,
        json_file=args.json,
    )
    setup_logging(cli_output_dir / "debug-log.txt")
    config = parser_config
    
    main(config, run_objects=args.objects, run_security=args.security_rules, run_app_override=args.app_override_rules, run_decrypt_rules=args.decryption_rules, run_nat=args.nat_rules, run_all=args.all, json_file=args.json, dry_run=args.dry_run, validate_only=args.validate_only, snapshot_current_data=args.snapshot_current_data, snapshot_output=args.snapshot_output, snapshot_policy=args.snapshot_policy, snapshot_policy_dependencies=args.snapshot_policy_dependencies, output_folder=args.output_folder, setup_scm_target=args.setup_scm_target, create_scm_target=args.create_scm_target, resolve_folder=args.resolve_folder, target_folder=args.target_folder, folder_path=args.folder_path, folder_id=args.folder_id, leaf_only=args.leaf_only, include_descendants=args.include_descendants, target_snippet=args.target_snippet, parent_folder=args.parent_folder, associate_snippet=not args.no_associate_snippet, post_objects=args.post_objects, post_policy=args.post_policy, post_network=args.post_network, warnings_as_errors=args.warnings_as_errors, warning_codes=args.warning_codes, strict_local_firewall=args.strict_local_firewall, network_report=args.network_report, conflict_policy=args.conflict_policy, plan_output=args.plan_output, report_output=args.report_output, remediation_output=args.remediation_output, current_data_file=args.current_data, parser_type=args.parser, config_file=args.config_file, scope=args.scope, object_scope=args.object_scope, policy_scope=args.policy_scope, network_scope=args.network_scope, fetch_panos_config=args.fetch_panos_config, interactive=args.interactive, panos_config_type=args.panos_config_type, device_group_name=args.device_group, use_config=args.use_config)
