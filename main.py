import logging
from logging.handlers import TimedRotatingFileHandler
import time
import os
from config import AppConfig, ConfigurationManager
from parse.parse_panos import XMLParser
from parse.parse_cisco import CiscoParser
from scm.process import Processor, SCMObjectManager
from migration import build_network_report, build_plan
import scm.obj as obj
import argparse
import json
import sys
import xml.etree.ElementTree as ET

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

def setup_logging():
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    
    handler = TimedRotatingFileHandler('debug-log.txt', utc=True, when="midnight", interval=1, backupCount=1)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)

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


def infer_panos_config_type(file_path):
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
        config_choice = input("Do you want to parse Cisco or PANOS configuration? (cisco/panos): ").strip().lower()
    else:
        config_choice = 'panos'

    if config_choice not in {'panos', 'cisco'}:
        raise CliError("--parser must be either 'panos' or 'cisco'")

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
    else:
        file_path = config_file or config.cisco_file_path
        logger.info(f"Using Cisco configuration file: {file_path}")

    return file_path, config_choice

def initialize_api_session():
    from api import PanApiSession

    session = PanApiSession()
    session.authenticate()
    return session

def setup_scm_object_manager(session, obj_types, sec_obj, nat_obj, scope_param):
    return SCMObjectManager(session, scope_param, obj, obj_types, sec_obj, nat_obj)

def process_obj_types(api_session, selected_obj_types, parsed_data, scope_param, device_group_name, config):
    if not selected_obj_types:
        return
    scm_obj_manager = setup_scm_object_manager(api_session, selected_obj_types, config.sec_obj, config.nat_obj, scope_param)
    scm_obj_manager.process_objects(parsed_data, scope_param, device_group_name, max_workers=6, limit=config.limit)


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
    return {
        obj_type.__name__: current_objects.get(obj_type, [])
        for obj_type in manager.obj_types
    }


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
    snapshot_policy_dependencies=False,
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
):
    try:
        start_time = time.time()
        logger.info(f"Script started at {time.ctime(start_time)}")
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

        if snapshot_policy_dependencies:
            dependency_names = set(POLICY_DEPENDENCY_OBJECT_TYPE_NAMES)
            run_objects_list = list(dict.fromkeys(run_objects_list + POLICY_DEPENDENCY_OBJECT_TYPE_NAMES))
            run_objects = ",".join(run_objects_list)
            logger.info(f"Including policy dependency snapshot object types: {sorted(dependency_names)}")

        selected_regular_obj_types, selected_network_obj_types = split_selected_obj_types(config, run_objects_list)
        selected_obj_types = selected_regular_obj_types + selected_network_obj_types
        if run_objects and not selected_obj_types:
            logger.warning(f"No valid objects found to run for {run_objects_list}")

        if snapshot_current_data:
            if not selected_obj_types:
                selected_obj_types = get_supported_obj_types(config)
                selected_regular_obj_types, selected_network_obj_types = split_selected_obj_types(
                    config,
                    [obj_type.__name__ for obj_type in selected_obj_types],
                )
            needs_object_scope = bool(selected_regular_obj_types)
            needs_network_scope = bool(selected_network_obj_types)
            scopes = resolve_category_scopes(
                scope,
                object_scope,
                policy_scope,
                network_scope,
                interactive,
                needs_object_scope,
                False,
                needs_network_scope,
            )
            from scm import PanApiHandler

            api_session = PanApiHandler(initialize_api_session())
            snapshot = {}
            if selected_regular_obj_types:
                snapshot.update(
                    build_current_data_snapshot(
                        api_session,
                        selected_regular_obj_types,
                        scopes.get('object'),
                        config,
                    )
                )
            if selected_network_obj_types:
                snapshot.update(
                    build_current_data_snapshot(
                        api_session,
                        selected_network_obj_types,
                        scopes.get('network'),
                        config,
                    )
                )
            write_json_file(snapshot_output, snapshot, "Current data snapshot")
            summary = {object_type: len(entries) for object_type, entries in sorted(snapshot.items())}
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
                
            else:
                parser = CiscoParser(file_path)
                parser.parse()
                parsed_data = parser.get_parsed_data()
                device_group_name = None
                run_objects_list = run_objects.split(',') if run_objects else []

            logger.debug(f"Parse Data: {json.dumps(parsed_data,indent=4)}")
            logger.debug(f"Parsed data keys: {list(parsed_data.keys())}")

        has_rule_flag = any([run_security, run_app_override, run_decrypt_rules, run_nat])
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

        scopes = resolve_category_scopes(
            scope,
            object_scope,
            policy_scope,
            network_scope,
            interactive,
            needs_object_scope,
            needs_policy_scope,
            needs_network_scope,
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

        if selected_regular_obj_types:
            if not post_objects:
                raise CliError(
                    "Object/profile posting requires --post-objects. Run --validate-only first, "
                    "or add --post-objects to acknowledge live SCM object changes."
                )
            current_data = load_current_data(current_data_file)
            validate_post_plan(
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
            validate_post_plan(
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
            validate_post_plan(
                parsed_data,
                current_data,
                network_type_names,
                conflict_policy,
                warnings_as_errors,
                warning_code_filter,
                "Network post",
            )

        from scm import PanApiHandler

        api_session = PanApiHandler(initialize_api_session())

        if run_all:
            process_obj_types(api_session, selected_regular_obj_types, parsed_data, scopes.get('object'), device_group_name, config)
            process_obj_types(api_session, selected_network_obj_types, parsed_data, scopes.get('network'), device_group_name, config)
            policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'])
            policy_manager.process_rules(config.sec_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='security')
            policy_manager.process_rules(config.app_override_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='application-override')
            policy_manager.process_rules(config.decryption_rule_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='decryption')
            policy_manager.configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
            policy_manager.process_rules(config.nat_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='nat')
        elif run_objects:
            process_obj_types(api_session, selected_regular_obj_types, parsed_data, scopes.get('object'), device_group_name, config)
            process_obj_types(api_session, selected_network_obj_types, parsed_data, scopes.get('network'), device_group_name, config)
        else:
            if run_security:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'])
                policy_manager.process_rules(config.sec_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='security')
            elif run_app_override:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'])
                policy_manager.process_rules(config.app_override_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='application-override')
            elif run_decrypt_rules:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'])
                policy_manager.process_rules(config.decryption_rule_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='decryption')
            elif run_nat:
                policy_manager = setup_scm_object_manager(api_session, [], config.sec_obj, config.nat_obj, scopes['policy'])
                policy_manager.configure.set_max_workers(1)  # Set max workers to 1 for NAT rules
                policy_manager.process_rules(config.nat_obj, parsed_data, scopes['policy'], limit=config.limit, rule_type='nat')
            else:
                process_obj_types(api_session, selected_regular_obj_types, parsed_data, scopes.get('object'), device_group_name, config)
                process_obj_types(api_session, selected_network_obj_types, parsed_data, scopes.get('network'), device_group_name, config)

        end_time = time.time()
        logger.info(f"Script execution time: {end_time - start_time:.2f} seconds")
        logger.info(f"Script ended at {time.ctime(end_time)}")

    except CliError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
    
    complete_time = time.time()
    script_begin_time = globals().get('begin_time', start_time)
    logger.info(f"Final Script execution time: {complete_time - script_begin_time:.2f} seconds")

if __name__ == "__main__":
    setup_logging()
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
    parser.add_argument('--parser', choices=['panos', 'cisco'], default=None, help="Configuration parser to use")
    parser.add_argument('--config-file', action='store', default="", help="Configuration source file for PAN-OS XML or Cisco config")
    parser.add_argument('--scope', action='store', default="", help="SCM scope in the format folder:All, snippet:Shared, or device:name")
    parser.add_argument('--object-scope', action='store', default="", help="SCM scope for objects and profiles. Falls back to --scope.")
    parser.add_argument('--policy-scope', action='store', default="", help="SCM scope for policy and NAT rulebases. Falls back to --scope.")
    parser.add_argument('--network-scope', action='store', default="", help="SCM scope for network stack objects such as zones. Falls back to --scope.")
    parser.add_argument('--fetch-panos-config', action='store_true', help="Retrieve running PAN-OS config before parsing")
    parser.add_argument('--interactive', action='store_true', help="Allow legacy prompts for missing CLI values")
    parser.add_argument('--panos-config-type', choices=['local', 'panorama/shared', 'panorama/device-group'], default="", help="PAN-OS XML scope type for non-interactive parsing")
    parser.add_argument('--device-group', action='store', default="", help="Panorama device-group name when using panorama/device-group")
    parser.add_argument('--dry-run', action='store_true', help="Build a local migration plan without authenticating to SCM or writing changes")
    parser.add_argument('--validate-only', action='store_true', help="Run parser/planner validation without SCM authentication or scope prompts; exits 1 on conflicts or unsupported entries")
    parser.add_argument('--snapshot-current-data', action='store_true', help="Fetch current SCM objects into --current-data compatible JSON and exit")
    parser.add_argument('--snapshot-output', action='store', default="", help="Write --snapshot-current-data JSON to this path")
    parser.add_argument('--snapshot-policy-dependencies', action='store_true', help="With --snapshot-current-data, include common policy dependency object types")
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
    config = parser_config if args.dry_run or args.validate_only or args.network_report else ConfigurationManager().app_config
    
    main(config, run_objects=args.objects, run_security=args.security_rules, run_app_override=args.app_override_rules, run_decrypt_rules=args.decryption_rules, run_nat=args.nat_rules, run_all=args.all, json_file=args.json, dry_run=args.dry_run, validate_only=args.validate_only, snapshot_current_data=args.snapshot_current_data, snapshot_output=args.snapshot_output, snapshot_policy_dependencies=args.snapshot_policy_dependencies, post_objects=args.post_objects, post_policy=args.post_policy, post_network=args.post_network, warnings_as_errors=args.warnings_as_errors, warning_codes=args.warning_codes, strict_local_firewall=args.strict_local_firewall, network_report=args.network_report, conflict_policy=args.conflict_policy, plan_output=args.plan_output, report_output=args.report_output, remediation_output=args.remediation_output, current_data_file=args.current_data, parser_type=args.parser, config_file=args.config_file, scope=args.scope, object_scope=args.object_scope, policy_scope=args.policy_scope, network_scope=args.network_scope, fetch_panos_config=args.fetch_panos_config, interactive=args.interactive, panos_config_type=args.panos_config_type, device_group_name=args.device_group)
