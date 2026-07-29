import logging
from logging.handlers import TimedRotatingFileHandler
import time
import os
from config import AppConfig, ConfigurationManager
from parse.parse_panos import XMLParser
from parse.parse_cisco import CiscoParser
from scm.process import Processor, SCMObjectManager
from migration import build_plan
import scm.obj as obj
import argparse
import json
import sys
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


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
    conflict_policy="fail",
    plan_output="",
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

        if run_objects:
            run_objects_list = run_objects.split(',')
            logger.info(f'Running specific objects: {run_objects_list}')
        else:
            run_objects_list = []  # Initialize as empty list

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
                    parsed_data = parser.parse_specific_types(run_objects_list)
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

        selected_regular_obj_types, selected_network_obj_types = split_selected_obj_types(config, run_objects_list)
        selected_obj_types = selected_regular_obj_types + selected_network_obj_types
        if run_objects and not selected_obj_types:
            logger.warning(f"No valid objects found to run for {run_objects_list}")

        has_rule_flag = any([run_security, run_app_override, run_decrypt_rules, run_nat])
        needs_object_scope = bool(selected_regular_obj_types) and (bool(run_objects) or not has_rule_flag)
        needs_network_scope = bool(selected_network_obj_types) and (bool(run_objects) or not has_rule_flag)
        needs_policy_scope = run_all or run_security or run_app_override or run_decrypt_rules or run_nat
        if run_all:
            needs_object_scope = bool(selected_regular_obj_types)
            needs_network_scope = bool(selected_network_obj_types)

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
            current_data = {}
            if current_data_file:
                try:
                    with open(current_data_file, 'r') as file:
                        current_data = json.load(file)
                except Exception as err:
                    logger.error(f"Error while loading current data json file {err}")
                    sys.exit(1)

            selected_type_names = [obj_type.__name__ for obj_type in selected_obj_types]
            if run_all:
                selected_type_names = list(parsed_data.keys())
            elif run_security:
                selected_type_names = ['security_pre_rules', 'security_post_rules']
            elif run_app_override:
                selected_type_names = ['app_override_pre_rules', 'app_override_post_rules']
            elif run_decrypt_rules:
                selected_type_names = ['decryption_pre_rules', 'decryption_post_rules']
            elif run_nat:
                selected_type_names = ['nat_pre_rules', 'nat_post_rules']
            plan = build_plan(
                parsed_data,
                current_data=current_data,
                object_types=selected_type_names,
                conflict_policy=conflict_policy,
            )
            if plan_output:
                try:
                    with open(plan_output, 'w') as file:
                        json.dump(plan.to_dict(), file, indent=2, sort_keys=True)
                        file.write('\n')
                except Exception as err:
                    logger.error(f"Error while writing plan output json file {err}")
                    sys.exit(1)
                logger.info(f"Dry-run migration plan written to {plan_output}")
            logger.info(f"Dry-run migration plan summary: {json.dumps(plan.summary(), sort_keys=True)}")
            print(json.dumps(plan.summary(), indent=2, sort_keys=True))
            return plan

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
    parser.add_argument('--conflict-policy', choices=['fail', 'replace', 'ignore'], default='fail', help="How dry-run planning handles changed existing objects")
    parser.add_argument('--plan-output', action='store', default="", help="Write full dry-run migration plan JSON to this path")
    parser.add_argument('--current-data', action='store', default="", help="Offline current SCM data JSON for dry-run comparison")
    args = parser.parse_args()
    config = parser_config if args.dry_run else ConfigurationManager().app_config
    
    main(config, run_objects=args.objects, run_security=args.security_rules, run_app_override=args.app_override_rules, run_decrypt_rules=args.decryption_rules, run_nat=args.nat_rules, run_all=args.all, json_file=args.json, dry_run=args.dry_run, conflict_policy=args.conflict_policy, plan_output=args.plan_output, current_data_file=args.current_data, parser_type=args.parser, config_file=args.config_file, scope=args.scope, object_scope=args.object_scope, policy_scope=args.policy_scope, network_scope=args.network_scope, fetch_panos_config=args.fetch_panos_config, interactive=args.interactive, panos_config_type=args.panos_config_type, device_group_name=args.device_group)
