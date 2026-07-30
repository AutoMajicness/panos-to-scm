import logging
import time
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Tuple, Dict
from urllib.parse import urlencode
import re

from scm.scope import Scope


NETWORK_OBJECT_DEPENDENCY_ORDER = [
    "InterfaceManagementProfile",
    "ZoneProtectionProfile",
    "AggregateInterface",
    "EthernetInterface",
    "Layer2Subinterface",
    "Layer3Subinterface",
    "VlanInterface",
    "TunnelInterface",
    "LoopbackInterface",
    "DHCPInterface",
    "Zones",
    "OSPFAuthProfile",
    "BgpAuthProfile",
    "BgpAddressFamilyProfile",
    "RoutePrefixList",
    "RouteAccessList",
    "RouteCommunityList",
    "RoutePathAccessList",
    "BgpRouteMap",
    "BgpRouteMapRedistribution",
    "BgpFilteringProfile",
    "BgpRedistributionProfile",
    "IKECryptoProfile",
    "IPsecCryptoProfile",
    "IKEGateway",
    "IPsecTunnel",
    "LogicalRouter",
    "PbfRule",
]

_NETWORK_OBJECT_ORDER_INDEX = {
    object_type: index
    for index, object_type in enumerate(NETWORK_OBJECT_DEPENDENCY_ORDER)
}

_PHYSICAL_ETHERNET_PATTERN = re.compile(r"^ethernet\d+/\d+$")
_ETHERNET_SUBINTERFACE_PATTERN = re.compile(r"^ethernet\d+/\d+\.\d+$")
_AGGREGATE_INTERFACE_PATTERN = re.compile(r"^ae\d+$")
_AGGREGATE_SUBINTERFACE_PATTERN = re.compile(r"^ae\d+\.\d+$")
_TUNNEL_INTERFACE_PATTERN = re.compile(r"^tunnel\.\d+$")
_LOOPBACK_INTERFACE_PATTERN = re.compile(r"^loopback\.\d+$")
_FETCH_LIMIT_OVERRIDES = {
    "Application": 500,
    "RoutePrefixList": 500,
    "RouteAccessList": 500,
}
_FETCH_LIMIT_FALLBACKS = (5000, 1000, 500, 200, 100, 50)
_SINGLE_PAGE_FETCH_OBJECTS = {"Application"}


def order_object_types_for_dependencies(obj_types):
    """Return object classes in a safe posting order while preserving unknown types."""

    return sorted(
        obj_types,
        key=lambda obj_type: (
            0 if obj_type.__name__ in _NETWORK_OBJECT_ORDER_INDEX else 1,
            _NETWORK_OBJECT_ORDER_INDEX.get(obj_type.__name__, len(_NETWORK_OBJECT_ORDER_INDEX)),
        ),
    )


def normalize_scm_interface_name(interface_name: str) -> str:
    """Convert PAN-OS interface identifiers into SCM variable-style names."""

    if not isinstance(interface_name, str) or not interface_name:
        return interface_name
    if interface_name.startswith("$"):
        return interface_name
    if (
        _PHYSICAL_ETHERNET_PATTERN.match(interface_name)
        or _ETHERNET_SUBINTERFACE_PATTERN.match(interface_name)
        or _AGGREGATE_INTERFACE_PATTERN.match(interface_name)
        or _AGGREGATE_SUBINTERFACE_PATTERN.match(interface_name)
    ):
        sanitized = "".join(
            character if character.isalnum() or character in "._-" else "-"
            for character in interface_name
        )
        return f"${sanitized}"
    if _TUNNEL_INTERFACE_PATTERN.match(interface_name):
        return f"$tunnel{interface_name.split('.', 1)[1]}"
    if _LOOPBACK_INTERFACE_PATTERN.match(interface_name):
        return f"$loopback{interface_name.split('.', 1)[1]}"
    return interface_name


class Processor:
    def __init__(self, api_handler, max_workers: int, obj_module, scm_object_manager):
        self.api_handler = api_handler
        self.max_workers = max_workers
        self.obj = obj_module
        self.scm_object_manager = scm_object_manager
        self.logger = logging.getLogger(__name__)

    def set_max_workers(self, new_max_workers: int):
        self.max_workers = new_max_workers

    def post_entries(self, scope_param, entries: List[Any], obj_type, extra_query_params: str) -> Tuple[int, int, int]:
        if not entries:
            self.logger.info("No entries to process.")
            return 0, 0, 0

        start_time = time.time()
        initial_entry_count = len(entries)
        endpoint_message = obj_type.get_endpoint().strip('/').split('/')[-1]
        self.logger.info(f"Processing {initial_entry_count} {endpoint_message} entries in parallel.")

        scope = Scope.from_param(scope_param)
        if obj_type.uses_payload_scope():
            endpoint = obj_type.get_endpoint()
            scoped_entries = [scope.apply_to_payload(entry) for entry in entries]
        else:
            endpoint = self._legacy_endpoint(obj_type.get_endpoint(), scope, extra_query_params)
            scoped_entries = entries
        results = self.create_objects(endpoint, scoped_entries)

        created_count, exists_count, error_count, error_objects = self.analyze_results(results)

        self.log_summary(initial_entry_count, created_count, exists_count, error_count, error_objects, endpoint_message, start_time)

        return created_count, exists_count, error_count

    def create_objects(self, endpoint: str, data: List[Any]) -> List[Dict[str, Any]]:
        self.logger.info(f'Running with {self.max_workers} workers.')
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.api_handler.post, endpoint, item, retries=2, delay=0.5): item for item in data}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    if result.get('status') in {'success', 'created', 'updated'}:
                        self.logger.info(f"Object '{result.get('name')}' processed successfully.")
                    elif result.get('status') == 'exists':
                        self.logger.info(f"Object '{result.get('name')}' already exists.")
                    else:
                        self.logger.error(f"Error creating object '{futures[future].get('name')}': {result.get('message')}")
                except Exception as e:
                    self.logger.error(f"Error processing object: {e}")
        return results

    def analyze_results(self, results: List[Dict[str, Any]]) -> Tuple[int, int, int, List[str]]:
        created_count = sum(1 for r in results if r.get('status') in {'success', 'created', 'updated'})
        exists_count = sum(1 for r in results if r.get('status') == 'exists')
        error_statuses = {'error', 'exception', 'failed'}
        error_count = sum(1 for r in results if r.get('status') in error_statuses)
        error_objects = [r.get('name') for r in results if r.get('status') in error_statuses]
        return created_count, exists_count, error_count, error_objects

    @staticmethod
    def _legacy_endpoint(endpoint: str, scope: Scope, extra_query_params: str) -> str:
        params = {}
        if extra_query_params:
            params.update(dict(item.split('=', 1) for item in extra_query_params.strip('?&').split('&') if item))
        params.update(scope.as_query_params())
        separator = '&' if '?' in endpoint else '?'
        return f"{endpoint}{separator}{urlencode(params)}"

    def log_summary(self, initial_count: int, created_count: int, exists_count: int, error_count: int, error_objects: List[str], message: str, start_time: float):
        processing_time = time.time() - start_time
        summary = (
            f"The processing of {message} is complete.\n"
            f"Summary: {created_count} created, {exists_count} already existed, {error_count} errors.\n"
            f"Initial Object/Policy count: {initial_count}. Potential missing objects: {initial_count - (created_count + exists_count)}\n"
            f"Time taken for creating {message}: {processing_time:.2f} seconds\n"
        )
        if error_objects:
            summary += f"Objects with errors:\n{chr(10).join(f' - {error}' for error in error_objects)}\n"
        self.logger.info(summary)

    def reorder_rules(self, obj_type, endpoint, scope_param, original_rules, current_rules, limit, position):
        current_rule_ids = {rule['name']: rule['id'] for rule in current_rules}
        current_order = self._rule_names_without_default(current_rules)
        desired_order = [rule['name'] for rule in original_rules if rule['name'] in current_rule_ids and rule['name'] != 'default']
        move_attempts = 0
        move_failures = []

        for _ in range(10000):  # Max 10000 attempts
            moves = []
            for i, rule_name in enumerate(desired_order[:-1]):
                if current_order.index(rule_name) > current_order.index(desired_order[i + 1]):
                    moves.append((
                        f"{endpoint}/{current_rule_ids[rule_name]}:move",
                        {"destination": "before", "rulebase": position, "destination_rule": current_rule_ids[desired_order[i + 1]]}
                    ))
                    self.logger.info(f"Prepared move: Rule '{rule_name}' before '{desired_order[i + 1]}'")

            if not moves:
                break
            move_attempts += len(moves)

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self.api_handler.post, endpoint, move_data) for endpoint, move_data in moves]
                for future in as_completed(futures):
                    result = future.result()
                    if not self._is_success_result(result):
                        move_failures.append(result)
                        self.logger.error(f"Error moving rule: {result}")

            # Use the fetch_rules method from SCMObjectManager
            current_rules = self.scm_object_manager.fetch_rules(obj_type, limit=limit, position=position)
            current_order = self._rule_names_without_default(current_rules)

        return current_rules, move_attempts, move_failures

    def check_and_reorder_rules(self, obj_type, scope_param, original_rules, limit, position):
        start_time = time.time()
        endpoint = obj_type.get_endpoint().replace('?', '')
        desired_order = self._rule_names_without_default(original_rules)
        report = {
            "rule_type": obj_type.__name__,
            "position": position,
            "desired_order": desired_order,
            "desired_count": len(desired_order),
            "current_order_before": [],
            "current_order_after": [],
            "current_count_before": 0,
            "current_count_after": 0,
            "move_attempts": 0,
            "move_failures": [],
            "reordered": False,
            "verified": False,
            "verification_mode": "relative-subsequence",
            "matched_rule_count": 0,
            "fetch_failed": False,
            "error": "",
        }

        try:
            current_rules = self.scm_object_manager.fetch_rules(obj_type, limit=limit, position=position)
            current_order = self._rule_names_without_default(current_rules)
            report["current_order_before"] = current_order
            report["current_count_before"] = len(current_order)

            if not self._contains_rule_subsequence(current_order, desired_order):
                self.logger.info("Reordering rules now..")
                current_rules, move_attempts, move_failures = self.reorder_rules(
                    obj_type,
                    endpoint,
                    scope_param,
                    original_rules,
                    current_rules,
                    limit,
                    position,
                )
                report["reordered"] = True
                report["move_attempts"] = move_attempts
                report["move_failures"] = move_failures

            final_order = self._rule_names_without_default(current_rules)
            report["current_order_after"] = final_order
            report["current_count_after"] = len(final_order)
            report["matched_rule_count"] = len(
                [rule_name for rule_name in final_order if rule_name in desired_order]
            )
            report["verified"] = self._contains_rule_subsequence(final_order, desired_order)
            if report["verified"]:
                self.logger.info(
                    "Verified %s %s rule order using %s check: %d migrated rules match the source order.",
                    position,
                    obj_type.__name__,
                    report["verification_mode"],
                    report["matched_rule_count"],
                )
            else:
                self.logger.warning(
                    "Unable to verify %s %s rule order using %s check. Desired=%s Final=%s",
                    position,
                    obj_type.__name__,
                    report["verification_mode"],
                    desired_order,
                    final_order,
                )
        except Exception as exc:
            report["fetch_failed"] = True
            report["error"] = str(exc)
            self.logger.error(
                "Unable to verify %s %s rule order after posting: %s",
                position,
                obj_type.__name__,
                exc,
            )

        self.logger.info(f"Time taken for reordering rules: {time.time() - start_time:.2f} seconds")
        return report

    @staticmethod
    def _rule_names_without_default(rules):
        return [rule['name'] for rule in rules if rule.get('name') != 'default']

    @staticmethod
    def _contains_rule_subsequence(current_order, desired_order):
        if not desired_order:
            return True
        desired_index = 0
        for rule_name in current_order:
            if rule_name != desired_order[desired_index]:
                continue
            desired_index += 1
            if desired_index == len(desired_order):
                return True
        return False

    @staticmethod
    def _is_success_result(result):
        return result.get('status') in {'success', 'created', 'updated'}


class SCMObjectManager:
    def __init__(self, api_handler, scope_param, obj_module, obj_types, sec_obj, nat_obj, conflict_policy="fail", interactive=False):
        self.api_handler = api_handler
        self.scope_param = scope_param
        self.scope = Scope.from_param(scope_param)
        self.configure = Processor(api_handler, 6, obj_module, self)
        self.obj = obj_module
        self.obj_types = order_object_types_for_dependencies(obj_types)
        self.sec_obj = sec_obj
        self.nat_obj = nat_obj        
        self.logger = logging.getLogger(__name__)
        self.scope_type, self.scope_value = self.scope.scope_type, self.scope.scope_value
        self.conflict_policy = conflict_policy
        self.interactive = interactive
        self.fetch_failures = []
        self.rule_order_verification = []

    def parse_scope_param(self, scope_param):
        scope_type, scope_value = scope_param.lstrip('&').split('=')
        return scope_type, scope_value

    def fetch_objects(self, obj_type, limit='10000', position=''):
        endpoint = obj_type.get_endpoint()
        initial_limit = _FETCH_LIMIT_OVERRIDES.get(obj_type.__name__, 5000)
        total_limit = int(limit)  # Convert the limit to an integer
        offset = 0  # Start offset for pagination
        all_objects = []  # Initialize list to store all fetched objects
        single_page_only = (
            obj_type.__name__ in _SINGLE_PAGE_FETCH_OBJECTS
            and self.scope.scope_type == "folder"
        )

        while offset < total_limit:
            # Calculate the limit for the current batch, ensuring it does not exceed max_limit
            current_limit = min(initial_limit, total_limit - offset)
            current_objects, effective_limit = self._fetch_batch_with_fallback(
                endpoint,
                obj_type.__name__,
                current_limit,
                offset,
                position,
            )
            params = {**self.scope.as_query_params(), 'limit': effective_limit, 'offset': offset}
            if position:
                params['position'] = position
            self.logger.debug(f'Fetched batch with offset {offset}: {current_objects}')
            if current_objects is None:
                raise RuntimeError(f"Failed to fetch objects for endpoint {endpoint}")

            # Add the current batch to the overall list
            all_objects.extend(current_objects)

            # Update offset for the next batch
            offset += effective_limit
            
            # Debug statement to log the count of objects
            object_count = len([obj for obj in current_objects if 'name' in obj])
            self.logger.debug(f'Number of objects in current batch with "name" key: {object_count}')

            # Stop fetching if the number of objects returned is less than requested for the batch
            if len(current_objects) < effective_limit:
                self.logger.debug('Fetched fewer objects than requested for the batch, no more objects to fetch.')
                break
            if single_page_only:
                self.logger.info(
                    "Stopping current-state fetch for %s after the first page in folder scope to avoid walking the full SCM application catalog.",
                    obj_type.__name__,
                )
                break

        # Log the total number of objects fetched
        total_object_count = len(all_objects)
        self.logger.debug(f'Total number of objects fetched: {total_object_count}')

        return all_objects

    def _fetch_batch_with_fallback(self, endpoint, object_type_name, requested_limit, offset, position):
        candidate_limits = [
            candidate
            for candidate in _FETCH_LIMIT_FALLBACKS
            if candidate <= requested_limit
        ]
        if requested_limit not in candidate_limits:
            candidate_limits.insert(0, requested_limit)

        last_error = None
        for candidate_limit in candidate_limits:
            params = {**self.scope.as_query_params(), 'limit': candidate_limit, 'offset': offset}
            if position:
                params['position'] = position
            try:
                return self.api_handler.get(endpoint, params=params), candidate_limit
            except Exception as exc:
                last_error = exc
                if candidate_limit == candidate_limits[-1]:
                    break
                self.logger.warning(
                    "Fetch for %s failed at limit %s offset %s; retrying with a smaller page size: %s",
                    object_type_name,
                    candidate_limit,
                    offset,
                    exc,
                )
        raise last_error

    def fetch_rules(self, obj_type, limit='10000', position=''):
        rules = self.fetch_objects(obj_type, limit, position)
        return [o for o in rules if 'name' in o and ('folder' in o or 'snippet' in o)]

    def process_objects(self, parsed_data, scope_param, device_group_name, max_workers=6, limit='10000', current_data=None):
        self.logger.info(f'Workers grabbing objects: {max_workers}')
        current_objects = self.get_current_objects(self.obj_types, max_workers, limit, parsed_data=parsed_data)
        new_entries, updated_entries = self.get_new_and_updated_entries(parsed_data, current_objects)
        alias_source = dict(current_objects)
        if isinstance(current_data, dict):
            alias_source.update(current_data)
        reference_aliases = self._build_reference_aliases(parsed_data, alias_source)

        if any(new_entries.values()):
            self.post_new_entries(new_entries, scope_param, device_group_name, reference_aliases)

        self.update_existing_entries(updated_entries, scope_param, device_group_name, limit, reference_aliases)

    def get_current_objects(self, obj_types, max_workers=6, limit='10000', parsed_data=None, **kwargs):
        self.logger.info(f"Running with {max_workers} workers.")
        current_objects = {}
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_obj_type = {
                executor.submit(
                    self.fetch_objects, 
                    obj_type, 
                    limit, 
                    **kwargs.get(obj_type.__name__, {})
                ): obj_type for obj_type in obj_types
            }
            for future in as_completed(future_to_obj_type):
                obj_type = future_to_obj_type[future]
                try:
                    current_objects[obj_type] = future.result()
                except Exception as exc:
                    fallback = self._fetch_named_route_lists(obj_type, parsed_data)
                    if fallback is not None:
                        current_objects[obj_type] = fallback
                        self.logger.warning(
                            "Used name-scoped fallback for %s after collection fetch failure: %d objects.",
                            obj_type.__name__,
                            len(fallback),
                        )
                        continue
                    self.fetch_failures.append(
                        {
                            "object_type": obj_type.__name__,
                            "scope": self.scope_param,
                            "error": str(exc),
                        }
                    )
                    self.logger.error(
                        "Unable to fetch current %s objects from SCM; continuing with an empty current set: %s",
                        obj_type.__name__,
                        exc,
                    )
                    current_objects[obj_type] = []
        return current_objects

    def _fetch_named_route_lists(self, obj_type, parsed_data):
        if obj_type.__name__ not in {"RoutePrefixList", "RouteAccessList"}:
            return None
        if not isinstance(parsed_data, dict):
            return None

        desired = parsed_data.get(obj_type.__name__, [])
        names = [entry.get("name") for entry in desired if isinstance(entry, dict) and entry.get("name")]
        if not names:
            return None

        found = []
        endpoint = obj_type.get_endpoint()
        for name in names:
            try:
                matches = self.api_handler.get(
                    endpoint,
                    params={**self.scope.as_query_params(), "name": name},
                )
            except Exception as exc:
                self.logger.warning("Name-scoped fallback failed for %s %s: %s", obj_type.__name__, name, exc)
                continue
            if isinstance(matches, list):
                found.extend(item for item in matches if isinstance(item, dict))
            elif isinstance(matches, dict):
                found.append(matches)
        return found

    def get_new_and_updated_entries(self, parsed_data, current_objects):
        new_entries = {}
        updated_entries = {}
        for obj_type, current_set in current_objects.items():
            entry_type_name = obj_type.__name__
            parsed_data_key = self._generate_key_name(entry_type_name)
            if parsed_data_key not in parsed_data:
                self.logger.warning(f"Warning: Key '{parsed_data_key}' not found in parsed_data.")
                continue

            current_names = {o['name'] for o in current_set if isinstance(o, dict)}
            for parsed_obj in parsed_data[parsed_data_key]:
                name = parsed_obj['name']
                if name not in current_names:
                    new_entries.setdefault(entry_type_name, []).append(parsed_obj)
                else:
                    existing_obj = next(o for o in current_set if o['name'] == name)
                    parsed_obj_with_id = {**parsed_obj, 'id': existing_obj.get('id')}
                    if self.needs_update(parsed_obj_with_id, existing_obj):
                        resolved_entry = self.resolve_conflicts(parsed_obj_with_id, existing_obj)
                        updated_entries.setdefault(entry_type_name, []).append(resolved_entry)

        return new_entries, updated_entries

    def resolve_conflicts(self, new_object, current_object):
        normalized_new = self.normalize(new_object.copy())
        normalized_current = self.normalize(current_object.copy())

        if normalized_new == normalized_current:
            self.logger.debug(f"Objects '{new_object['name']}' are identical after normalization. Skipping conflict resolution.")
            return current_object

        if not self.interactive:
            if self.conflict_policy == 'replace':
                self.logger.info(
                    "Replacing existing %s object '%s' during non-interactive migration.",
                    new_object.get('type', 'SCM'),
                    new_object['name'],
                )
                return new_object
            if self.conflict_policy == 'ignore':
                self.logger.info(
                    "Ignoring differing existing object '%s' during non-interactive migration.",
                    new_object['name'],
                )
                return current_object
            raise RuntimeError(
                f"Conflict detected for object '{new_object['name']}' during non-interactive migration. "
                "Re-run with --conflict-policy replace or --conflict-policy ignore."
            )

        print(f"Conflict detected for object '{new_object['name']}'")
        print(f"SCM Object: {normalized_current}")
        print(f"New Object: {normalized_new}")
        choice = input("Choose an action: [M]erge, [R]eplace, [C]reate new with appended name, [I]gnore (M/R/C/I): ").strip().upper()

        if choice == 'M':
            return self.merge_entries(new_object, current_object)
        elif choice == 'R':
            return new_object
        elif choice == 'C':
            new_object['name'] = f"{new_object['name']}_new"
            return new_object
        elif choice == 'I':
            self.logger.info(f"Ignoring conflict for object '{new_object['name']}'. No changes will be made.")
            return current_object
        else:
            print("Invalid choice. Ignoring conflict and making no changes.")
            return current_object

    @staticmethod
    def merge_entries(new_object, current_object):
        merged_object = current_object.copy()
        for key, value in new_object.items():
            if isinstance(value, list) and value:  # Only merge non-empty lists
                merged_object[key] = list(set(merged_object.get(key, []) + value))
            elif value not in (None, [], {}):  # Only update with non-empty values
                merged_object[key] = value
        return SCMObjectManager.normalize(merged_object)  # Normalize the result

    @staticmethod
    def needs_update(new_object, current_object):
        normalized_new = SCMObjectManager.normalize(new_object)
        normalized_current = SCMObjectManager.normalize(current_object)
        return normalized_new != normalized_current

    def update_existing_entries(self, updated_entries, scope_param, device_group_name, limit, reference_aliases=None):
        for obj_type in self.obj_types:
            entry_type_name = obj_type.__name__
            if entry_type_name not in updated_entries:
                continue

            entry_class = getattr(self.obj, entry_type_name)
            for entry in updated_entries[entry_type_name]:
                entry = self._normalize_entry_for_post(entry_type_name, entry, reference_aliases or {})
                object_id = entry.pop('id', None)
                if not object_id:
                    self.logger.warning(f"Warning: Object ID not found for {entry['name']} in {entry_type_name}. Skipping update.")
                    continue

                endpoint = f"{entry_class.get_endpoint().rstrip('?')}/{object_id}"
                params = {**self.scope.as_query_params(), 'limit': limit}
                
                current_objects = self.api_handler.get(entry_class.get_endpoint(), params=params)
                current_object = next((obj for obj in current_objects if obj['name'] == entry['name']), None)
                
                if not current_object:
                    self.logger.error(f"Current object '{entry['name']}' not found in SCM. Skipping update.")
                    continue

                if self.normalize(entry) != self.normalize(current_object):
                    self.logger.info(f"Updating {entry_type_name}: {entry['name']} at endpoint: {endpoint}")
                    payload = self.scope.apply_to_payload(entry) if entry_class.uses_payload_scope() else entry
                    result = self.api_handler.put(endpoint, payload)
                    if result['status'] in {'success', 'updated'}:
                        self.logger.info(f"Updated {entry_type_name}: {entry['name']} with values: {entry}")
                    else:
                        self.logger.error(f"Failed to update {entry_type_name}: {entry['name']}, Reason: {result['message']}")
                else:
                    self.logger.info(f"No changes detected for {entry['name']}. Skipping update.")

    def _generate_key_name(self, entry_type_name):
        return entry_type_name.replace(' ', '-')

    def post_new_entries(self, new_entries, scope_param, device_group_name, reference_aliases=None):
        for obj_type in self.obj_types:
            entry_type_name = obj_type.__name__
            if entry_type_name in new_entries and new_entries[entry_type_name]:
                entry_class = getattr(self.obj, entry_type_name)
                normalized_entries = [
                    self._normalize_entry_for_post(entry_type_name, entry, reference_aliases or {})
                    for entry in new_entries[entry_type_name]
                ]
                self.configure.post_entries(scope_param, normalized_entries, entry_class, extra_query_params='')
            else:
                message = f"No new {entry_type_name} entries to create from parsed data"
                if device_group_name:
                    message += f" (Device Group: {device_group_name})"
                message += f" for SCM {self.scope_param.split('=')[0]}: {self.scope_param.split('=')[1]}."
                self.logger.info(message)

    @staticmethod
    def _build_reference_aliases(parsed_data, current_objects):
        aliases = {}

        def collect(entries):
            if not isinstance(entries, list):
                return
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get('name')
                default_value = entry.get('default_value')
                if isinstance(name, str):
                    aliases.setdefault(name, name)
                if isinstance(default_value, str) and isinstance(name, str):
                    aliases[default_value] = name
                ip_netmask = entry.get('ip_netmask')
                if isinstance(name, str) and isinstance(ip_netmask, str):
                    aliases[name] = ip_netmask

        for entries in parsed_data.values():
            collect(entries)
        for entries in current_objects.values():
            collect(entries)

        return aliases

    def _normalize_entry_for_post(self, entry_type_name, entry, reference_aliases):
        normalized = deepcopy(entry)

        if entry_type_name == "InterfaceManagementProfile":
            permitted_ip = normalized.get("permitted_ip")
            if isinstance(permitted_ip, list):
                normalized["permitted_ip"] = [
                    item if isinstance(item, dict) else {"name": item}
                    for item in permitted_ip
                    if item
                ]
            return normalized

        if entry_type_name == "DHCPInterface":
            interface_name = normalized.get("name")
            if isinstance(interface_name, str):
                normalized["name"] = self._resolve_interface_reference(interface_name, reference_aliases)
            return normalized

        if entry_type_name == "LoopbackInterface":
            normalized.pop("default_value", None)
            interface_name = normalized.get("name")
            if isinstance(interface_name, str):
                normalized["name"] = self._resolve_interface_reference(interface_name, reference_aliases)
            ip_entries = normalized.get("ip")
            if isinstance(ip_entries, list):
                normalized["ip"] = self._normalize_ip_entries(ip_entries, reference_aliases)
            return normalized

        if entry_type_name == "EthernetInterface":
            aggregate_group = normalized.get("aggregate_group")
            if isinstance(aggregate_group, str):
                normalized["aggregate_group"] = self._resolve_interface_reference(aggregate_group, reference_aliases)
            layer3 = normalized.get("layer3")
            if isinstance(layer3, dict) and isinstance(layer3.get("ip"), list):
                layer3["ip"] = self._normalize_ip_entries(layer3["ip"], reference_aliases)
            return normalized

        if entry_type_name in {"Layer2Subinterface", "Layer3Subinterface"}:
            normalized.pop("default_value", None)
            parent_interface = normalized.get("parent_interface")
            if isinstance(parent_interface, str):
                normalized["parent_interface"] = self._resolve_interface_reference(parent_interface, reference_aliases)
            if entry_type_name == "Layer3Subinterface" and isinstance(normalized.get("ip"), list):
                normalized["ip"] = self._normalize_ip_entries(normalized["ip"], reference_aliases)
            return normalized

        if entry_type_name in {"VlanInterface", "TunnelInterface"}:
            if isinstance(normalized.get("ip"), list):
                normalized["ip"] = self._normalize_ip_entries(normalized["ip"], reference_aliases)
            if entry_type_name == "TunnelInterface":
                normalized.pop("default_value", None)
            return normalized

        if entry_type_name == "Zones":
            network = normalized.get("network")
            if isinstance(network, dict):
                for network_type in ("layer2", "layer3", "tap", "virtual_wire"):
                    references = network.get(network_type)
                    if isinstance(references, list):
                        network[network_type] = [
                            self._resolve_interface_reference(reference, reference_aliases)
                            if isinstance(reference, str) else reference
                            for reference in references
                        ]
            return normalized

        if entry_type_name == "RoutePrefixList":
            return self._normalize_route_prefix_list(normalized)

        if entry_type_name == "RouteAccessList":
            return self._normalize_route_access_list(normalized)

        if entry_type_name == "LogicalRouter":
            for vrf in normalized.get("vrf", []):
                interfaces = vrf.get("interface")
                if isinstance(interfaces, list):
                    vrf["interface"] = [
                        self._resolve_interface_reference(interface_name, reference_aliases)
                        if isinstance(interface_name, str) else interface_name
                        for interface_name in interfaces
                    ]
                routing_table = vrf.get("routing_table", {})
                for address_family in ("ip", "ipv6"):
                    static_routes = routing_table.get(address_family, {}).get("static_route", [])
                    for route in static_routes:
                        interface_name = route.get("interface")
                        if isinstance(interface_name, str):
                            route["interface"] = self._resolve_interface_reference(interface_name, reference_aliases)
                        nexthop = route.get("nexthop")
                        if isinstance(nexthop, dict) and isinstance(nexthop.get("tunnel"), str):
                            nexthop["tunnel"] = self._resolve_interface_reference(nexthop["tunnel"], reference_aliases)
                bgp = vrf.get("bgp")
                if isinstance(bgp, dict):
                    self._normalize_bgp_for_post(bgp)
                    for peer_group in bgp.get("peer_group", []):
                        for peer in peer_group.get("peer", []):
                            local_interface = peer.get("local_interface")
                            if isinstance(local_interface, str):
                                peer["local_interface"] = self._resolve_interface_reference(local_interface, reference_aliases)
            return normalized

        if entry_type_name == "IKEGateway":
            local_address = normalized.get("local_address")
            if isinstance(local_address, dict) and isinstance(local_address.get("interface"), str):
                local_address["interface"] = self._resolve_interface_reference(local_address["interface"], reference_aliases)
            return normalized

        if entry_type_name == "IPsecTunnel":
            tunnel_interface = normalized.get("tunnel_interface")
            if isinstance(tunnel_interface, str):
                normalized["tunnel_interface"] = self._resolve_interface_reference(tunnel_interface, reference_aliases)
            return normalized

        if entry_type_name == "PbfRule":
            forwarding = normalized.get("action", {}).get("forwarding")
            if isinstance(forwarding, dict):
                for key in ("egress_interface", "symmetric_return_interface"):
                    value = forwarding.get(key)
                    if isinstance(value, str):
                        forwarding[key] = self._resolve_interface_reference(value, reference_aliases)
            return normalized

        return normalized

    @staticmethod
    def _normalize_route_prefix_list(entry):
        if "type" in entry:
            return entry
        for family in ("ipv4", "ipv6"):
            rules = entry.pop(family, {}).get("prefix_list", [])
            if not rules:
                continue
            family_entry = []
            for rule in rules:
                normalized_rule = {
                    "name": rule.get("name"),
                    "action": rule.get("action", "permit"),
                    "prefix": {"entry": {"network": rule.get("prefix")}},
                }
                for key in ("exact", "ge", "le"):
                    if key in rule:
                        normalized_rule["prefix"]["entry"][key] = rule[key]
                family_entry.append(normalized_rule)
            entry["type"] = {family: {f"{family}_entry": family_entry}}
            break
        return entry

    @staticmethod
    def _normalize_route_access_list(entry):
        if "type" in entry:
            return entry
        rules = entry.pop("access_list", [])
        if not rules:
            return entry
        family = "ipv6" if any(":" in str(rule.get("source", "")) for rule in rules) else "ipv4"
        family_entry = []
        for rule in rules:
            family_entry.append(
                {
                    "name": rule.get("name"),
                    "action": rule.get("action", "permit"),
                    "source_address": {"address": rule.get("source", "any")},
                    "destination_address": {"address": rule.get("destination", "any")},
                }
            )
        entry["type"] = {family: {f"{family}_entry": family_entry}}
        return entry

    @staticmethod
    def _normalize_bgp_for_post(bgp):
        redistribution_profile = bgp.get("redistribution_profile")
        if isinstance(redistribution_profile, str):
            bgp["redistribution_profile"] = {
                "ipv4": {"unicast": redistribution_profile},
                "ipv6": {},
            }

        for peer_group in bgp.get("peer_group", []):
            if not isinstance(peer_group, dict):
                continue
            peer_group_type = peer_group.get("type")
            if isinstance(peer_group_type, str) and peer_group_type in {"ebgp", "ibgp"}:
                peer_group["type"] = {peer_group_type: {}}
            peer_group["address_family"] = SCMObjectManager._normalize_bgp_family_references(
                peer_group.get("address_family", {})
            )
            filtering_profile = peer_group.get("filtering_profile", {})
            if not isinstance(filtering_profile, dict):
                filtering_profile = {}
            for peer in peer_group.get("peer", []):
                if not isinstance(peer, dict):
                    continue
                peer_family = peer.get("address_family", {})
                for family, family_payload in peer_family.items():
                    if not isinstance(family_payload, dict):
                        continue
                    unicast = family_payload.get("unicast", {})
                    if isinstance(unicast, dict) and unicast.get("filtering_profile"):
                        filtering_profile[family] = unicast["filtering_profile"]
                peer["address_family"] = SCMObjectManager._normalize_bgp_family_references(peer_family)
            if filtering_profile:
                peer_group["filtering_profile"] = filtering_profile

    @staticmethod
    def _normalize_bgp_family_references(address_family):
        normalized = {}
        if not isinstance(address_family, dict):
            return normalized
        for family, family_payload in address_family.items():
            if isinstance(family_payload, str):
                normalized[family] = family_payload
                continue
            if not isinstance(family_payload, dict):
                continue
            unicast = family_payload.get("unicast", {})
            if isinstance(unicast, dict) and unicast.get("address_family_profile"):
                normalized[family] = unicast["address_family_profile"]
        return normalized

    @staticmethod
    def _resolve_interface_reference(interface_name, reference_aliases):
        resolved = reference_aliases.get(interface_name)
        if resolved:
            return resolved
        return normalize_scm_interface_name(interface_name)

    @staticmethod
    def _normalize_ip_entries(ip_entries, reference_aliases):
        normalized_entries = []
        for ip_entry in ip_entries:
            if isinstance(ip_entry, dict):
                value = ip_entry.get("name")
            else:
                value = ip_entry
            if not value:
                continue
            normalized_entries.append({"name": reference_aliases.get(value, value)})
        return normalized_entries

    def process_rules(self, rule_obj, parsed_data, scope_param, rule_type='security', limit='10000'):
        rule_data = {
            'security': ('security_pre_rules', 'security_post_rules'),
            'application-override': ('app_override_pre_rules', 'app_override_post_rules'),
            'decryption': ('decryption_pre_rules', 'decryption_post_rules'),
            'nat': ('nat_pre_rules', 'nat_post_rules')
        }
        pre_rules, post_rules = [parsed_data[key] for key in rule_data[rule_type]]

        current_rules_pre = self.fetch_rules(rule_obj, limit, position='pre')
        current_rules_post = self.fetch_rules(rule_obj, limit, position='post')
        
        current_rule_names_pre = {rule['name'] for rule in current_rules_pre}
        current_rule_names_post = {rule['name'] for rule in current_rules_post}
        
        rules_to_create_pre = [rule for rule in pre_rules if rule['name'] not in current_rule_names_pre]
        rules_to_create_post = [rule for rule in post_rules if rule['name'] not in current_rule_names_post]

        self.configure.set_max_workers(1 if rule_type == 'nat' else 6)

        rule_types = [
            (rules_to_create_pre, "position=pre", f"pre-{rule_type}-rules"),
            (rules_to_create_post, "position=post", f"post-{rule_type}-rules")
        ]

        for rules, extra_query_param, rule_type_name in rule_types:
            if rules:
                self.configure.post_entries(self.scope_param, rules, rule_obj, extra_query_params=extra_query_param)
            else:
                self.logger.info(f"No new {rule_type_name} to create from XML: {scope_param}")

        self.reorder_rules_if_needed(rule_obj, pre_rules, current_rules_pre, limit, position='pre')
        self.reorder_rules_if_needed(rule_obj, post_rules, current_rules_post, limit, position='post')

    def reorder_rules_if_needed(self, rule_obj, desired_rules, current_rules, limit, position):
        if not self.is_rule_order_correct(current_rules, desired_rules, limit):
            report = self.configure.check_and_reorder_rules(rule_obj, self.scope_param, desired_rules, limit='10000', position=position)
        else:
            current_order = Processor._rule_names_without_default(current_rules)
            desired_order = Processor._rule_names_without_default(desired_rules)
            report = {
                "rule_type": rule_obj.__name__,
                "position": position,
                "desired_order": desired_order,
                "desired_count": len(desired_order),
                "current_order_before": current_order,
                "current_order_after": current_order,
                "current_count_before": len(current_order),
                "current_count_after": len(current_order),
                "move_attempts": 0,
                "move_failures": [],
                "reordered": False,
                "verified": True,
                "verification_mode": "relative-subsequence",
                "matched_rule_count": len([rule_name for rule_name in current_order if rule_name in desired_order]),
                "fetch_failed": False,
                "error": "",
            }
            self.logger.info(
                "%s %s rule order already matches the source order.",
                position,
                rule_obj.__name__,
            )
        self.rule_order_verification.append(report)
        return report

    @staticmethod
    def is_rule_order_correct(current_rules, desired_rules, limit):
        current_rule_names = Processor._rule_names_without_default(current_rules)
        desired_rule_names = Processor._rule_names_without_default(desired_rules)
        return Processor._contains_rule_subsequence(current_rule_names, desired_rule_names)

    @staticmethod
    def normalize(obj):
        def convert_to_int_if_possible(item):
            if isinstance(item, str):
                try:
                    return int(item)
                except ValueError:
                    return item
            return item

        def sort_key(item):
            if isinstance(item, (list, tuple)):
                return (0, tuple(sort_key(convert_to_int_if_possible(i)) for i in item))
            elif isinstance(item, dict):
                return (1, tuple(sorted((k, sort_key(v)) for k, v in item.items())))
            elif isinstance(item, (int, float)):
                return (2, item)
            elif isinstance(item, str):
                try:
                    return (2, int(item))
                except ValueError:
                    return (3, item)
            elif isinstance(item, bool):
                return (4, item)
            else:
                return (5, str(item))

        def sort_nested(item):
            if isinstance(item, dict):
                return {k: sort_nested(v) for k, v in sorted(item.items()) 
                        if v not in (None, [], {}) and not (k == 'threat_name' and v == 'any')}
            elif isinstance(item, list):
                return sorted((sort_nested(convert_to_int_if_possible(i)) for i in item if i not in (None, [], {})), key=sort_key)
            else:
                return convert_to_int_if_possible(item)

        normalized = {k: v for k, v in obj.items() 
                    if k not in {'folder', 'snippet', 'type', 'fqdn', 'protocol', 'description'} 
                    and v not in (None, [], {})
                    and not (k == 'threat_name' and v == 'any')}
        
        for key, value in normalized.items():
            if isinstance(value, (list, dict)):
                normalized[key] = sort_nested(value)
            else:
                normalized[key] = convert_to_int_if_possible(value)

        return dict(sorted(normalized.items(), key=lambda x: sort_key(x[1])))
