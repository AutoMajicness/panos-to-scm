import xml.etree.ElementTree as ET
import logging
import re

class XMLParser:
    def __init__(self, file_path, config_type, device_group_name=None):
        self.file_path = file_path
        self.config_type = config_type
        self.device_group_name = device_group_name
        self.tree = ET.parse(self.file_path)
        self.root = self.tree.getroot()
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Initialized XMLParser with file_path: {self.file_path}, config_type: {self.config_type}, device_group_name: {self.device_group_name}")

    def _get_base_xpath(self, path_dict):
        if self.config_type == 'panorama/shared':
            return path_dict.get('shared')
        elif self.config_type == 'panorama/device-group':
            if self.device_group_name:
                try:
                    return path_dict.get('device-group', '').format(device_group_name=self.device_group_name)
                except KeyError:
                    self.logger.error(f"Device group name not found in path_dict: {path_dict}")
                    raise
            else:
                self.logger.error("Device group name is required for panorama/device-group but is None.")
                raise ValueError("Device group name is required for panorama/device-group but is None.")
        return path_dict.get('local')

    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize the name to match the API requirements.
        """
        sanitized_name = re.sub(r'[^a-zA-Z0-9._-]', '-', name)
        return sanitized_name[:63]

    def parse_config_and_set_scope(self, xml_file_path):
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        device_group_xpath = root.find('.//devices/entry/device-group')
        device_group_name = None
        scope_type = None
        scope_value = None

        if device_group_xpath is not None:
            config_choice = input("Is this a Panorama 'shared' configuration or 'device-group' configuration? Enter 'shared' or 'device-group': ").strip().lower()
            if config_choice == 'device-group':
                device_group_name = input("Enter the device-group name: ").strip()
                scope_type = input("Do you want to use a folder or a snippet? Enter 'folder' or 'snippet': ").strip().lower()
                scope_value = input(f'Enter the {scope_type} name (Use "All" for "Global"): ').strip()
                config_type = 'panorama/device-group'
            else:
                scope_type = input("Do you want to use a folder or a snippet? Enter 'folder' or 'snippet': ").strip().lower()
                scope_value = input(f'Enter the {scope_type} name (Use "All" for "Global"): ').strip()
                config_type = 'panorama/shared'
        else:
            scope_type = input("Do you want to use a folder or a snippet? Enter 'folder' or 'snippet': ").strip().lower()
            scope_value = input(f'Enter the {scope_type} name (Use "All" for "Global"): ').strip()
            config_type = 'local'

        scope_param = f"&{scope_type}={scope_value}"

        self.logger.debug(f"Parsed config and set scope: {scope_type}={scope_value}, config_type={config_type}, device_group_name={device_group_name}")

        return scope_param, config_type, device_group_name

    def etree_to_dict(self, element):
        if element is None:
            return None

        if len(element) == 0:
            return element.text

        result = {}
        for child in element:
            child_result = self.etree_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_result)
            else:
                result[child.tag] = child_result

        return result

    def parse_all(self):
        return {
            'URLCategory': self._parse_entries(self._url_category_entries),
            'URLAccessProfile': self._parse_entries(self._url_profiles_entries),
            'VulnerabilityProtectionProfile': self._parse_entries(self._vulnerability_profiles_entries),
            'AntiSpywareProfile': self._parse_entries(self._spyware_profiles_entries),
            'WildFireAntivirusProfile': self._parse_entries(self._antivirus_profiles_entries),
            'FileBlockingProfile': self._parse_entries(self._fileblocking_profiles_entries),
            'ProfileGroup': self._parse_entries(self._profile_group_entries),
            'Tag': self._parse_entries(self._tag_entries),
            'Address': self._parse_entries(self._address_entries),
            'AddressGroup': self._parse_entries(self._address_group_entries),
            'Service': self._parse_entries(self._service_entries),
            'ServiceGroup': self._parse_entries(self._service_group_entries),
            'ExternalDynamicList': self._parse_entries(self._edl_entries),
            'ApplicationFilter': self._parse_entries(self._application_filter_entries),
            'ApplicationGroup': self._parse_entries(self._application_group_entries),
            'Schedule': self._parse_entries(self._schedule_entries),
            'app_override_pre_rules': self._parse_entries(self._app_override_pre_rules_entries),
            'app_override_post_rules': self._parse_entries(self._app_override_post_rules_entries),
            'security_pre_rules': self._parse_entries(self._security_pre_rules_entries),
            'security_post_rules': self._parse_entries(self._security_post_rules_entries),
            'nat_pre_rules': self._parse_entries(self._nat_pre_rules_entries),
            'nat_post_rules': self._parse_entries(self._nat_post_rules_entries),
            'Application': self._parse_entries(self._application_entries),
            'InterfaceManagementProfile': self._parse_entries(self._interface_management_profile_entries),
            'ZoneProtectionProfile': self._parse_entries(self._zone_protection_profile_entries),
            'DHCPInterface': self._parse_entries(self._dhcp_interface_entries),
            'AggregateInterface': self._parse_entries(self._aggregate_interface_entries),
            'EthernetInterface': self._parse_entries(self._ethernet_interface_entries),
            'Layer2Subinterface': self._parse_entries(self._layer2_subinterface_entries),
            'Layer3Subinterface': self._parse_entries(self._layer3_subinterface_entries),
            'VlanInterface': self._parse_entries(self._vlan_interface_entries),
            'TunnelInterface': self._parse_entries(self._tunnel_interface_entries),
            'LoopbackInterface': self._parse_entries(self._loopback_interface_entries),
            'OSPFAuthProfile': self._parse_entries(self._ospf_auth_profile_entries),
            'BgpAuthProfile': self._parse_entries(self._bgp_auth_profile_entries),
            'BgpAddressFamilyProfile': self._parse_entries(self._bgp_address_family_profile_entries),
            'BgpFilteringProfile': self._parse_entries(self._bgp_filtering_profile_entries),
            'LogicalRouter': self._parse_entries(self._logical_router_entries),
            'RoutePrefixList': self._parse_entries(self._route_prefix_list_entries),
            'RouteAccessList': self._parse_entries(self._route_access_list_entries),
            'RouteCommunityList': self._parse_entries(self._route_community_list_entries),
            'RoutePathAccessList': self._parse_entries(self._route_path_access_list_entries),
            'BgpRouteMap': self._parse_entries(self._bgp_route_map_entries),
            'BgpRouteMapRedistribution': self._parse_entries(self._bgp_route_map_redistribution_entries),
            'BgpRedistributionProfile': self._parse_entries(self._bgp_redistribution_profile_entries),
            'IKECryptoProfile': self._parse_entries(self._ike_crypto_profile_entries),
            'IPsecCryptoProfile': self._parse_entries(self._ipsec_crypto_profile_entries),
            'IKEGateway': self._parse_entries(self._ike_gateway_entries),
            'IPsecTunnel': self._parse_entries(self._ipsec_tunnel_entries),
            'PbfRule': self._parse_entries(self._pbf_rule_entries),
            'Zones': self._parse_entries(self._zones),
            'DecryptionProfile': self._parse_entries(self._decryption_profiles_entries),
            'decryption_pre_rules': self._parse_entries(self._decryption_pre_rules_entries),
            'decryption_post_rules': self._parse_entries(self._decryption_post_rules_entries),
            'DNSSecurityProfile': self._parse_entries(self._dns_security_profiles_entries),
            'HipObject': self._parse_entries(self._hip_objects_entries),
            'HipProfile': self._parse_entries(self._hip_profiles_entries),
            '_migration_warnings': self._migration_warning_entries(),
        }

    def parse_specific_types(self, object_types):
        parsed_data = {}
        method_map = {
            'URLCategory': self._url_category_entries,
            'URLAccessProfile': self._url_profiles_entries,
            'VulnerabilityProtectionProfile': self._vulnerability_profiles_entries,
            'AntiSpywareProfile': self._spyware_profiles_entries,
            'WildFireAntivirusProfile': self._antivirus_profiles_entries,
            'FileBlockingProfile': self._fileblocking_profiles_entries,
            'ProfileGroup': self._profile_group_entries,
            'Tag': self._tag_entries,
            'Address': self._address_entries,
            'AddressGroup': self._address_group_entries,
            'Service': self._service_entries,
            'ServiceGroup': self._service_group_entries,
            'ExternalDynamicList': self._edl_entries,
            'ApplicationFilter': self._application_filter_entries,
            'ApplicationGroup': self._application_group_entries,
            'Schedule': self._schedule_entries,
            'app_override_pre_rules': self._app_override_pre_rules_entries,
            'app_override_post_rules': self._app_override_post_rules_entries,
            'security_pre_rules': self._security_pre_rules_entries,
            'security_post_rules': self._security_post_rules_entries,
            'nat_pre_rules': self._nat_pre_rules_entries,
            'nat_post_rules': self._nat_post_rules_entries,
            'Application': self._application_entries,
            'InterfaceManagementProfile': self._interface_management_profile_entries,
            'ZoneProtectionProfile': self._zone_protection_profile_entries,
            'DHCPInterface': self._dhcp_interface_entries,
            'AggregateInterface': self._aggregate_interface_entries,
            'EthernetInterface': self._ethernet_interface_entries,
            'Layer2Subinterface': self._layer2_subinterface_entries,
            'Layer3Subinterface': self._layer3_subinterface_entries,
            'VlanInterface': self._vlan_interface_entries,
            'TunnelInterface': self._tunnel_interface_entries,
            'LoopbackInterface': self._loopback_interface_entries,
            'OSPFAuthProfile': self._ospf_auth_profile_entries,
            'BgpAuthProfile': self._bgp_auth_profile_entries,
            'BgpAddressFamilyProfile': self._bgp_address_family_profile_entries,
            'BgpFilteringProfile': self._bgp_filtering_profile_entries,
            'LogicalRouter': self._logical_router_entries,
            'RoutePrefixList': self._route_prefix_list_entries,
            'RouteAccessList': self._route_access_list_entries,
            'RouteCommunityList': self._route_community_list_entries,
            'RoutePathAccessList': self._route_path_access_list_entries,
            'BgpRouteMap': self._bgp_route_map_entries,
            'BgpRouteMapRedistribution': self._bgp_route_map_redistribution_entries,
            'BgpRedistributionProfile': self._bgp_redistribution_profile_entries,
            'IKECryptoProfile': self._ike_crypto_profile_entries,
            'IPsecCryptoProfile': self._ipsec_crypto_profile_entries,
            'IKEGateway': self._ike_gateway_entries,
            'IPsecTunnel': self._ipsec_tunnel_entries,
            'PbfRule': self._pbf_rule_entries,
            'Zones': self._zones,
            'DecryptionProfile': self._decryption_profiles_entries,
            'decryption_pre_rules': self._decryption_pre_rules_entries,
            'decryption_post_rules': self._decryption_post_rules_entries,
            'DNSSecurityProfile': self._dns_security_profiles_entries,
            'HipObject': self._hip_objects_entries,
            'HipProfile': self._hip_profiles_entries,
        }

        for obj_type in object_types:
            if obj_type in method_map:
                parsed_data[obj_type] = method_map[obj_type]()
            else:
                self.logger.warning(f"Unknown object type requested: {obj_type}")

        parsed_data['_migration_warnings'] = self._migration_warning_entries()
        return parsed_data

    def _parse_entries(self, parse_function):
        return parse_function()

    def _migration_warning_entries(self):
        if self.config_type != 'local':
            return []

        warnings = []
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            router_name = router_entry.get('name') or "unknown"
            if router_entry.find('ecmp') is not None:
                warnings.append(
                    self._migration_warning(
                        "LogicalRouter",
                        router_name,
                        f"network.virtual-router.entry[{router_name}].ecmp",
                        "unsupported-panos-routing-node",
                        "PAN-OS ECMP settings are not migrated yet; review and recreate ECMP behavior in SCM if required.",
                    )
                )

            for route_family, route_path in [
                ("ip", "routing-table/ip/static-route/entry"),
                ("ipv6", "routing-table/ipv6/static-route/entry"),
            ]:
                for route_entry in router_entry.findall(route_path):
                    route_name = route_entry.get('name') or "unnamed-static-route"
                    if route_entry.find('nexthop/qualified-next-hop') is not None:
                        warnings.append(
                            self._migration_warning(
                                "LogicalRouter",
                                router_name,
                                f"network.virtual-router.entry[{router_name}].routing-table.{route_family}.static-route.entry[{route_name}].nexthop.qualified-next-hop",
                                "unsupported-panos-routing-node",
                                "PAN-OS qualified-next-hop static route data is not migrated because the target SCM static route field is not implemented in this tool yet.",
                            )
                        )
        return warnings

    @staticmethod
    def _migration_warning(object_type, name, path, code, message, severity="warning"):
        return {
            "object_type": object_type,
            "name": name,
            "path": path,
            "code": code,
            "severity": severity,
            "message": message,
        }

    def _url_category_entries(self):
        # Example: You can refactor individual parse methods in a similar way
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/custom-url-category/entry',
            'shared': './shared/profiles/custom-url-category/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/custom-url-category/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        url_category = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            list_elements = entry.find('list')
            type_element = entry.find('type')

            members = [member.text for member in list_elements.findall('member')] if list_elements is not None else []
            
            url_categorys = {
                'name': name,
                'description': description.text if description is not None else None,
                'type': type_element.text if type_element is not None else None,
                'list': members if members else None
            }

            filtered_url_categories = {k: v for k, v in url_categorys.items() if v is not None}
            url_category.append(filtered_url_categories)

        return url_category

    def _url_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/url-filtering/entry',
            'shared': './shared/profiles/url-filtering/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/url-filtering/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        url_profiles = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            block_elements = entry.find('block')
            alert_elements = entry.find('alert')
            allow_elements = entry.find('allow')
            continue_elements = entry.find('continue')

            url_profile = {
                'name': name,
                'description': description.text if description is not None else None,
                'block': [member.text for member in block_elements.findall('member')] if block_elements is not None else None,
                'alert': [member.text for member in alert_elements.findall('member')] if alert_elements is not None else None,
                'allow': [member.text for member in allow_elements.findall('member')] if allow_elements is not None else None,
                'continue': [member.text for member in continue_elements.findall('member')] if continue_elements is not None else None,
            }

            filtered_url_profiles = {k: v for k, v in url_profile.items() if v is not None}
            url_profiles.append(filtered_url_profiles)

        return url_profiles
    
    def _hip_objects_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/hip-objects/entry',
            'shared': './shared/profiles/hip-objects/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/hip-objects/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        hip_objects = []

        for entry in self.root.findall(base_xpath):
            hip_object = {
                'name': entry.get('name'),
            }
            
            description = entry.findtext('description')
            if description is not None:
                hip_object['description'] = description

            for category in ['host-info', 'anti-malware', 'patch-management', 'disk-backup', 'certificate', 'custom-checks', 'disk-encryption', 'firewall', 'data-loss-prevention']:
                category_elem = entry.find(category)
                if category_elem is not None:
                    parsed_category = self._parse_category(category_elem)
                    if parsed_category:  # Only add non-empty categories
                        hip_object[category.replace('-', '_')] = parsed_category

            # Remove any empty dictionaries
            hip_object = {k: v for k, v in hip_object.items() if v}

            hip_objects.append(hip_object)

        return hip_objects

    def _parse_category(self, category_elem):
        result = {}
        criteria = category_elem.find('criteria')
        if criteria is not None:
            result['criteria'] = self._parse_criteria(criteria, category_elem.tag)

        vendor = category_elem.find('vendor')
        if vendor is not None:
            result['vendor'] = self._parse_vendor(vendor)

        exclude_vendor = category_elem.find('exclude-vendor')
        if exclude_vendor is not None:
            try:
                result['exclude_vendor'] = self._toBool(exclude_vendor.text)
            except ValueError:
                # If the value is not 'yes' or 'no', we'll keep the original text
                result['exclude_vendor'] = exclude_vendor.text.lower()

        return result

    def _parse_criteria(self, criteria_elem, category):
        criteria = {}
        if category == 'host-info':
            for child in criteria_elem:
                if child.tag == 'os':
                    criteria['os'] = self._parse_os(child)
                elif child.tag in ['domain', 'client-version', 'host-id', 'host-name', 'serial-number']:
                    criteria[child.tag] = self._parse_comparison(child)
                elif child.tag == 'managed':
                    criteria['managed'] = child.text.lower() == 'yes'
        else:
            for child in criteria_elem:
                if child.tag in ['is-installed', 'managed', 'disk-encrypted', 'jailbroken', 'passcode-set']:
                    criteria[child.tag.replace('-', '_')] = child.text.lower() == 'yes'
                elif child.tag in ['is-enabled', 'real-time-protection']:
                    criteria[child.tag.replace('-', '_')] = child.text.lower()
                elif child.tag == 'virdef-version':
                    criteria['virdef_version'] = self._parse_comparison(child)
                elif child.tag == 'certificate-profile':
                    criteria['certificate_profile'] = child.text
                elif child.tag in ['product-version', 'last-scan-time', 'last-backup-time', 'client-version', 'domain', 'host-id', 'host-name', 'serial-number', 'imei', 'model', 'phone-number', 'tag']:
                    criteria[child.tag.replace('-', '_')] = self._parse_comparison(child)
                elif child.tag == 'os':
                    criteria['os'] = self._parse_os(child)
                elif child.tag == 'missing-patches':
                    missing_patches = {'check': child.findtext('check')}
                    patches = [patch.text for patch in child.findall('patches/member')]
                    if patches:
                        missing_patches['patches'] = patches
                    criteria['missing_patches'] = missing_patches
                elif child.tag == 'encrypted-locations':
                    criteria['encrypted_locations'] = [
                        {
                            'name': loc.findtext('name'),
                            'encryption_state': self._parse_comparison(loc.find('encryption-state'))
                        }
                        for loc in child.findall('entry')
                    ]
                # Add more specific parsing for other criteria as needed

        return criteria

    def _parse_comparison(self, elem):
        for comp in ['greater-equal', 'greater-than', 'is', 'is-not', 'less-equal', 'less-than', 'contains', 'within', 'not-within']:
            comp_elem = elem.find(comp)
            if comp_elem is not None:
                if comp == 'within' and elem.tag == 'virdef-version':
                    days = comp_elem.findtext('days')
                    if days is not None:
                        return {comp: {'days': int(days)}}
                return {comp.replace('-', '_'): comp_elem.text}
        return None

    def _parse_os(self, os_elem):
        contains = os_elem.find('contains')
        if contains is not None:
            for vendor in ['Microsoft', 'Apple', 'Google', 'Linux', 'Other']:
                vendor_elem = contains.find(vendor)
                if vendor_elem is not None:
                    return {'contains': {vendor: vendor_elem.text}}
        return None

    def _parse_vendor(self, vendor_elem):
        vendors = []
        for entry in vendor_elem.findall('entry'):
            vendor = {
                'name': entry.get('name'),
                'product': [prod.text for prod in entry.findall('product/member')]
            }
            vendors.append(vendor)
        return vendors

    def _hip_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/hip-profiles/entry',
            'shared': './shared/profiles/hip-profiles/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/hip-profiles/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        hip_profiles = []

        for entry in self.root.findall(base_xpath):
            hip_profile = {
                'name': entry.get('name')
            }

            # Parse description if present
            description = entry.findtext('description')
            if description is not None:
                hip_profile['description'] = description[:255]  # Limit to 255 characters as per API spec

            # Parse match
            match = entry.findtext('match')
            if match is not None:
                hip_profile['match'] = match[:2048]  # Limit to 2048 characters as per API spec

            # Validate name length
            if len(hip_profile['name']) > 31:
                self.logger.warning(f"HIP profile name '{hip_profile['name']}' exceeds 31 characters. It will be truncated.")
                hip_profile['name'] = hip_profile['name'][:31]

            # Validate name characters
            if not re.match(r'^[0-9a-zA-Z._-]+$', hip_profile['name']):
                self.logger.warning(f"HIP profile name '{hip_profile['name']}' contains invalid characters. It should only contain alphanumeric characters, dots, underscores, and hyphens.")

            hip_profiles.append(hip_profile)

        return hip_profiles

    def _vulnerability_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/vulnerability/entry',
            'shared': './shared/profiles/vulnerability/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/vulnerability/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        vulnerability_profiles = []
        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            rules = []
            for rule_entry in profile_entry.findall('./rules/entry'):
                rule_name = rule_entry.get('name')
                severity_elements = rule_entry.find('severity')
                severities = [member.text for member in severity_elements.findall('member')] if severity_elements is not None else []
                cve_elements = rule_entry.find('cve')
                cves = [member.text for member in cve_elements.findall('member')] if cve_elements is not None else []
                category = rule_entry.find('category')
                packet_capture = rule_entry.find('packet-capture')
                host = rule_entry.find('host')
                threat_name = rule_entry.find('threat-name')
                vendor_id_elements = rule_entry.find('vendor-id')
                vendor_ids = [member.text for member in vendor_id_elements.findall('member')] if vendor_id_elements is not None else []
                action = {}
                for action_type in rule_entry.find('action'):
                    if action_type.tag != 'default':
                        action[action_type.tag.replace('-', '_')] = {}

                rule = {
                    'name': rule_name,
                    'severity': severities,
                    'cve': cves,
                    'category': category.text,
                    'packet_capture': packet_capture.text if packet_capture is not None else 'disable',
                    'host': host.text if host is not None else 'any',
                    'threat_name': threat_name.text if threat_name is not None else 'any',
                    'vendor_id': vendor_ids
                }

                if action:
                    rule['action'] = action

                rules.append(rule)

            vulnerability_profile = {
                'name': profile_name,
                'rules': rules
            }

            if description:
                vulnerability_profile['description'] = description

            vulnerability_profiles.append(vulnerability_profile)

        return vulnerability_profiles

    def _spyware_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/spyware/entry',
            'shared': './shared/profiles/spyware/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/spyware/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        spyware_profiles = []
        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            rules = []
            for rule_entry in profile_entry.findall('./rules/entry'):
                rule_name = rule_entry.get('name')
                threat_name_element = rule_entry.find('threat-name')
                threat_name = threat_name_element.text if threat_name_element is not None else None
                severity_elements = rule_entry.find('severity')
                severities = [member.text for member in severity_elements.findall('member')] if severity_elements is not None else []
                category = rule_entry.find('category')
                packet_capture = rule_entry.find('packet-capture')
                action = {}
                for action_type in rule_entry.find('action'):
                    if action_type.tag != 'default':
                        action[action_type.tag.replace('-', '_')] = {}

                rule = {
                    'name': rule_name,
                    'severity': severities,
                    'category': category.text if category is not None else 'any',
                    'packet_capture': packet_capture.text if packet_capture is not None else 'disable'
                }

                if threat_name and threat_name.lower() != 'any':
                    rule['threat_name'] = threat_name
                if action:
                    rule['action'] = action

                rules.append(rule)

            spyware_profile = {
                'name': profile_name,
                'rules': rules
            }
            if description:
                spyware_profile['description'] = description

            spyware_profiles.append(spyware_profile)

        return spyware_profiles

    def _dns_security_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/spyware/entry',
            'shared': './shared/profiles/spyware/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/spyware/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        dns_security_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            botnet_domains_element = profile_entry.find('botnet-domains')
            if botnet_domains_element is not None:
                dns_security_profile = {
                    'name': profile_name,
                    'botnet_domains': {}
                }

                # Handle dns_security_categories
                dns_security_categories = []
                for category_entry in botnet_domains_element.findall('./dns-security-categories/entry'):
                    category = {
                        'name': category_entry.get('name'),
                        'log_level': category_entry.find('log-level').text if category_entry.find('log-level') is not None else 'default',
                        'action': category_entry.find('action').text if category_entry.find('action') is not None else 'default',
                        'packet_capture': category_entry.find('packet-capture').text if category_entry.find('packet-capture') is not None else 'disable'
                    }
                    dns_security_categories.append(category)

                # Handle lists
                lists = []
                for list_entry in botnet_domains_element.findall('./lists/entry'):
                    action_element = list_entry.find('./action/*')
                    action = {action_element.tag: {}} if action_element is not None else {}
                    list_item = {
                        'name': list_entry.get('name'),
                        'action': action,
                        'packet_capture': list_entry.find('packet-capture').text if list_entry.find('packet-capture') is not None else 'disable'
                    }
                    lists.append(list_item)

                # Handle sinkhole
                sinkhole_element = botnet_domains_element.find('sinkhole')
                sinkhole = {
                    'ipv4_address': 'pan-sinkhole-default-ip',
                    'ipv6_address': '::1'
                }
                if sinkhole_element is not None:
                    ipv4_element = sinkhole_element.find('ipv4-address')
                    ipv6_element = sinkhole_element.find('ipv6-address')
                    
                    if ipv4_element is not None:
                        ipv4_value = ipv4_element.text
                        # Ensure ipv4_address is within allowed values
                        if ipv4_value in ['127.0.0.1', 'pan-sinkhole-default-ip']:
                            sinkhole['ipv4_address'] = ipv4_value
                        else:
                            self.logger.warning(f"Invalid ipv4_address '{ipv4_value}' for profile '{profile_name}'. Using default 'pan-sinkhole-default-ip'.")
                    
                    if ipv6_element is not None:
                        ipv6_value = ipv6_element.text
                        # Ensure ipv6_address is the allowed value
                        if ipv6_value == '::1':
                            sinkhole['ipv6_address'] = ipv6_value
                        else:
                            self.logger.warning(f"Invalid ipv6_address '{ipv6_value}' for profile '{profile_name}'. Using default '::1'.")

                # Handle whitelist
                whitelist = []
                for whitelist_entry in botnet_domains_element.findall('./whitelist/entry'):
                    whitelist_item = {
                        'name': whitelist_entry.get('name'),
                        'description': whitelist_entry.find('description').text if whitelist_entry.find('description') is not None else ''
                    }
                    whitelist.append(whitelist_item)

                # Ensure there is at least one placeholder in the whitelist if it's empty
                if not whitelist:
                    whitelist.append({'name': 'placeholder', 'description': 'placeholder'})

                if dns_security_categories:
                    dns_security_profile['botnet_domains']['dns_security_categories'] = dns_security_categories
                dns_security_profile['botnet_domains']['lists'] = lists
                dns_security_profile['botnet_domains']['sinkhole'] = sinkhole
                dns_security_profile['botnet_domains']['whitelist'] = whitelist

                dns_security_profiles.append(dns_security_profile)

        return dns_security_profiles

    def _decryption_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/decryption/entry',
            'shared': './shared/profiles/decryption/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/decryption/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        decryption_profiles = []

        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')

            ssl_forward_proxy = {
                "auto_include_altname": False,
                "block_client_cert": False,
                "block_expired_certificate": False,
                "block_timeout_cert": False,
                "block_tls13_downgrade_no_resource": False,
                "block_unknown_cert": False,
                "block_unsupported_cipher": False,
                "block_unsupported_version": False,
                "block_untrusted_issuer": False,
                "restrict_cert_exts": False,
                "strip_alpn": False
            }
            
            ssl_inbound_proxy = {
                "block_if_hsm_unavailable": False,
                "block_if_no_resource": False,
                "block_unsupported_cipher": False,
                "block_unsupported_version": False
            }
            
            ssl_no_proxy = {
                "block_expired_certificate": False,
                "block_untrusted_issuer": False
            }
            
            ssl_protocol_settings = {
                "auth_algo_md5": False,
                "auth_algo_sha1": True,
                "auth_algo_sha256": True,
                "auth_algo_sha384": True,
                "enc_algo_3des": True,
                "enc_algo_aes_128_cbc": True,
                "enc_algo_aes_128_gcm": True,
                "enc_algo_aes_256_cbc": True,
                "enc_algo_aes_256_gcm": True,
                "enc_algo_chacha20_poly1305": True,
                "enc_algo_rc4": True,
                "keyxchg_algo_dhe": True,
                "keyxchg_algo_ecdhe": True,
                "keyxchg_algo_rsa": True,
                "max_version": "tls1-2",
                "min_version": "tls1-0"
            }

            # Parse ssl-forward-proxy
            ssl_forward_proxy_element = profile_entry.find('ssl-forward-proxy')
            if ssl_forward_proxy_element is not None:
                for key in ssl_forward_proxy.keys():
                    element = ssl_forward_proxy_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_forward_proxy[key] = element.text.lower() == 'yes'

            # Parse ssl-inbound-proxy
            ssl_inbound_proxy_element = profile_entry.find('ssl-inbound-proxy')
            if ssl_inbound_proxy_element is not None:
                for key in ssl_inbound_proxy.keys():
                    element = ssl_inbound_proxy_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_inbound_proxy[key] = element.text.lower() == 'yes'

            # Parse ssl-no-proxy
            ssl_no_proxy_element = profile_entry.find('ssl-no-proxy')
            if ssl_no_proxy_element is not None:
                for key in ssl_no_proxy.keys():
                    element = ssl_no_proxy_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_no_proxy[key] = element.text.lower() == 'yes'

            # Parse ssl-protocol-settings
            ssl_protocol_settings_element = profile_entry.find('ssl-protocol-settings')
            if ssl_protocol_settings_element is not None:
                for key in ssl_protocol_settings.keys():
                    element = ssl_protocol_settings_element.find(key.replace("_", "-"))
                    if element is not None:
                        ssl_protocol_settings[key] = element.text.lower() == 'yes'
                
                max_version_element = ssl_protocol_settings_element.find('max-version')
                if max_version_element is not None:
                    ssl_protocol_settings['max_version'] = max_version_element.text
                
                min_version_element = ssl_protocol_settings_element.find('min-version')
                if min_version_element is not None:
                    ssl_protocol_settings['min_version'] = min_version_element.text

            decryption_profile = {
                "name": profile_name,
                "ssl_forward_proxy": ssl_forward_proxy,
                "ssl_inbound_proxy": ssl_inbound_proxy,
                "ssl_no_proxy": ssl_no_proxy,
                "ssl_protocol_settings": ssl_protocol_settings
            }

            decryption_profiles.append(decryption_profile)

        return decryption_profiles

    def _antivirus_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/virus/entry',
            'shared': './shared/profiles/virus/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/virus/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        antivirus_profiles = []
        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            packet_capture = profile_entry.find('packet-capture') is not None and profile_entry.find('packet-capture').text.lower() == 'enabled'
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            decoders = []
            for decoder_entry in profile_entry.findall('./decoder/entry'):
                decoder_name = decoder_entry.get('name')
                action = decoder_entry.find('action').text.replace('-', '_') if decoder_entry.find('action') is not None else None
                wildfire_action = decoder_entry.find('wildfire-action').text.replace('-', '_') if decoder_entry.find('wildfire-action') is not None else None
                mlav_action = decoder_entry.find('mlav-action').text.replace('-', '_') if decoder_entry.find('mlav-action') is not None else None

                decoder = {
                    'name': decoder_name,
                    'action': action,
                    'wildfire_action': wildfire_action,
                    'mlav_action': mlav_action
                }
                decoders.append(decoder)

            antivirus_profile = {
                'name': profile_name,
                'packet_capture': packet_capture,
                'rules': [
                    {
                        'analysis': 'public-cloud',
                        'application': ['any'],
                        'direction': "both",
                        'file_type': ['any'],
                        'name': 'all-files'
                    }
                ],
            }

            if description:
                antivirus_profile['description'] = description

            antivirus_profiles.append(antivirus_profile)

        return antivirus_profiles

    def _fileblocking_profiles_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profiles/file-blocking/entry',
            'shared': './shared/profiles/file-blocking/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profiles/file-blocking/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        fileblocking_profiles = []
        for profile_entry in self.root.findall(base_xpath):
            profile_name = profile_entry.get('name')
            description_element = profile_entry.find('description')
            description = description_element.text if description_element is not None else None

            rules = []
            for rule_entry in profile_entry.findall('./rules/entry'):
                rule_name = rule_entry.get('name')
                application_elements = rule_entry.find('application')
                applications = [member.text for member in application_elements.findall('member')]
                file_type_elements = rule_entry.find('file-type')
                file_types = [member.text for member in file_type_elements.findall('member')]
                direction = rule_entry.find('direction').text
                action = rule_entry.find('action').text

                rule = {
                    'name': rule_name,
                    'application': applications,
                    'file_type': file_types,
                    'direction': direction,
                    'action': action
                }

                rules.append(rule)

            fileblocking_profile = {
                'name': profile_name,
                'rules': rules
            }
            if description:
                fileblocking_profile['description'] = description

            fileblocking_profiles.append(fileblocking_profile)

        return fileblocking_profiles

    def _profile_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/profile-group/entry',
            'shared': './shared/profile-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/profile-group/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        profile_groups = []
        for entry in self.root.findall(base_xpath):
            profile_group_name = entry.get('name')

            profile_group = {'name': profile_group_name}

            virus_members = [member.text for member in entry.findall('./virus/member')]
            if virus_members:
                profile_group['virus_and_wildfire_analysis'] = virus_members

            spyware_members = [member.text for member in entry.findall('./spyware/member')]
            if spyware_members:
                profile_group['spyware'] = spyware_members
                profile_group['dns_security'] = spyware_members

            vulnerability_members = [member.text for member in entry.findall('./vulnerability/member')]
            if vulnerability_members:
                profile_group['vulnerability'] = vulnerability_members

            url_filtering_members = [member.text for member in entry.findall('./url-filtering/member')]
            if url_filtering_members:
                profile_group['url_filtering'] = url_filtering_members

            profile_groups.append(profile_group)

        return profile_groups

    @staticmethod
    def _map_color_code_to_color(color_code):
        colorCodes = {
            'color1': 'Red',
            'color2': 'Green',
            'color3': 'Blue',
            'color4': 'Yellow',
            'color5': 'Copper',
            'color6': 'Orange',
            'color7': 'Purple',
            'color8': 'Gray',
            'color9': 'Light Green',
            'color10': 'Cyan',
            'color11': 'Light Gray',
            'color12': 'Blue Gray',
            'color13': 'Lime',
            'color14': 'Black',
            'color15': 'Gold',
            'color16': 'Brown',
            'color17': 'Olive',
            'color19': 'Maroon',
            'color20': 'Red-Orange',
            'color21': 'Yellow-Orange',
            'color22': 'Forest Green',
            'color23': 'Turquoise Blue',
            'color24': 'Azure Blue',
            'color25': 'Cerulean Blue',
            'color26': 'Midnight Blue',
            'color27': 'Medium Blue',
            'color28': 'Cobalt Blue',
            'color29': 'Violet Blue',
            'color30': 'Blue Violet',
            'color31': 'Medium Violet',
            'color32': 'Medium Rose',
            'color33': 'Lavender',
            'color34': 'Orchid',
            'color35': 'Thistle',
            'color36': 'Peach',
            'color37': 'Salmon',
            'color38': 'Magenta',
            'color39': 'Red Violet',
            'color40': 'Mahogany',
            'color41': 'Burnt Sienna',
            'color42': 'Chestnut'
            }
        return colorCodes.get(color_code)

    def _tag_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/tag/entry',
            'shared': './shared/tag/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/tag/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        tags = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            tag_color_element = entry.find('color')
            tag_color = self._map_color_code_to_color(tag_color_element.text) if tag_color_element is not None else None

            tag = {'name': name}
            if tag_color:
                tag['color'] = tag_color

            tags.append(tag)

        return tags

    def _address_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/address/entry',
            'shared': './shared/address/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/address/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        addresses = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            ip_netmask = entry.find('ip-netmask')
            ip_range = entry.find('ip-range')
            fqdn = entry.find('fqdn')
            description = entry.find('description')
            tag = entry.find('tag')

            address = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
                'ip_netmask': ip_netmask.text if ip_netmask is not None else None,
                'ip_range': ip_range.text if ip_range is not None else None,
                'fqdn': fqdn.text if fqdn is not None else None
            }

            filtered_address = {k: v for k, v in address.items() if v is not None}
            addresses.append(filtered_address)

        return addresses

    def _address_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/address-group/entry',
            'shared': './shared/address-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/address-group/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        address_groups = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            static = entry.find('static')
            dynamic = entry.find('dynamic/filter')
            tag = entry.find('tag')

            address_group = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
                'dynamic': {'filter': dynamic.text} if dynamic is not None else None,
                'static': [member.text for member in static.findall('member')] if static is not None else None
            }

            filtered_address_group = {k: v for k, v in address_group.items() if v is not None}
            address_groups.append(filtered_address_group)

        return address_groups

    def _service_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/service/entry',
            'shared': './shared/service/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/service/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        service_entries = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            description = entry.find('description')
            tag = entry.find('tag')
            protocol = entry.find('.//protocol')

            service_data = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
            }

            if protocol is not None:
                for proto in protocol:
                    if proto.tag in ('tcp', 'udp'):
                        port = proto.find('port')
                        source_port = proto.find('source-port')
                        protocol_data = {
                            'port': port.text if port is not None else None,
                            'source_port': source_port.text if source_port is not None else None,
                        }
                        filtered_protocol_data = {k: v for k, v in protocol_data.items() if v is not None}
                        service_data.update({
                            'protocol': {
                                proto.tag: filtered_protocol_data
                            }
                        })

            filtered_services = {k: v for k, v in service_data.items() if v is not None}
            service_entries.append(filtered_services)

        return service_entries

    def _service_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/service-group/entry',
            'shared': './shared/service-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/service-group/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        service_groups = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            members = entry.find('members')
            tag = entry.find('tag')

            service_group = {
                'name': name,
                'tag': [member.text for member in tag.findall('member')] if tag is not None else [],
                'members': [member.text for member in members.findall('member')] if members is not None else []
            }

            filtered_service_groups = {k: v for k, v in service_group.items() if v is not None}
            service_groups.append(filtered_service_groups)

        return service_groups

    def _edl_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/external-list/entry',
            'shared': './shared/external-list/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/external-list/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        edl_entries = []
        for entry in self.root.findall(base_xpath):
            edl_entry = self._parse_edl_entry(entry)
            if edl_entry:
                edl_entries.append(edl_entry)

        return edl_entries

    def _parse_edl_entry(self, entry):
        edl_entry_name = entry.get('name')
        type_element = entry.find('type')
        for edl_type in ['url', 'ip', 'domain']:
            element = type_element.find(edl_type)
            if element is not None:
                return self._create_edl_entry_dict(edl_entry_name, edl_type, element)
        return None

    def _create_edl_entry_dict(self, name, edl_type, element):
        # Find the recurring element and determine the type (e.g., daily, weekly, monthly)
        recurring_element = element.find('recurring')
        recurring = {}
        if recurring_element is not None:
            for child in recurring_element:
                recurring_type = child.tag
                recurring_detail = {}
                at_element = child.find('at')
                if at_element is not None:
                    recurring_detail['at'] = at_element.text
                
                # Handle different types of recurrence
                if recurring_type == 'daily':
                    if at_element is not None:
                        recurring_detail['at'] = at_element.text
                    else:
                        recurring_detail['at'] = '00'  # Default to '00' if 'at' is missing

                elif recurring_type == 'weekly':
                    day_elements = child.findall('day-of-week')
                    days = [day.text for day in day_elements]
                    recurring_detail['day_of_week'] = days
                    if at_element is not None:
                        recurring_detail['at'] = at_element.text
                    else:
                        recurring_detail['at'] = '00'  # Default to '00' if 'at' is missing

                elif recurring_type == 'monthly':
                    day_of_month_element = child.find('day-of-month')
                    if day_of_month_element is not None:
                        recurring_detail['day_of_month'] = int(day_of_month_element.text)
                    if at_element is not None:
                        recurring_detail['at'] = at_element.text
                    else:
                        recurring_detail['at'] = '00'  # Default to '00' if 'at' is missing

                recurring[recurring_type] = recurring_detail

        url = element.find('url').text if element.find('url') is not None else 'N/A'
        profile = element.find('certificate-profile').text if element.find('certificate-profile') is not None else 'Default'

        return {
            'name': name,
            'type': {edl_type: {'recurring': recurring, 'url': url, 'certificate_profile': profile}},
        }

    def _application_filter_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application-filter/entry',
            'shared': './shared/application-filter/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application-filter/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        application_filters = []
        for entry in self.root.findall(base_xpath):
            filter_entry = {"name": entry.get("name")}

            for category in ["category", "subcategory", "technology", "risk", "saas-certifications", "saas-risk"]:
                members = entry.find(f"./{category}")
                if members is not None:
                    filter_entry[category.replace('-', '_')] = [member.text for member in members.findall("./member")]

            tagging = entry.find("./tagging")
            if tagging is not None:
                no_tag = tagging.find("no-tag")
                if no_tag is not None:
                    filter_entry["tagging"] = {"no_tag": self._toBool(no_tag.text.strip())}

                tags = tagging.find("./tag/member")
                if tags is not None:
                    filter_entry["tagging"] = {"tag": [tag.text for tag in tagging.findall("./tag/member")]}
                else:
                    filter_entry["tagging"] = {"no_tag": True}

            for attribute in ["evasive", "excessive-bandwidth-use", "used-by-malware", "transfers-files", "has-known-vulnerabilities", "tunnels-other-apps", "prone-to-misuse", "pervasive", "is-saas", "new-appid"]:
                element = entry.find(attribute)
                if element is not None:
                    filter_entry[attribute.replace('-', '_')] = self._toBool(element.text.strip())

            application_filters.append(filter_entry)

        return application_filters

    def _application_group_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application-group/entry',
            'shared': './shared/application-group/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application-group/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        application_groups = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            members_elements = entry.find('members')

            application_group = {
                'name': name,
                'members': [member.text for member in members_elements.findall('member')] if members_elements is not None else []
            }

            application_groups.append(application_group)

        return application_groups

    def _app_override_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/application-override/rules/entry',
            'shared': './shared/pre-rulebase/application-override/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/application-override/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        app_override_rules = []
        for entry in self.root.findall(base_xpath):
            application = entry.find('application')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = self._sanitize_name(entry.get('name'))
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            port = entry.find('port')
            protocol = entry.find('protocol')
            source = entry.findall('source/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')

            app_override_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'port': port.text,
                'protocol': protocol.text,
                'application': application.text,
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
            }
            filtered_app_override_rule = {k: v for k, v in app_override_rule.items() if v is not None}
            app_override_rules.append(filtered_app_override_rule)

        logging.debug(f'FOUND THESE APP PRE RULES: {app_override_rules}')
        return app_override_rules

    def _app_override_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/application-override/rules/entry',
            'shared': './shared/post-rulebase/application-override/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/application-override/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
        app_override_rules = []
        for entry in self.root.findall(base_xpath):
            application = entry.find('application')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = self._sanitize_name(entry.get('name'))
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            port = entry.find('port')
            protocol = entry.find('protocol')
            source = entry.findall('source/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')

            app_override_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'port': port.text,
                'protocol': protocol.text,
                'application': application.text,
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
            }
            filtered_app_override_rule = {k: v for k, v in app_override_rule.items() if v is not None}
            app_override_rules.append(filtered_app_override_rule)

        logging.debug(f'FOUND THESE APP POST RULES: {app_override_rules}')
        return app_override_rules

    def _security_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/security/rules/entry',
            'shared': './shared/pre-rulebase/security/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/security/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        security_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            application = entry.findall('application/member')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            log_setting = entry.find('log-setting')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            profile_setting = entry.find('profile-setting/group/member')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            schedule = entry.find('schedule')

            security_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'source_user': [members.text for members in source_user] if source_user else ['any'],
                'source_hip': [member.text for member in entry.findall('source-hip/member')] or ['any'],
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'destination_hip': [member.text for member in entry.findall('destination-hip/member')] or ['any'],
                'application': [members.text for members in application] if application is not None else 'any',
                'service': [members.text for members in service] if service is not None else 'any',
                'category': [members.text for members in category] if category is not None else 'any',
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                'action': action.text if action is not None else None,
                'profile_setting': {'group': [profile_setting.text]} if profile_setting is not None else None,
                'schedule': schedule.text if schedule is not None else None
            }
            if schedule is not None and schedule.text:
                logging.warning(f"Schedule detected, manually add {schedule.text} to rule '{name}'")

            filtered_security_rules = {k: v for k, v in security_rule.items() if v is not None}
            security_rules.append(filtered_security_rules)

        logging.debug(f'FOUND THESE SECURITY PRE RULES: {security_rules}')
        return security_rules

    def _security_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/security/rules/entry',
            'shared': './shared/post-rulebase/security/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/security/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
        security_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            application = entry.findall('application/member')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            log_setting = entry.find('log-setting')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            profile_setting = entry.find('profile-setting/group/member')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            schedule = entry.find('schedule')

            security_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'source_user': [members.text for members in source_user] if source_user else ['any'],
                'source_hip': [member.text for member in entry.findall('source-hip/member')] or ['any'],
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'destination_hip': [member.text for member in entry.findall('destination-hip/member')] or ['any'],
                'application': [members.text for members in application] if application is not None else 'any',
                'service': [members.text for members in service] if service is not None else 'any',
                'category': [members.text for members in category] if category is not None else 'any',
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                'action': action.text if action is not None else None,
                'profile_setting': {'group': [profile_setting.text]} if profile_setting is not None else None,
                'schedule': schedule.text if schedule is not None else None
            }
            if schedule is not None and schedule.text:
                logging.warning(f"Schedule detected, manually add {schedule.text} to rule '{name}'")

            filtered_security_rules = {k: v for k, v in security_rule.items() if v is not None}
            security_rules.append(filtered_security_rules)

        logging.debug(f'FOUND THESE SECURITY POST RULES: {security_rules}')
        return security_rules

    def _decryption_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/decryption/rules/entry',
            'shared': './shared/pre-rulebase/decryption/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/decryption/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        decryption_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            type_element = entry.find('type')
            type_value = None
            if type_element is not None:
                type_children = list(type_element)
                if type_children:
                    type_key = type_children[0].tag
                    type_value = type_key.replace('-', '_')
            log_success = entry.find('log-success')
            log_fail = entry.find('log-fail')
            profile = entry.find('profile')
            profile_value = profile.text if profile is not None else 'best-practice'
            if profile_value == 'default':
                profile_value = 'best-practice'

            decryption_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'source_user': [members.text for members in source_user] if source_user else ['any'],
                'source_hip': [member.text for member in entry.findall('source-hip/member')] or ['any'],
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'destination_hip': [member.text for member in entry.findall('destination-hip/member')] or ['any'],
                'service': [members.text for members in service] if service is not None else ['any'],
                'category': [members.text for members in category] if category is not None else ['any'],
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                'action': action.text if action is not None else None,
                'type': {type_value: {}} if type_value else None,
                'log_success': True if (log_success is not None and log_success.text == 'yes') else False,
                'log_fail': False if (log_fail is not None and log_fail.text == 'no') else True,
                'profile': profile_value
            }

            filtered_decryption_rules = {k: v for k, v in decryption_rule.items() if v is not None}
            decryption_rules.append(filtered_decryption_rules)

        logging.debug(f'FOUND THESE DECRYPT PRE RULES: {decryption_rules}')
        return decryption_rules

    def _decryption_post_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/decryption/rules/entry',
            'shared': './shared/post-rulebase/decryption/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/decryption/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
        decryption_rules = []
        for entry in self.root.findall(base_xpath):
            action = entry.find('action')
            category = entry.findall('category/member')
            description = entry.find('description')
            destination = entry.findall('destination/member')
            disabled = entry.find('disabled')
            from_zone = entry.findall('from/member')
            name = entry.get('name')
            negate_destination = entry.find('negate-destination')
            negate_source = entry.find('negate-source')
            service = entry.findall('service/member')
            source = entry.findall('source/member')
            source_user = entry.findall('source-user/member')
            tag = entry.findall('tag/member')
            to_zone = entry.findall('to/member')
            type_element = entry.find('type')
            type_value = None
            if type_element is not None:
                type_children = list(type_element)
                if type_children:
                    type_key = type_children[0].tag
                    type_value = type_key.replace('-', '_')
            log_success = entry.find('log-success')
            log_fail = entry.find('log-fail')
            profile = entry.find('profile')
            profile_value = profile.text if profile is not None else 'best-practice'
            if profile_value == 'default':
                profile_value = 'best-practice'

            decryption_rule = {
                'name': name,
                'description': description.text if description is not None else None,
                'tag': [members.text for members in tag] if tag is not None else None,
                'from': [members.text for members in from_zone] if from_zone is not None else 'any',
                'source': [members.text for members in source] if source is not None else 'any',
                'negate_source': True if (negate_source is not None and negate_source.text == 'yes') else False,
                'source_user': [members.text for members in source_user] if source_user else ['any'],
                'source_hip': [member.text for member in entry.findall('source-hip/member')] or ['any'],
                'to': [members.text for members in to_zone] if to_zone is not None else 'any',
                'destination': [members.text for members in destination] if destination is not None else 'any',
                'negate_destination': True if (negate_destination is not None and negate_destination.text == 'yes') else False,
                'destination_hip': [member.text for member in entry.findall('destination-hip/member')] or ['any'],
                'service': [members.text for members in service] if service is not None else ['any'],
                'category': [members.text for members in category] if category is not None else ['any'],
                'disabled': True if (disabled is not None and disabled.text == 'yes') else False,
                'log_setting': "Cortex Data Lake",
                'action': action.text if action is not None else None,
                'type': {type_value: {}} if type_value else None,
                'log_success': True if (log_success is not None and log_success.text == 'yes') else False,
                'log_fail': False if (log_fail is not None and log_fail.text == 'no') else True,
                'profile': profile_value
            }

            filtered_decryption_rules = {k: v for k, v in decryption_rule.items() if v is not None}
            decryption_rules.append(filtered_decryption_rules)

        logging.debug(f'FOUND THESE DECRYPT POST RULES: {decryption_rules}')
        return decryption_rules

    def _nat_pre_rules_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/rulebase/nat/rules/entry',
            'shared': './shared/pre-rulebase/nat/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/pre-rulebase/nat/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        nat_rules = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            from_zone = entry.findall('from/member')
            to_zone = entry.findall('to/member')
            source = entry.findall('source/member')
            destination = entry.findall('destination/member')
            service = entry.find('service')
            nat_type = entry.find('nat-type')
            description = entry.find('description')
            disabled = entry.find('disabled')
            tag = entry.findall('tag/member')
            source_translation = entry.find('source-translation')
            destination_translation = entry.find('destination-translation')
            active_active_device_binding = entry.find('active-active-device-binding')

            service_value = service.text if service is not None else 'any'

            # Handle destination translation
            destination_translation_dict = None
            if destination_translation is not None:
                translated_address = destination_translation.find('translated-address')
                translated_port = destination_translation.find('translated-port')
                destination_translation_dict = {}
                if translated_address is not None:
                    destination_translation_dict['translated_address'] = translated_address.text
                if translated_port is not None:
                    destination_translation_dict['translated_port'] = translated_port.text

            # Handle source translation
            source_translation_dict = None
            if source_translation is not None:
                dynamic_ip_and_port = source_translation.find('dynamic-ip-and-port')
                if dynamic_ip_and_port is not None:
                    translated_addresses = dynamic_ip_and_port.findall('translated-address/member')
                    source_translation_dict = {
                        'dynamic_ip_and_port': {
                            'translated_address': [addr.text for addr in translated_addresses] if translated_addresses else None
                        }
                    }

            nat_rule = {
                'name': name,
                'from': [member.text for member in from_zone] if from_zone else [],
                'to': [member.text for member in to_zone] if to_zone else [],
                'source': [member.text for member in source] if source else [],
                'destination': [member.text for member in destination] if destination else [],
                'service': service_value,
                'nat_type': nat_type.text if nat_type is not None else None,
                'description': description.text if description is not None else None,
                'disabled': disabled.text == 'yes' if disabled is not None else False,
                'tag': [member.text for member in tag] if tag else [],
                'source_translation': source_translation_dict,
                'destination_translation': destination_translation_dict,
                'active_active_device_binding': active_active_device_binding.text if active_active_device_binding is not None else None
            }

            filtered_nat_rule = {k: v for k, v in nat_rule.items() if v is not None}
            nat_rules.append(filtered_nat_rule)

        return nat_rules

    def _nat_post_rules_entries(self):
        base_xpath_dict = {
            'shared': './shared/post-rulebase/nat/rules/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/post-rulebase/nat/rules/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        if self.config_type == 'local' or not base_xpath:
            return []
        nat_rules = []
        for entry in self.root.findall(base_xpath):
            name = entry.get('name')
            from_zone = entry.findall('from/member')
            to_zone = entry.findall('to/member')
            source = entry.findall('source/member')
            destination = entry.findall('destination/member')
            service = entry.find('service')
            nat_type = entry.find('nat-type')
            description = entry.find('description')
            disabled = entry.find('disabled')
            tag = entry.findall('tag/member')
            source_translation = entry.find('source-translation')
            destination_translation = entry.find('destination-translation')
            active_active_device_binding = entry.find('active-active-device-binding')

            service_value = service.text if service is not None else 'any'

            # Handle destination translation
            destination_translation_dict = None
            if destination_translation is not None:
                translated_address = destination_translation.find('translated-address')
                translated_port = destination_translation.find('translated-port')
                destination_translation_dict = {}
                if translated_address is not None:
                    destination_translation_dict['translated_address'] = translated_address.text
                if translated_port is not None:
                    destination_translation_dict['translated_port'] = translated_port.text

            # Handle source translation
            source_translation_dict = None
            if source_translation is not None:
                dynamic_ip_and_port = source_translation.find('dynamic-ip-and-port')
                if dynamic_ip_and_port is not None:
                    translated_addresses = dynamic_ip_and_port.findall('translated-address/member')
                    source_translation_dict = {
                        'dynamic_ip_and_port': {
                            'translated_address': [addr.text for addr in translated_addresses] if translated_addresses else None
                        }
                    }

            nat_rule = {
                'name': name,
                'from': [member.text for member in from_zone] if from_zone else [],
                'to': [member.text for member in to_zone] if to_zone else [],
                'source': [member.text for member in source] if source else [],
                'destination': [member.text for member in destination] if destination else [],
                'service': service_value,
                'nat_type': nat_type.text if nat_type is not None else None,
                'description': description.text if description is not None else None,
                'disabled': disabled.text == 'yes' if disabled is not None else False,
                'tag': [member.text for member in tag] if tag else [],
                'source_translation': source_translation_dict,
                'destination_translation': destination_translation_dict,
                'active_active_device_binding': active_active_device_binding.text if active_active_device_binding is not None else None
            }

            filtered_nat_rule = {k: v for k, v in nat_rule.items() if v is not None}
            nat_rules.append(filtered_nat_rule)

        return nat_rules

    def _application_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/application/entry',
            'shared': './shared/application/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/application/entry'
        }
        base_xpath = self._get_base_xpath(base_xpath_dict)
        applications = []
        for entry in self.root.findall(base_xpath):
            application = self._convert_application(entry)
            applications.append(application)
        return applications

    def _schedule_entries(self):
        base_xpath_dict = {
            'local': './devices/entry/vsys/entry/schedule/entry',
            'shared': './shared/schedule/entry',
            'device-group': './devices/entry/device-group/entry[@name="{device_group_name}"]/schedule/entry'
        }

        base_xpath = self._get_base_xpath(base_xpath_dict)
        schedules = []

        for entry in self.root.findall(base_xpath):
            schedule_entry = {
                'name': entry.get('name'),
                'schedule_type': {}
            }

            schedule_type = entry.find('schedule-type')
            if schedule_type is not None:
                if schedule_type.find('recurring') is not None:
                    recurring = {}
                    recurring_type = schedule_type.find('recurring')

                    if recurring_type.find('daily') is not None:
                        daily_schedule = {
                            'daily': [member.text for member in recurring_type.find('daily').findall('member')]
                        }
                        recurring.update(daily_schedule)

                    if recurring_type.find('weekly') is not None:
                        weekly_schedule = {}
                        for day in ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday']:
                            day_schedule = recurring_type.find('weekly').find(day)
                            if day_schedule is not None:
                                weekly_schedule[day] = [member.text for member in day_schedule.findall('member')]
                        recurring.update({'weekly': weekly_schedule})

                    schedule_entry['schedule_type']['recurring'] = recurring

                elif schedule_type.find('non-recurring') is not None:
                    non_recurring_times = [member.text for member in schedule_type.find('non-recurring').findall('member')]
                    schedule_entry['schedule_type']['non_recurring'] = non_recurring_times

            schedules.append(schedule_entry)

        return schedules

    def _interface_management_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Interface management profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        for entry in self.root.findall('./devices/entry/network/profiles/interface-management-profile/entry'):
            payload = self._convert_interface_management_profile(entry)
            if payload:
                profiles.append(payload)

        return profiles

    def _convert_interface_management_profile(self, entry):
        profile_name = entry.get('name')
        if not profile_name:
            return None

        payload = {'name': profile_name}
        for service in ['ping', 'https', 'ssh', 'snmp', 'response-pages', 'userid-service']:
            value = self._child_text(entry, service)
            if value:
                payload[service.replace('-', '_')] = value.lower() == 'yes'

        permitted_ips = self._member_or_entry_names(entry.find('permitted-ip'))
        if permitted_ips:
            payload['permitted_ip'] = permitted_ips

        return payload

    @staticmethod
    def _member_or_entry_names(parent):
        if parent is None:
            return []

        values = [
            child.text.strip()
            for child in parent.findall('member')
            if child.text and child.text.strip()
        ]
        values.extend(
            child.get('name')
            for child in parent.findall('entry')
            if child.get('name')
        )
        return values

    def _zone_protection_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Zone protection profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        for entry in self.root.findall('./devices/entry/network/profiles/zone-protection-profile/entry'):
            payload = self._convert_zone_protection_profile(entry)
            if payload:
                profiles.append(payload)

        return profiles

    def _convert_zone_protection_profile(self, entry):
        profile_name = entry.get('name')
        if not profile_name:
            return None

        payload = {'name': profile_name}
        description = self._child_text(entry, 'description')
        if description:
            payload['description'] = description

        flood = self._convert_zone_protection_flood(entry.find('flood'))
        if flood:
            payload['flood'] = flood

        reconnaissance = self._convert_zone_protection_reconnaissance(entry.find('scan'))
        if reconnaissance:
            payload['reconnaissance'] = reconnaissance

        return payload

    def _convert_zone_protection_flood(self, flood):
        if flood is None:
            return None

        flood_payload = {}
        for panos_name, scm_name in [
            ('tcp-syn', 'tcp_syn'),
            ('udp', 'udp'),
            ('icmp', 'icmp'),
            ('icmpv6', 'icmpv6'),
            ('other-ip', 'other_ip'),
        ]:
            section = flood.find(panos_name)
            if section is None:
                continue
            converted = self._convert_zone_protection_flood_section(section)
            if converted:
                flood_payload[scm_name] = converted

        return flood_payload

    def _convert_zone_protection_flood_section(self, section):
        payload = {}
        enabled = self._child_text(section, 'enable')
        if enabled:
            payload['enable'] = enabled.lower() == 'yes'

        red = section.find('red')
        if red is not None:
            red_payload = self._int_child_map(
                red,
                {
                    'alarm-rate': 'alarm_rate',
                    'activate-rate': 'activate_rate',
                    'maximal-rate': 'maximal_rate',
                    'block-duration': 'block_duration',
                },
            )
            if red_payload:
                payload['red'] = red_payload

        syn_cookies = section.find('syn-cookies')
        if syn_cookies is not None:
            syn_cookie_payload = self._int_child_map(
                syn_cookies,
                {
                    'alarm-rate': 'alarm_rate',
                    'activate-rate': 'activate_rate',
                    'maximal-rate': 'maximal_rate',
                },
            )
            if syn_cookie_payload:
                payload['syn_cookies'] = syn_cookie_payload

        return payload

    def _convert_zone_protection_reconnaissance(self, scan):
        if scan is None:
            return None

        reconnaissance = {}
        for entry in scan.findall('entry'):
            scan_name = entry.get('name')
            if not scan_name:
                continue

            scan_payload = self._int_child_map(
                entry,
                {
                    'interval': 'interval',
                    'threshold': 'threshold',
                },
            )
            action = self._first_child_name(entry.find('action'))
            if action:
                scan_payload['action'] = action
            if scan_payload:
                reconnaissance[scan_name.replace('-', '_')] = scan_payload

        return reconnaissance

    def _int_child_map(self, entry, field_map):
        payload = {}
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value and value.isdigit():
                payload[scm_name] = int(value)
        return payload

    @staticmethod
    def _first_child_name(entry):
        if entry is not None and list(entry):
            return list(entry)[0].tag.replace('-', '_')
        return None

    def _dhcp_interface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("DHCP interface migration currently supports local firewall XML only.")
            return []

        interfaces = []
        for entry in self.root.findall('./devices/entry/network/dhcp/interface/entry'):
            payload = self._convert_dhcp_interface(entry)
            if payload:
                interfaces.append(payload)

        return interfaces

    def _convert_dhcp_interface(self, entry):
        interface_name = entry.get('name')
        if not interface_name:
            return None

        payload = {'name': interface_name}

        server = self._convert_dhcp_server(entry.find('server'))
        if server:
            payload['server'] = server

        relay = self._convert_dhcp_relay(entry.find('relay'))
        if relay:
            payload['relay'] = relay

        if not server and not relay:
            self.logger.warning(f"Skipping DHCP interface '{interface_name}' because it has no supported server or relay configuration.")
            return None

        return payload

    def _convert_dhcp_server(self, server):
        if server is None:
            return None

        payload = {}
        mode = self._child_text(server, 'mode')
        if mode:
            payload['mode'] = mode

        ip_pool = self._member_or_entry_names(server.find('ip-pool'))
        if ip_pool:
            payload['ip_pool'] = ip_pool

        option = self._convert_dhcp_server_option(server.find('option'))
        if option:
            payload['option'] = option

        reserved = []
        for reserved_entry in server.findall('reserved/entry'):
            reservation = self._convert_dhcp_reservation(reserved_entry)
            if reservation:
                reserved.append(reservation)
        if reserved:
            payload['reserved'] = reserved

        return payload or None

    def _convert_dhcp_server_option(self, option):
        if option is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('gateway', 'gateway'),
            ('subnet-mask', 'subnet_mask'),
            ('primary-dns', 'primary_dns'),
            ('secondary-dns', 'secondary_dns'),
            ('primary-wins', 'primary_wins'),
            ('secondary-wins', 'secondary_wins'),
            ('domain', 'domain'),
        ]:
            value = self._child_text(option, panos_name)
            if value:
                payload[scm_name] = value

        lease = self._convert_dhcp_lease(option.find('lease'))
        if lease:
            payload['lease'] = lease

        dns_suffix = self._member_texts(option.find('dns-suffix'))
        if dns_suffix:
            payload['dns_suffix'] = dns_suffix

        return payload or None

    def _convert_dhcp_lease(self, lease):
        if lease is None:
            return None

        if lease.find('unlimited') is not None:
            return {'unlimited': {}}

        timeout = lease.find('timeout')
        if timeout is not None:
            timeout_payload = self._int_child_map(
                timeout,
                {
                    'days': 'days',
                    'hours': 'hours',
                    'minutes': 'minutes',
                },
            )
            if timeout_payload:
                return {'timeout': timeout_payload}

        return None

    def _convert_dhcp_reservation(self, entry):
        reservation_name = entry.get('name')
        if not reservation_name:
            return None

        payload = {'name': reservation_name}
        for panos_name, scm_name in [
            ('mac', 'mac'),
            ('ip', 'ip'),
            ('description', 'description'),
        ]:
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        return payload

    def _convert_dhcp_relay(self, relay):
        if relay is None:
            return None

        payload = {}
        enabled = self._child_text(relay, 'enable')
        if enabled:
            payload['enable'] = enabled.lower() == 'yes'

        servers = self._member_texts(relay.find('server'))
        if servers:
            payload['server'] = servers

        return payload or None

    def _aggregate_interface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Aggregate interface migration currently supports local firewall XML only.")
            return []

        interfaces = []
        for entry in self.root.findall('./devices/entry/network/interface/aggregate-ethernet/entry'):
            payload = self._convert_aggregate_interface(entry)
            if payload:
                interfaces.append(payload)

        return interfaces

    def _convert_aggregate_interface(self, entry):
        aggregate_name = entry.get('name')
        if not aggregate_name:
            return None

        payload = {
            'name': f"${self._sanitize_name(aggregate_name)}",
            'default_value': aggregate_name,
        }

        comment = self._child_text(entry, 'comment')
        if comment:
            payload['comment'] = comment

        lacp = self._convert_lacp(entry.find('lacp'))
        if lacp:
            payload['lacp'] = lacp

        layer3 = entry.find('layer3')
        if layer3 is not None:
            payload['layer3'] = self._convert_ethernet_layer3(layer3)
            return payload

        if entry.find('layer2') is not None:
            payload['layer2'] = {}
            return payload

        self.logger.warning(f"Skipping aggregate interface '{aggregate_name}' because it has no supported mode.")
        return None

    def _convert_lacp(self, lacp):
        if lacp is None:
            return None

        lacp_payload = {}
        enabled = self._child_text(lacp, 'enable')
        if enabled:
            lacp_payload['enable'] = enabled.lower() == 'yes'

        mode = self._child_text(lacp, 'mode')
        if mode:
            lacp_payload['mode'] = mode

        transmission_rate = self._child_text(lacp, 'transmission-rate')
        if transmission_rate:
            lacp_payload['transmission_rate'] = transmission_rate

        return lacp_payload or None

    def _ethernet_interface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Ethernet interface migration currently supports local firewall XML only.")
            return []

        interfaces = []
        for entry in self.root.findall('./devices/entry/network/interface/ethernet/entry'):
            payload = self._convert_ethernet_interface(entry)
            if payload:
                interfaces.append(payload)

        return interfaces

    def _convert_ethernet_interface(self, entry):
        physical_name = entry.get('name')
        if not physical_name:
            return None

        payload = {
            'name': f"${self._sanitize_name(physical_name)}",
            'default_value': physical_name,
        }

        field_map = {
            'comment': 'comment',
            'link-speed': 'link_speed',
            'link-duplex': 'link_duplex',
            'link-state': 'link_state',
        }
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        aggregate_group = self._child_text(entry, 'aggregate-group')
        if aggregate_group:
            payload['aggregate_group'] = aggregate_group
            return payload

        layer3 = entry.find('layer3')
        if layer3 is not None:
            payload['layer3'] = self._convert_ethernet_layer3(layer3)
            return payload

        if entry.find('layer2') is not None:
            payload['layer2'] = {}
            return payload

        if entry.find('virtual-wire') is not None or entry.find('virtual-wire-interfaces') is not None:
            payload['virtual_wire'] = {}
            return payload

        if entry.find('tap') is not None:
            payload['tap'] = {}
            return payload

        self.logger.warning(f"Skipping ethernet interface '{physical_name}' because it has no supported mode.")
        return None

    def _convert_ethernet_layer3(self, layer3):
        layer3_payload = {}

        dhcp_client = self._convert_dhcp_client(layer3.find('dhcp-client'))
        if dhcp_client:
            layer3_payload['dhcp_client'] = dhcp_client
        else:
            ip_entries = [
                ip_entry.get('name')
                for ip_entry in layer3.findall('ip/entry')
                if ip_entry.get('name')
            ]
            if ip_entries:
                layer3_payload['ip'] = [{'name': ip_address} for ip_address in ip_entries]

        mtu = self._child_text(layer3, 'mtu')
        if mtu and mtu.isdigit():
            layer3_payload['mtu'] = int(mtu)

        management_profile = self._child_text(layer3, 'interface-management-profile')
        if management_profile:
            layer3_payload['interface_management_profile'] = management_profile

        return layer3_payload

    def _convert_dhcp_client(self, dhcp_client):
        if dhcp_client is None:
            return None

        payload = {}
        boolean_fields = {
            'enable': 'enable',
            'create-default-route': 'create_default_route',
        }
        for panos_name, scm_name in boolean_fields.items():
            value = self._child_text(dhcp_client, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes'

        metric = self._child_text(dhcp_client, 'default-route-metric')
        if metric and metric.isdigit():
            payload['default_route_metric'] = int(metric)

        send_hostname = dhcp_client.find('send-hostname')
        if send_hostname is not None:
            send_hostname_payload = {}
            enabled = self._child_text(send_hostname, 'enable')
            if enabled:
                send_hostname_payload['enable'] = enabled.lower() == 'yes'
            hostname = self._child_text(send_hostname, 'hostname')
            if hostname:
                send_hostname_payload['hostname'] = hostname
            if send_hostname_payload:
                payload['send_hostname'] = send_hostname_payload

        return payload or None

    def _static_ip_entries(self, entry):
        ip_entries = [
            ip_entry.get('name')
            for ip_entry in entry.findall('ip/entry')
            if ip_entry.get('name')
        ]
        return [{'name': ip_address} for ip_address in ip_entries]

    def _apply_common_l3_interface_fields(self, payload, entry):
        field_map = {
            'comment': 'comment',
            'interface-management-profile': 'interface_management_profile',
            'netflow-profile': 'netflow_profile',
        }
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        mtu = self._child_text(entry, 'mtu')
        if mtu and mtu.isdigit():
            payload['mtu'] = int(mtu)

        dhcp_client = self._convert_dhcp_client(entry.find('dhcp-client'))
        if dhcp_client:
            payload['dhcp_client'] = dhcp_client
        else:
            ip_entries = self._static_ip_entries(entry)
            if ip_entries:
                payload['ip'] = ip_entries

        return payload

    def _apply_common_l2_interface_fields(self, payload, entry):
        field_map = {
            'comment': 'comment',
            'netflow-profile': 'netflow_profile',
        }
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        return payload

    def _layer2_subinterface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Layer 2 subinterface migration currently supports local firewall XML only.")
            return []

        subinterfaces = []
        for parent_entry in self.root.findall('./devices/entry/network/interface/ethernet/entry'):
            parent_name = parent_entry.get('name')
            if not parent_name:
                continue

            for subinterface_entry in parent_entry.findall('layer2/units/entry'):
                payload = self._convert_layer2_subinterface(parent_name, subinterface_entry)
                if payload:
                    subinterfaces.append(payload)

        return subinterfaces

    def _convert_layer2_subinterface(self, parent_name, entry):
        subinterface_name = entry.get('name')
        if not subinterface_name:
            return None

        payload = {
            'name': subinterface_name,
            'parent_interface': parent_name,
        }

        tag = self._child_text(entry, 'tag')
        if tag and tag.isdigit():
            payload['tag'] = int(tag)

        return self._apply_common_l2_interface_fields(payload, entry)

    def _layer3_subinterface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Layer 3 subinterface migration currently supports local firewall XML only.")
            return []

        subinterfaces = []
        for parent_entry in self.root.findall('./devices/entry/network/interface/ethernet/entry'):
            parent_name = parent_entry.get('name')
            if not parent_name:
                continue

            for subinterface_entry in parent_entry.findall('layer3/units/entry'):
                payload = self._convert_layer3_subinterface(parent_name, subinterface_entry)
                if payload:
                    subinterfaces.append(payload)

        return subinterfaces

    def _convert_layer3_subinterface(self, parent_name, entry):
        subinterface_name = entry.get('name')
        if not subinterface_name:
            return None

        payload = {
            'name': subinterface_name,
            'parent_interface': parent_name,
        }

        tag = self._child_text(entry, 'tag')
        if tag and tag.isdigit():
            payload['tag'] = int(tag)

        return self._apply_common_l3_interface_fields(payload, entry)

    def _vlan_interface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("VLAN interface migration currently supports local firewall XML only.")
            return []

        interfaces = []
        for entry in self.root.findall('./devices/entry/network/interface/vlan/units/entry'):
            payload = self._convert_vlan_interface(entry)
            if payload:
                interfaces.append(payload)

        return interfaces

    def _convert_vlan_interface(self, entry):
        interface_name = entry.get('name')
        if not interface_name:
            return None

        payload = {'name': interface_name}
        vlan_tag = self._child_text(entry, 'tag')
        if vlan_tag:
            payload['vlan_tag'] = vlan_tag

        return self._apply_common_l3_interface_fields(payload, entry)

    def _tunnel_interface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Tunnel interface migration currently supports local firewall XML only.")
            return []

        interfaces = []
        for entry in self.root.findall('./devices/entry/network/interface/tunnel/units/entry'):
            payload = self._convert_tunnel_interface(entry)
            if payload:
                interfaces.append(payload)

        return interfaces

    def _convert_tunnel_interface(self, entry):
        interface_name = entry.get('name')
        if not interface_name:
            return None

        payload = {
            'name': interface_name,
            'default_value': interface_name,
        }

        return self._apply_common_l3_interface_fields(payload, entry)

    def _loopback_interface_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Loopback interface migration currently supports local firewall XML only.")
            return []

        interfaces = []
        for entry in self.root.findall('./devices/entry/network/interface/loopback/units/entry'):
            payload = self._convert_loopback_interface(entry)
            if payload:
                interfaces.append(payload)

        return interfaces

    def _convert_loopback_interface(self, entry):
        interface_name = entry.get('name')
        if not interface_name:
            return None

        payload = {'name': interface_name}
        field_map = {
            'comment': 'comment',
            'interface-management-profile': 'interface_management_profile',
        }
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        mtu = self._child_text(entry, 'mtu')
        if mtu and mtu.isdigit():
            payload['mtu'] = int(mtu)

        ip_entries = [
            ip_entry.get('name')
            for ip_entry in entry.findall('ip/entry')
            if ip_entry.get('name')
        ]
        if ip_entries:
            payload['ip'] = ip_entries

        return payload

    def _logical_router_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Logical router migration currently supports local firewall XML only.")
            return []

        logical_routers = []
        for entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            payload = self._convert_panos_virtual_router_to_logical_router(entry)
            if payload:
                logical_routers.append(payload)

        return logical_routers

    def _convert_panos_virtual_router_to_logical_router(self, entry):
        router_name = entry.get('name')
        if not router_name:
            return None

        vrf = {'name': 'default'}
        interfaces = [
            member.text.strip()
            for member in entry.findall('interface/member')
            if member.text and member.text.strip()
        ]
        if interfaces:
            vrf['interface'] = interfaces

        static_routes = []
        for route_entry in entry.findall('routing-table/ip/static-route/entry'):
            route = self._convert_static_route(route_entry)
            if route:
                static_routes.append(route)

        if static_routes:
            vrf['routing_table'] = {'ip': {'static_route': static_routes}}

        static_routes_v6 = []
        for route_entry in entry.findall('routing-table/ipv6/static-route/entry'):
            route = self._convert_static_route(route_entry)
            if route:
                static_routes_v6.append(route)

        if static_routes_v6:
            routing_table = vrf.setdefault('routing_table', {})
            routing_table['ipv6'] = {'static_route': static_routes_v6}

        export_ipv4_route_maps = self._bgp_policy_route_map_names(entry, 'export', family='ipv4')
        if export_ipv4_route_maps:
            rib_filter = vrf.setdefault('rib_filter', {})
            ipv4_filter = rib_filter.setdefault('ipv4', {})
            ipv4_filter['bgp'] = {'route_map': export_ipv4_route_maps[0]}

        export_ipv6_route_maps = self._bgp_policy_route_map_names(entry, 'export', family='ipv6')
        if export_ipv6_route_maps:
            rib_filter = vrf.setdefault('rib_filter', {})
            ipv6_filter = rib_filter.setdefault('ipv6', {})
            ipv6_filter['bgp'] = {'route_map': export_ipv6_route_maps[0]}

        bgp = self._convert_bgp(entry.find('protocol/bgp'), entry)
        if bgp:
            vrf['bgp'] = bgp

        ospf = self._convert_ospf(entry.find('protocol/ospf'))
        if ospf:
            vrf['ospf'] = ospf

        ospfv3 = self._convert_ospfv3(entry.find('protocol/ospfv3'))
        if ospfv3:
            vrf['ospfv3'] = ospfv3

        return {
            'name': router_name,
            'routing_stack': 'advanced',
            'vrf': [vrf],
        }

    def _convert_static_route(self, entry):
        route_name = entry.get('name')
        if not route_name:
            return None

        route = {'name': route_name}
        field_map = {
            'destination': 'destination',
            'interface': 'interface',
        }
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value:
                route[scm_name] = value

        int_field_map = {
            'metric': 'metric',
            'admin-dist': 'admin_dist',
        }
        for panos_name, scm_name in int_field_map.items():
            value = self._child_text(entry, panos_name)
            if value and value.isdigit():
                route[scm_name] = int(value)

        route_table = self._convert_static_route_table(entry.find('route-table'))
        if route_table:
            route['route_table'] = route_table

        option = self._convert_static_route_option(entry.find('option'))
        if option:
            route['option'] = option

        nexthop = self._convert_static_route_nexthop(entry.find('nexthop'))
        if nexthop:
            route['nexthop'] = nexthop

        bfd_profile = self._child_text(entry, 'bfd/profile')
        if bfd_profile:
            route['bfd'] = {'profile': bfd_profile}

        path_monitor = self._convert_static_route_path_monitor(entry.find('path-monitor'))
        if path_monitor:
            route['path_monitor'] = path_monitor

        return route

    def _convert_static_route_table(self, route_table):
        if route_table is None:
            return None

        for table_name in ['unicast', 'multicast', 'both', 'no-install', 'no_install']:
            if route_table.find(table_name) is not None:
                return {table_name.replace('-', '_'): {}}

        value = self._first_text_or_member(route_table)
        if value:
            return {value.replace('-', '_'): {}}
        return None

    def _convert_static_route_option(self, option):
        if option is None:
            return None

        payload = {}
        if option.find('passive') is not None:
            payload['passive'] = {}
        return payload or None

    def _convert_static_route_nexthop(self, nexthop):
        if nexthop is None:
            return None

        text_fields = {
            'ip-address': 'ip_address',
            'ipv6-address': 'ipv6_address',
            'fqdn': 'fqdn',
            'next-vr': 'next_vr',
            'next-lr': 'next_lr',
            'tunnel': 'tunnel',
        }
        for panos_name, scm_name in text_fields.items():
            value = self._child_text(nexthop, panos_name)
            if value:
                return {scm_name: value}

        for empty_field in ['receive', 'discard']:
            if nexthop.find(empty_field) is not None:
                return {empty_field: {}}

        return None

    def _convert_static_route_path_monitor(self, path_monitor):
        if path_monitor is None:
            return None

        payload = {}
        enabled = self._child_text(path_monitor, 'enable')
        if enabled:
            payload['enable'] = enabled.lower() == 'yes'

        failure_condition = self._child_text(path_monitor, 'failure-condition')
        if failure_condition:
            payload['failure_condition'] = failure_condition

        hold_time = self._child_text(path_monitor, 'hold-time')
        if hold_time and hold_time.isdigit():
            payload['hold_time'] = int(hold_time)

        destinations = []
        for destination_entry in path_monitor.findall('monitor-destinations/entry'):
            destination = {'name': destination_entry.get('name')}
            for panos_name, scm_name in [
                ('enable', 'enable'),
                ('source', 'source'),
                ('destination', 'destination'),
                ('destination-fqdn', 'destination_fqdn'),
                ('interval', 'interval'),
                ('count', 'count'),
            ]:
                value = self._child_text(destination_entry, panos_name)
                if not value:
                    continue
                if panos_name == 'enable':
                    destination[scm_name] = value.lower() == 'yes'
                elif value.isdigit():
                    destination[scm_name] = int(value)
                else:
                    destination[scm_name] = value
            if destination.get('name'):
                destinations.append(destination)

        if destinations:
            payload['monitor_destinations'] = destinations

        return payload or None

    def _ike_crypto_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("IKE crypto profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        for entry in self.root.findall('./devices/entry/network/ike/crypto-profiles/ike-crypto-profiles/entry'):
            payload = self._convert_ike_crypto_profile(entry)
            if payload:
                profiles.append(payload)

        return profiles

    def _convert_ike_crypto_profile(self, entry):
        profile_name = entry.get('name')
        if not profile_name:
            return None

        payload = {'name': profile_name}
        for panos_name, scm_name in [
            ('hash', 'hash'),
            ('encryption', 'encryption'),
            ('dh-group', 'dh_group'),
        ]:
            values = self._member_texts(entry.find(panos_name))
            if values:
                payload[scm_name] = values

        lifetime = self._convert_lifetime(entry.find('lifetime'))
        if lifetime:
            payload['lifetime'] = lifetime

        authentication_multiple = self._child_text(entry, 'authentication-multiple')
        if authentication_multiple and authentication_multiple.isdigit():
            payload['authentication_multiple'] = int(authentication_multiple)

        return payload

    def _ipsec_crypto_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("IPsec crypto profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        for entry in self.root.findall('./devices/entry/network/ike/crypto-profiles/ipsec-crypto-profiles/entry'):
            payload = self._convert_ipsec_crypto_profile(entry)
            if payload:
                profiles.append(payload)

        return profiles

    def _convert_ipsec_crypto_profile(self, entry):
        profile_name = entry.get('name')
        if not profile_name:
            return None

        payload = {'name': profile_name}
        esp = entry.find('esp')
        if esp is not None:
            esp_payload = {}
            encryption = self._member_texts(esp.find('encryption'))
            if encryption:
                esp_payload['encryption'] = encryption
            authentication = self._member_texts(esp.find('authentication'))
            if authentication:
                esp_payload['authentication'] = authentication
            if esp_payload:
                payload['esp'] = esp_payload

        dh_group = self._first_text_or_member(entry.find('dh-group'))
        if dh_group:
            payload['dh_group'] = dh_group

        lifetime = self._convert_lifetime(entry.find('lifetime'))
        if lifetime:
            payload['lifetime'] = lifetime

        return payload

    def _ike_gateway_entries(self):
        if self.config_type != 'local':
            self.logger.warning("IKE gateway migration currently supports local firewall XML only.")
            return []

        gateways = []
        for entry in self.root.findall('./devices/entry/network/ike/gateway/entry'):
            payload = self._convert_ike_gateway(entry)
            if payload:
                gateways.append(payload)

        return gateways

    def _convert_ike_gateway(self, entry):
        gateway_name = entry.get('name')
        if not gateway_name:
            return None

        payload = {'name': gateway_name}

        protocol = self._convert_ike_gateway_protocol(entry.find('protocol'))
        if protocol:
            payload['protocol'] = protocol

        local_address = self._convert_named_text_fields(
            entry.find('local-address'),
            {
                'interface': 'interface',
                'ip': 'ip',
                'floating-ip': 'floating_ip',
            },
        )
        if local_address:
            payload['local_address'] = local_address

        peer_address = self._convert_named_text_fields(
            entry.find('peer-address'),
            {
                'ip': 'ip',
                'fqdn': 'fqdn',
                'dynamic': 'dynamic',
            },
        )
        if peer_address:
            payload['peer_address'] = peer_address

        authentication = self._convert_ike_gateway_authentication(entry.find('authentication'))
        if authentication:
            payload['authentication'] = authentication

        return payload

    def _convert_ike_gateway_protocol(self, protocol):
        if protocol is None:
            return None

        payload = {}
        version = self._child_text(protocol, 'version')
        if version:
            payload['version'] = version

        for version_name in ['ikev1', 'ikev2']:
            version_element = protocol.find(version_name)
            if version_element is None:
                continue
            version_payload = {}
            crypto_profile = self._child_text(version_element, 'ike-crypto-profile')
            if crypto_profile:
                version_payload['ike_crypto_profile'] = crypto_profile
            dpd = self._convert_dpd(version_element.find('dpd'))
            if dpd:
                version_payload['dpd'] = dpd
            if version_payload:
                payload[version_name] = version_payload

        return payload or None

    def _convert_dpd(self, dpd):
        if dpd is None:
            return None

        payload = {}
        enable = self._child_text(dpd, 'enable')
        if enable:
            payload['enable'] = enable.lower() == 'yes'

        interval = self._child_text(dpd, 'interval')
        if interval and interval.isdigit():
            payload['interval'] = int(interval)

        retry = self._child_text(dpd, 'retry')
        if retry and retry.isdigit():
            payload['retry'] = int(retry)

        return payload or None

    def _convert_ike_gateway_authentication(self, authentication):
        if authentication is None:
            return None

        psk = authentication.find('pre-shared-key')
        if psk is not None:
            key = self._child_text(psk, 'key')
            return {'pre_shared_key': {'key': key}} if key else {'pre_shared_key': {}}

        certificate = authentication.find('certificate')
        if certificate is not None:
            certificate_profile = self._child_text(certificate, 'certificate-profile')
            return {'certificate': {'certificate_profile': certificate_profile}} if certificate_profile else {'certificate': {}}

        return None

    def _ipsec_tunnel_entries(self):
        if self.config_type != 'local':
            self.logger.warning("IPsec tunnel migration currently supports local firewall XML only.")
            return []

        tunnels = []
        for entry in self.root.findall('./devices/entry/network/tunnel/ipsec/entry'):
            payload = self._convert_ipsec_tunnel(entry)
            if payload:
                tunnels.append(payload)

        return tunnels

    def _convert_ipsec_tunnel(self, entry):
        tunnel_name = entry.get('name')
        if not tunnel_name:
            return None

        payload = {'name': tunnel_name}
        tunnel_interface = self._child_text(entry, 'tunnel-interface')
        if tunnel_interface:
            payload['tunnel_interface'] = tunnel_interface

        auto_key = self._convert_ipsec_auto_key(entry.find('auto-key'))
        if auto_key:
            payload['auto_key'] = auto_key

        for panos_name, scm_name in [
            ('anti-replay', 'anti_replay'),
            ('copy-tos', 'copy_tos'),
            ('enable-gre-encapsulation', 'enable_gre_encapsulation'),
        ]:
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes'

        tunnel_monitor = self._convert_tunnel_monitor(entry.find('tunnel-monitor'))
        if tunnel_monitor:
            payload['tunnel_monitor'] = tunnel_monitor

        return payload

    def _convert_ipsec_auto_key(self, auto_key):
        if auto_key is None:
            return None

        payload = {}
        gateways = self._entry_names_or_member_texts(auto_key.find('ike-gateway'))
        if gateways:
            payload['ike_gateway'] = [{'name': gateway} for gateway in gateways]

        crypto_profile = self._child_text(auto_key, 'ipsec-crypto-profile')
        if crypto_profile:
            payload['ipsec_crypto_profile'] = crypto_profile

        proxy_ids = []
        for proxy_id_entry in auto_key.findall('proxy-id/entry'):
            proxy_id = self._convert_proxy_id(proxy_id_entry)
            if proxy_id:
                proxy_ids.append(proxy_id)
        if proxy_ids:
            payload['proxy_id'] = proxy_ids

        return payload or None

    def _convert_proxy_id(self, entry):
        proxy_name = entry.get('name')
        if not proxy_name:
            return None

        payload = {'name': proxy_name}
        for panos_name, scm_name in [
            ('local', 'local'),
            ('remote', 'remote'),
        ]:
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        protocol = entry.find('protocol')
        if protocol is not None:
            protocol_payload = {}
            number = self._child_text(protocol, 'number')
            if number and number.isdigit():
                protocol_payload['number'] = int(number)
            for protocol_name in ['any', 'tcp', 'udp']:
                if protocol.find(protocol_name) is not None:
                    protocol_payload[protocol_name] = {}
                    break
            if protocol_payload:
                payload['protocol'] = protocol_payload

        return payload

    def _convert_tunnel_monitor(self, tunnel_monitor):
        if tunnel_monitor is None:
            return None

        payload = {}
        enable = self._child_text(tunnel_monitor, 'enable')
        if enable:
            payload['enable'] = enable.lower() == 'yes'

        destination_ip = self._child_text(tunnel_monitor, 'destination-ip')
        if destination_ip:
            payload['destination_ip'] = destination_ip

        proxy_id = self._child_text(tunnel_monitor, 'proxy-id')
        if proxy_id:
            payload['proxy_id'] = proxy_id

        return payload or None

    def _pbf_rule_entries(self):
        if self.config_type != 'local':
            self.logger.warning("PBF rule migration currently supports local firewall XML only.")
            return []

        rules = []
        for entry in self.root.findall('./devices/entry/vsys/entry/rulebase/pbf/rules/entry'):
            payload = self._convert_pbf_rule(entry)
            if payload:
                rules.append(payload)

        return rules

    def _convert_pbf_rule(self, entry):
        rule_name = entry.get('name')
        if not rule_name:
            return None

        payload = {'name': rule_name}
        description = self._child_text(entry, 'description')
        if description:
            payload['description'] = description

        for panos_name, scm_name in [
            ('from', 'from'),
            ('source', 'source'),
            ('source-user', 'source_user'),
            ('destination', 'destination'),
            ('application', 'application'),
            ('service', 'service'),
        ]:
            values = self._member_texts(entry.find(panos_name))
            if values:
                payload[scm_name] = values

        for panos_name, scm_name in [
            ('negate-source', 'negate_source'),
            ('negate-destination', 'negate_destination'),
            ('disabled', 'disabled'),
        ]:
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes'

        tags = self._member_texts(entry.find('tag'))
        if tags:
            payload['tag'] = tags

        action = self._convert_pbf_action(entry.find('action'))
        if action:
            payload['action'] = action

        return payload

    def _convert_pbf_action(self, action):
        if action is None:
            return None

        forwarding = action.find('forwarding')
        if forwarding is not None:
            forwarding_payload = self._convert_named_text_fields(
                forwarding,
                {
                    'egress-interface': 'egress_interface',
                },
            ) or {}

            symmetric_return = self._child_text(forwarding, 'symmetric-return')
            if symmetric_return:
                forwarding_payload['symmetric_return'] = symmetric_return.lower() == 'yes'

            nexthop = self._convert_static_route_nexthop(forwarding.find('nexthop'))
            if nexthop:
                forwarding_payload['nexthop'] = nexthop

            monitor = self._convert_pbf_monitor(forwarding.find('monitor'))
            if monitor:
                forwarding_payload['monitor'] = monitor

            return {'forwarding': forwarding_payload}

        if action.find('no-pbf') is not None:
            return {'no_pbf': {}}

        if action.find('discard') is not None:
            return {'discard': {}}

        return None

    def _convert_pbf_monitor(self, monitor):
        if monitor is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('ip-address', 'ip_address'),
            ('profile', 'profile'),
        ]:
            value = self._child_text(monitor, panos_name)
            if value:
                payload[scm_name] = value

        disable_if_unreachable = self._child_text(monitor, 'disable-if-unreachable')
        if disable_if_unreachable:
            payload['disable_if_unreachable'] = disable_if_unreachable.lower() == 'yes'

        return payload or None

    def _ospf_auth_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("OSPF auth profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for protocol_name in ['ospf', 'ospfv3']:
                for profile_entry in self._ospf_auth_profile_config_entries(router_entry.find(f'protocol/{protocol_name}')):
                    profile = self._convert_ospf_auth_profile(profile_entry)
                    if not profile or profile['name'] in seen_names:
                        continue
                    seen_names.add(profile['name'])
                    profiles.append(profile)

        return profiles

    def _ospf_auth_profile_config_entries(self, protocol_entry):
        if protocol_entry is None:
            return []

        entries = []
        for path in ['auth-profile/entry', 'auth-profiles/entry']:
            entries.extend(protocol_entry.findall(path))
        return entries

    def _convert_ospf_auth_profile(self, profile_entry):
        profile_name = profile_entry.get('name')
        if not profile_name:
            return None

        payload = {'name': profile_name}
        password = self._child_text(profile_entry, 'password')
        if password:
            payload['password'] = password
            return payload

        md5_entries = []
        for key_entry in profile_entry.findall('md5/entry'):
            key_id = key_entry.get('name')
            key = self._child_text(key_entry, 'key') or self._child_text(key_entry, 'password')
            if not key_id or not key:
                continue
            md5 = {'key': key}
            if key_id.isdigit():
                md5['key_id'] = int(key_id)
            else:
                md5['name'] = key_id
            md5_entries.append(md5)
        if md5_entries:
            payload['md5'] = md5_entries

        return payload if len(payload) > 1 else None

    def _bgp_auth_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("BGP auth profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            bgp = router_entry.find('protocol/bgp')
            if bgp is None:
                continue
            for profile_entry in self._bgp_auth_profile_config_entries(bgp):
                profile = self._convert_bgp_auth_profile(profile_entry)
                if not profile or profile['name'] in seen_names:
                    continue
                seen_names.add(profile['name'])
                profiles.append(profile)

        return profiles

    def _bgp_auth_profile_config_entries(self, bgp):
        entries = []
        for path in ['auth-profile/entry', 'auth-profiles/entry', 'authentication-profile/entry', 'authentication-profiles/entry']:
            entries.extend(bgp.findall(path))
        return entries

    def _convert_bgp_auth_profile(self, profile_entry):
        profile_name = profile_entry.get('name')
        if not profile_name:
            return None

        secret = (
            self._child_text(profile_entry, 'secret')
            or self._child_text(profile_entry, 'password')
            or self._child_text(profile_entry, 'key')
        )
        if not secret:
            return None

        return {'name': profile_name, 'secret': secret}

    def _bgp_address_family_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("BGP address family profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            router_name = router_entry.get('name')
            bgp = router_entry.find('protocol/bgp')
            if not router_name or bgp is None:
                continue

            for group_entry in bgp.findall('peer-group/entry'):
                group_name = group_entry.get('name')
                if not group_name:
                    continue
                for family, af_entry in self._bgp_address_family_entries(group_entry):
                    profile = self._convert_bgp_address_family_profile(
                        self._bgp_address_family_profile_name(router_name, group_name, None, family),
                        family,
                        af_entry,
                    )
                    if profile and profile['name'] not in seen_names:
                        seen_names.add(profile['name'])
                        profiles.append(profile)

                for peer_entry in group_entry.findall('peer/entry'):
                    peer_name = peer_entry.get('name')
                    if not peer_name:
                        continue
                    for family, af_entry in self._bgp_address_family_entries(peer_entry):
                        profile = self._convert_bgp_address_family_profile(
                            self._bgp_address_family_profile_name(router_name, group_name, peer_name, family),
                            family,
                            af_entry,
                        )
                        if profile and profile['name'] not in seen_names:
                            seen_names.add(profile['name'])
                            profiles.append(profile)

        return profiles

    def _bgp_address_family_entries(self, entry):
        entries = []
        for family, paths in {
            'ipv4': [
                'address-family/ipv4',
                'address-family/ipv4-unicast',
                'address-family/ipv4/unicast',
                'afi-safi/ipv4-unicast',
            ],
            'ipv6': [
                'address-family/ipv6',
                'address-family/ipv6-unicast',
                'address-family/ipv6/unicast',
                'afi-safi/ipv6-unicast',
            ],
        }.items():
            for path in paths:
                af_entry = entry.find(path)
                if af_entry is not None:
                    entries.append((family, af_entry))
                    break
        return entries

    def _convert_bgp_address_family_profile(self, profile_name, family, af_entry):
        unicast = self._convert_bgp_address_family_unicast(af_entry)
        if not unicast:
            return None
        return {'name': profile_name, family: {'unicast': unicast}}

    def _convert_bgp_address_family_unicast(self, af_entry):
        payload = {}
        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('soft-reconfig-with-stored-info', 'soft_reconfig_with_stored_info'),
            ('soft-reconfiguration-with-stored-info', 'soft_reconfig_with_stored_info'),
            ('as-override', 'as_override'),
            ('route-reflector-client', 'route_reflector_client'),
            ('default-originate', 'default_originate'),
        ]:
            value = self._child_text(af_entry, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if value.lower() in {'yes', 'no'} else value

        default_originate_map = self._child_text(af_entry, 'default-originate-map')
        if default_originate_map:
            payload['default_originate_map'] = default_originate_map

        add_path = self._convert_bgp_add_path(af_entry.find('add-path'))
        if add_path:
            payload['add_path'] = add_path

        allowas_in = self._convert_bgp_allowas_in(af_entry.find('allowas-in'))
        if allowas_in:
            payload['allowas_in'] = allowas_in

        maximum_prefix_entry = af_entry.find('maximum-prefix')
        if maximum_prefix_entry is None:
            maximum_prefix_entry = af_entry.find('max-prefix')
        maximum_prefix = self._convert_bgp_maximum_prefix(maximum_prefix_entry)
        if maximum_prefix:
            payload['maximum_prefix'] = maximum_prefix

        next_hop = self._convert_bgp_next_hop_option(af_entry.find('next-hop'))
        if next_hop:
            payload['next_hop'] = next_hop

        remove_private_as_entry = af_entry.find('remove-private-AS')
        if remove_private_as_entry is None:
            remove_private_as_entry = af_entry.find('remove-private-as')
        remove_private_as = self._convert_bgp_remove_private_as(remove_private_as_entry)
        if remove_private_as:
            payload['remove_private_AS'] = remove_private_as

        send_community = self._convert_bgp_send_community(af_entry.find('send-community'))
        if send_community:
            payload['send_community'] = send_community

        orf = self._convert_bgp_orf(af_entry.find('orf'))
        if orf:
            payload['orf'] = orf

        return payload

    def _convert_bgp_add_path(self, add_path):
        if add_path is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('tx-all-paths', 'tx_all_paths'),
            ('tx-bestpath-per-AS', 'tx_bestpath_per_AS'),
            ('tx-bestpath-per-as', 'tx_bestpath_per_AS'),
        ]:
            value = self._child_text(add_path, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if value.lower() in {'yes', 'no'} else value
        return payload or None

    def _convert_bgp_allowas_in(self, allowas_in):
        if allowas_in is None:
            return None

        occurrence = self._child_text(allowas_in, 'occurrence')
        if occurrence and occurrence.isdigit():
            return {'occurrence': int(occurrence)}
        if allowas_in.find('origin') is not None:
            return {'origin': {}}
        value = self._first_text_or_member(allowas_in)
        if value and value.isdigit():
            return {'occurrence': int(value)}
        if value == 'origin':
            return {'origin': {}}
        return None

    def _convert_bgp_maximum_prefix(self, maximum_prefix):
        if maximum_prefix is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('num-prefixes', 'num_prefixes'),
            ('number', 'num_prefixes'),
            ('prefix-limit', 'num_prefixes'),
            ('threshold', 'threshold'),
        ]:
            value = self._child_text(maximum_prefix, panos_name)
            if value and value.isdigit():
                payload[scm_name] = int(value)

        action = self._child_text(maximum_prefix, 'action')
        if action:
            payload['action'] = {action.replace('-', '_'): {}}
        elif maximum_prefix.find('warning-only') is not None:
            payload['action'] = {'warning_only': {}}
        elif maximum_prefix.find('restart') is not None:
            payload['action'] = {'restart': {}}

        return payload or None

    def _convert_bgp_next_hop_option(self, next_hop):
        if next_hop is None:
            return None
        if next_hop.find('self-force') is not None:
            return {'self_force': {}}
        if next_hop.find('self') is not None:
            return {'self': {}}
        value = self._first_text_or_member(next_hop)
        if value in {'self', 'self-force', 'self_force'}:
            return {value.replace('-', '_'): {}}
        return None

    def _convert_bgp_remove_private_as(self, remove_private_as):
        if remove_private_as is None:
            return None
        if remove_private_as.find('replace-AS') is not None or remove_private_as.find('replace-as') is not None:
            return {'replace_AS': {}}
        if remove_private_as.find('all') is not None:
            return {'all': {}}
        value = self._first_text_or_member(remove_private_as)
        if value in {'all', 'replace-AS', 'replace-as'}:
            return {value.replace('-', '_').replace('_as', '_AS'): {}}
        return None

    def _convert_bgp_send_community(self, send_community):
        if send_community is None:
            return None
        for option in ['all', 'both', 'extended', 'large', 'standard']:
            if send_community.find(option) is not None:
                return {option: {}}
        value = self._first_text_or_member(send_community)
        if value in {'all', 'both', 'extended', 'large', 'standard'}:
            return {value: {}}
        return None

    def _convert_bgp_orf(self, orf):
        if orf is None:
            return None

        orf_prefix_list = self._child_text(orf, 'orf-prefix-list') or self._child_text(orf, 'prefix-list')
        if orf_prefix_list:
            return {'orf_prefix_list': orf_prefix_list}
        value = self._first_text_or_member(orf)
        if value in {'none', 'both', 'receive', 'send'}:
            return {'orf_prefix_list': value}
        return None

    def _bgp_address_family_profile_name(self, router_name, group_name, peer_name, family):
        if peer_name:
            return self._sanitize_name(f"{router_name}-{group_name}-{peer_name}-{family}-af")
        return self._sanitize_name(f"{router_name}-{group_name}-{family}-af")

    def _bgp_filtering_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("BGP filtering profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for family in ['ipv4', 'ipv6']:
                unicast = self._convert_bgp_filtering_profile_unicast(router_entry, family)
                if not unicast:
                    continue
                profiles.append(
                    {
                        'name': self._bgp_filtering_profile_name(router_entry, family),
                        family: {'unicast': unicast},
                    }
                )
        return profiles

    def _convert_bgp_filtering_profile_unicast(self, router_entry, family):
        payload = {}

        route_maps = {}
        inbound_route_map = self._first_bgp_policy_artifact(router_entry, 'import', family, self._bgp_policy_route_map_name)
        if inbound_route_map:
            route_maps['inbound'] = inbound_route_map
        outbound_route_map = self._first_bgp_policy_artifact(router_entry, 'export', family, self._bgp_policy_route_map_name)
        if outbound_route_map:
            route_maps['outbound'] = outbound_route_map
        if route_maps:
            payload['route_maps'] = route_maps

        inbound_filters = self._convert_bgp_filtering_network_filters(router_entry, 'import', family)
        if inbound_filters:
            payload['inbound_network_filters'] = inbound_filters

        outbound_filters = self._convert_bgp_filtering_network_filters(router_entry, 'export', family)
        if outbound_filters:
            payload['outbound_network_filters'] = outbound_filters

        return payload or None

    def _convert_bgp_filtering_network_filters(self, router_entry, direction, family):
        filters = {}
        prefix_list = self._first_bgp_policy_artifact(
            router_entry,
            direction,
            family,
            self._bgp_policy_prefix_list_name,
            needs_prefix=True,
        )
        if prefix_list:
            filters['prefix_list'] = prefix_list

        access_list = self._first_bgp_policy_artifact(
            router_entry,
            direction,
            family,
            self._bgp_policy_access_list_name,
            needs_access_list=True,
        )
        if access_list:
            filters['distribute_list'] = access_list

        return filters or None

    def _first_bgp_policy_artifact(
        self,
        router_entry,
        direction,
        family,
        name_builder,
        needs_prefix=False,
        needs_access_list=False,
    ):
        for rule_entry in self._bgp_policy_rule_entries(router_entry, direction):
            if self._bgp_policy_rule_family(rule_entry) != family:
                continue
            if needs_prefix and not self._bgp_policy_rule_prefixes(rule_entry):
                continue
            if needs_access_list and not self._member_texts(rule_entry.find('match/route-table/access-list')):
                continue
            return name_builder(router_entry, direction, rule_entry)
        return None

    def _bgp_filtering_profile_name(self, router_entry, family):
        return self._sanitize_name(f"{router_entry.get('name')}-{family}-bgp-filtering")

    def _route_prefix_list_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Route prefix list migration currently supports local firewall XML only.")
            return []

        prefix_lists = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for direction in ['import', 'export']:
                for rule_entry in self._bgp_policy_rule_entries(router_entry, direction):
                    prefixes = self._bgp_policy_rule_prefixes(rule_entry)
                    if not prefixes:
                        continue

                    list_name = self._bgp_policy_prefix_list_name(router_entry, direction, rule_entry)
                    if list_name in seen_names:
                        continue
                    seen_names.add(list_name)

                    action = self._bgp_policy_rule_action(rule_entry)
                    prefix_lists.append(
                        {
                            'name': list_name,
                            'prefix_list': [
                                self._route_prefix_list_rule(index, prefix, action)
                                for index, prefix in enumerate(prefixes, start=1)
                            ],
                        }
                    )

        return prefix_lists

    def _route_access_list_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Route access list migration currently supports local firewall XML only.")
            return []

        access_lists = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for direction in ['import', 'export']:
                for rule_entry in self._bgp_policy_rule_entries(router_entry, direction):
                    values = self._member_texts(rule_entry.find('match/route-table/access-list'))
                    if not values:
                        continue
                    name = self._bgp_policy_access_list_name(router_entry, direction, rule_entry)
                    if name in seen_names:
                        continue
                    seen_names.add(name)
                    access_lists.append(
                        {
                            'name': name,
                            'access_list': [
                                {'name': index, 'action': self._bgp_policy_rule_action(rule_entry), 'source': value}
                                for index, value in enumerate(values, start=1)
                            ],
                        }
                    )

        return access_lists

    def _route_community_list_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Route community list migration currently supports local firewall XML only.")
            return []

        community_lists = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for direction in ['import', 'export']:
                for rule_entry in self._bgp_policy_rule_entries(router_entry, direction):
                    values = []
                    for path in ['match/community', 'match/regular-community']:
                        values.extend(self._member_texts(rule_entry.find(path)))
                    if not values:
                        continue
                    name = self._bgp_policy_community_list_name(router_entry, direction, rule_entry)
                    if name in seen_names:
                        continue
                    seen_names.add(name)
                    community_lists.append(
                        {
                            'name': name,
                            'community_list': [
                                {'name': index, 'action': self._bgp_policy_rule_action(rule_entry), 'community': value}
                                for index, value in enumerate(values, start=1)
                            ],
                        }
                    )

        return community_lists

    def _route_path_access_list_entries(self):
        if self.config_type != 'local':
            self.logger.warning("Route path access list migration currently supports local firewall XML only.")
            return []

        path_lists = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for direction in ['import', 'export']:
                for rule_entry in self._bgp_policy_rule_entries(router_entry, direction):
                    values = []
                    for path in ['match/as-path', 'match/as-path-access-list']:
                        values.extend(self._member_texts(rule_entry.find(path)))
                    if not values:
                        continue
                    name = self._bgp_policy_path_access_list_name(router_entry, direction, rule_entry)
                    if name in seen_names:
                        continue
                    seen_names.add(name)
                    path_lists.append(
                        {
                            'name': name,
                            'path_access_list': [
                                {'name': index, 'action': self._bgp_policy_rule_action(rule_entry), 'regular_expression': value}
                                for index, value in enumerate(values, start=1)
                            ],
                        }
                    )

        return path_lists

    def _bgp_route_map_entries(self):
        if self.config_type != 'local':
            self.logger.warning("BGP route map migration currently supports local firewall XML only.")
            return []

        route_maps = []
        seen_names = set()
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for direction in ['import', 'export']:
                for sequence, rule_entry in enumerate(self._bgp_policy_rule_entries(router_entry, direction), start=1):
                    route_map_name = self._bgp_policy_route_map_name(router_entry, direction, rule_entry)
                    if route_map_name in seen_names:
                        continue
                    seen_names.add(route_map_name)

                    rule = {
                        'name': sequence * 10,
                        'action': self._bgp_policy_rule_action(rule_entry),
                    }

                    description = self._child_text(rule_entry, 'description')
                    if description:
                        rule['description'] = description

                    prefixes = self._bgp_policy_rule_prefixes(rule_entry)
                    if prefixes:
                        family = self._bgp_policy_rule_family(rule_entry)
                        rule['match'] = {
                            family: {
                                'address': {
                                    'prefix_list': self._bgp_policy_prefix_list_name(router_entry, direction, rule_entry)
                                }
                            }
                        }

                    access_list = self._bgp_policy_access_list_name_if_needed(router_entry, direction, rule_entry)
                    if access_list:
                        match = rule.setdefault('match', {})
                        ipv4 = match.setdefault('ipv4', {})
                        address = ipv4.setdefault('address', {})
                        address['access_list'] = access_list

                    community_list = self._bgp_policy_community_list_name_if_needed(router_entry, direction, rule_entry)
                    if community_list:
                        rule.setdefault('match', {})['regular_community'] = community_list

                    path_access_list = self._bgp_policy_path_access_list_name_if_needed(router_entry, direction, rule_entry)
                    if path_access_list:
                        rule.setdefault('match', {})['as_path_access_list'] = path_access_list

                    scalar_match = self._convert_bgp_policy_match(rule_entry.find('match'))
                    if scalar_match:
                        match = rule.setdefault('match', {})
                        match.update(scalar_match)

                    set_payload = self._convert_bgp_policy_set(rule_entry.find('set'))
                    if set_payload:
                        rule['set'] = set_payload

                    route_maps.append(
                        {
                            'name': route_map_name,
                            'description': f"Generated from PAN-OS BGP {direction} rule {rule_entry.get('name')}",
                            'route_map': [rule],
                        }
                    )

        return route_maps

    def _bgp_route_map_redistribution_entries(self):
        if self.config_type != 'local':
            self.logger.warning("BGP route map redistribution migration currently supports local firewall XML only.")
            return []

        entries = []
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            for redist_entry in self._bgp_redist_rule_entries(router_entry):
                name = self._bgp_redist_route_map_name(router_entry, redist_entry)
                route_map = {
                    'name': 10,
                    'action': self._bgp_policy_rule_action(redist_entry),
                }
                metric = self._child_text(redist_entry, 'metric')
                if metric and metric.isdigit():
                    route_map['set'] = {'metric': {'action': 'set', 'value': int(metric)}}
                entries.append({'name': name, 'route_map': [route_map]})

        return entries

    def _bgp_redistribution_profile_entries(self):
        if self.config_type != 'local':
            self.logger.warning("BGP redistribution profile migration currently supports local firewall XML only.")
            return []

        profiles = []
        for router_entry in self.root.findall('./devices/entry/network/virtual-router/entry'):
            redist_rules = self._bgp_redist_rule_entries(router_entry)
            if not redist_rules:
                continue

            unicast = {}
            for redist_entry in redist_rules:
                source_type = self._bgp_redist_source_type(redist_entry)
                if source_type not in {'static', 'connected', 'ospf'}:
                    continue
                payload = {'enable': True}
                metric = self._child_text(redist_entry, 'metric')
                if metric and metric.isdigit():
                    payload['metric'] = int(metric)
                payload['route_map'] = self._bgp_redist_route_map_name(router_entry, redist_entry)
                unicast[source_type] = payload

            if unicast:
                profiles.append(
                    {
                        'name': self._sanitize_name(f"{router_entry.get('name')}-bgp-redist"),
                        'ipv4': {'unicast': unicast},
                    }
                )

        return profiles

    def _convert_bgp(self, bgp, router_entry):
        if bgp is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('router-id', 'router_id'),
        ]:
            value = self._child_text(bgp, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if panos_name == 'enable' else value

        local_as = self._child_text(bgp, 'local-as')
        if local_as:
            payload['local_as'] = local_as

        redist_profile_name = self._bgp_redist_profile_name_if_needed(router_entry)
        if redist_profile_name:
            payload['redistribution_profile'] = redist_profile_name

        peer_groups = []
        for group_entry in bgp.findall('peer-group/entry'):
            group_payload = self._convert_bgp_peer_group(group_entry, router_entry)
            if group_payload:
                peer_groups.append(group_payload)
        if peer_groups:
            payload['peer_group'] = peer_groups

        return payload or None

    def _convert_bgp_peer_group(self, group_entry, router_entry):
        group_name = group_entry.get('name')
        if not group_name:
            return None

        payload = {'name': group_name}
        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('type', 'type'),
            ('auth-profile', 'authentication_profile'),
            ('authentication-profile', 'authentication_profile'),
        ]:
            value = self._child_text(group_entry, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if panos_name == 'enable' else value

        timers = self._convert_bgp_timers(group_entry.find('timers'))
        if timers:
            payload['timers'] = timers

        address_family = self._convert_bgp_address_family_references(
            router_entry,
            group_entry,
            group_name,
        )
        if address_family:
            payload['address_family'] = address_family

        peers = []
        for peer_entry in group_entry.findall('peer/entry'):
            peer_payload = self._convert_bgp_peer(peer_entry, router_entry, group_name)
            if peer_payload:
                peers.append(peer_payload)
        if peers:
            payload['peer'] = peers

        return payload

    def _convert_bgp_peer(self, peer_entry, router_entry, group_name):
        peer_name = peer_entry.get('name')
        if not peer_name:
            return None

        payload = {'name': peer_name}
        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('peer-as', 'peer_as'),
            ('local-address/interface', 'local_interface'),
            ('local-address/ip', 'local_address'),
            ('peer-address/ip', 'peer_address'),
            ('auth-profile', 'authentication_profile'),
            ('authentication-profile', 'authentication_profile'),
        ]:
            value = self._child_text(peer_entry, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if panos_name == 'enable' else value

        timers = self._convert_bgp_timers(peer_entry.find('timers'))
        if timers:
            payload['timers'] = timers

        multihop = self._convert_bgp_multihop(peer_entry.find('multihop'))
        if multihop:
            payload['multihop'] = multihop

        connection_options = self._convert_bgp_connection_options(peer_entry.find('connection-options'))
        if connection_options:
            payload['connection_options'] = connection_options

        address_family = self._convert_bgp_address_family_references(
            router_entry,
            peer_entry,
            group_name,
            peer_name,
        )

        import_ipv4_route_maps = self._bgp_policy_route_map_names(router_entry, 'import', family='ipv4')
        export_ipv4_route_maps = self._bgp_policy_route_map_names(router_entry, 'export', family='ipv4')
        import_ipv6_route_maps = self._bgp_policy_route_map_names(router_entry, 'import', family='ipv6')
        export_ipv6_route_maps = self._bgp_policy_route_map_names(router_entry, 'export', family='ipv6')
        if import_ipv4_route_maps or export_ipv4_route_maps or import_ipv6_route_maps or export_ipv6_route_maps:
            if import_ipv4_route_maps or export_ipv4_route_maps:
                address_family.setdefault('ipv4', {'unicast': {}})
                address_family['ipv4']['unicast']['filtering_profile'] = self._bgp_filtering_profile_name(router_entry, 'ipv4')
                if import_ipv4_route_maps:
                    address_family['ipv4']['unicast']['import_route_map'] = import_ipv4_route_maps[0]
                if export_ipv4_route_maps:
                    address_family['ipv4']['unicast']['export_route_map'] = export_ipv4_route_maps[0]
            if import_ipv6_route_maps or export_ipv6_route_maps:
                address_family.setdefault('ipv6', {'unicast': {}})
                address_family['ipv6']['unicast']['filtering_profile'] = self._bgp_filtering_profile_name(router_entry, 'ipv6')
                if import_ipv6_route_maps:
                    address_family['ipv6']['unicast']['import_route_map'] = import_ipv6_route_maps[0]
                if export_ipv6_route_maps:
                    address_family['ipv6']['unicast']['export_route_map'] = export_ipv6_route_maps[0]
        if address_family:
            payload['address_family'] = address_family

        return payload

    def _convert_bgp_address_family_references(self, router_entry, entry, group_name, peer_name=None):
        router_name = router_entry.get('name')
        if not router_name or not group_name:
            return {}

        address_family = {}
        for family, _ in self._bgp_address_family_entries(entry):
            address_family[family] = {
                'unicast': {
                    'address_family_profile': self._bgp_address_family_profile_name(
                        router_name,
                        group_name,
                        peer_name,
                        family,
                    )
                }
            }
        return address_family

    def _convert_bgp_timers(self, timers):
        if timers is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('keep-alive-interval', 'keep_alive_interval'),
            ('hold-time', 'hold_time'),
            ('open-delay-time', 'open_delay_time'),
            ('idle-hold-time', 'idle_hold_time'),
            ('min-route-advertisement-interval', 'min_route_advertisement_interval'),
        ]:
            value = self._child_text(timers, panos_name)
            if value and value.isdigit():
                payload[scm_name] = int(value)
        return payload or None

    def _convert_bgp_multihop(self, multihop):
        if multihop is None:
            return None

        payload = {}
        enable = self._child_text(multihop, 'enable')
        if enable:
            payload['enable'] = enable.lower() == 'yes'

        ttl = self._child_text(multihop, 'ttl')
        if ttl and ttl.isdigit():
            payload['ttl'] = int(ttl)

        return payload or None

    def _convert_bgp_connection_options(self, connection_options):
        if connection_options is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('incoming-bgp-connection', 'incoming_bgp_connection'),
            ('outgoing-bgp-connection', 'outgoing_bgp_connection'),
        ]:
            value = self._child_text(connection_options, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if value.lower() in {'yes', 'no'} else value

        source_port = self._child_text(connection_options, 'local-port')
        if source_port and source_port.isdigit():
            payload['local_port'] = int(source_port)

        return payload or None

    def _convert_ospf(self, ospf):
        if ospf is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('router-id', 'router_id'),
            ('rfc1583', 'rfc1583'),
            ('reject-default-route', 'reject_default_route'),
            ('allow-redist-default-route', 'allow_redist_default_route'),
        ]:
            value = self._child_text(ospf, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes' if value.lower() in {'yes', 'no'} else value

        areas = []
        for area_entry in ospf.findall('area/entry'):
            area = self._convert_ospf_area(area_entry)
            if area:
                areas.append(area)
        if areas:
            payload['area'] = areas

        export_rules = self._convert_ospf_export_rules(ospf)
        if export_rules:
            payload['export_rules'] = export_rules

        redistribution_profile = self._ospf_redistribution_profile_name(ospf)
        if redistribution_profile:
            payload['redistribution_profile'] = redistribution_profile

        return payload or None

    def _convert_ospfv3(self, ospfv3):
        if ospfv3 is None:
            return None

        payload = self._convert_ospf(ospfv3) or {}
        return payload or None

    def _convert_ospf_area(self, area_entry):
        area_name = area_entry.get('name')
        if not area_name:
            return None

        payload = {'name': area_name}
        authentication = self._child_text(area_entry, 'authentication')
        if authentication:
            payload['authentication'] = authentication

        area_type = area_entry.find('type')
        if area_type is not None:
            type_payload = self._convert_ospf_area_type(area_type)
            if type_payload:
                payload['type'] = type_payload

        for panos_name, scm_name in [
            ('import-list', 'import_list'),
            ('export-list', 'export_list'),
            ('inbound-filter-list', 'inbound_filter_list'),
            ('outbound-filter-list', 'outbound_filter_list'),
        ]:
            value = self._child_text(area_entry, panos_name)
            if value:
                payload[scm_name] = value

        ranges = self._convert_ospf_ranges(area_entry)
        if ranges:
            payload['range'] = ranges

        vr_ranges = self._convert_ospf_vr_ranges(area_entry)
        if vr_ranges:
            payload['vr_range'] = vr_ranges

        interfaces = []
        for interface_entry in area_entry.findall('interface/entry'):
            interface = self._convert_ospf_interface(interface_entry)
            if interface:
                interfaces.append(interface)
        if interfaces:
            payload['interface'] = interfaces

        virtual_links = []
        for virtual_link_entry in area_entry.findall('virtual-link/entry'):
            virtual_link = self._convert_ospf_virtual_link(virtual_link_entry)
            if virtual_link:
                virtual_links.append(virtual_link)
        if virtual_links:
            payload['virtual_link'] = virtual_links

        return payload

    def _convert_ospf_area_type(self, area_type):
        child_name = self._first_child_name(area_type)
        if not child_name:
            return None

        child = area_type.find(child_name)
        payload = {}
        for panos_name, scm_name in [
            ('default-route/advertise', 'default_route_advertise'),
            ('default-route/metric', 'default_route_metric'),
            ('default-route/type', 'default_route_type'),
            ('accept-summary', 'accept_summary'),
        ]:
            value = self._child_text(child, panos_name) if child is not None else None
            if not value:
                continue
            if value.lower() in {'yes', 'no'}:
                payload[scm_name] = value.lower() == 'yes'
            elif value.isdigit():
                payload[scm_name] = int(value)
            else:
                payload[scm_name] = value

        abr = self._child_text(child, 'abr') if child is not None else None
        if abr:
            payload['abr'] = abr

        return {child_name: payload}

    def _convert_ospf_ranges(self, area_entry):
        ranges = []
        for range_entry in area_entry.findall('range/entry'):
            name = range_entry.get('name')
            if not name:
                continue
            payload = {'name': name}
            substitute = self._child_text(range_entry, 'substitute')
            if substitute:
                payload['substitute'] = substitute
            advertise = self._child_text(range_entry, 'advertise')
            if advertise:
                payload['advertise'] = advertise.lower() == 'yes'
            ranges.append(payload)
        return ranges

    def _convert_ospf_vr_ranges(self, area_entry):
        ranges = []
        for range_entry in area_entry.findall('vr-range/entry'):
            name = range_entry.get('name')
            if not name:
                continue
            mode = self._first_child_name(range_entry)
            if mode in {'advertise', 'suppress'}:
                ranges.append({mode: {'name': name}})
            else:
                ranges.append({'advertise': {'name': name}})
        return ranges

    def _convert_ospf_export_rules(self, ospf):
        export_rules = []
        for rule_entry in self._ospf_export_rule_entries(ospf):
            rule = self._convert_ospf_export_rule(rule_entry)
            if rule:
                export_rules.append(rule)
        return export_rules

    def _ospf_export_rule_entries(self, ospf):
        entries = []
        for path in ['export-rules/entry', 'export-rule/entry', 'redist-rules/entry', 'redist-rule/entry']:
            entries.extend(ospf.findall(path))
        return entries

    def _convert_ospf_export_rule(self, rule_entry):
        rule_name = rule_entry.get('name')
        if not rule_name:
            return None

        payload = {'name': rule_name}
        new_path_type = (
            self._child_text(rule_entry, 'new-path-type')
            or self._child_text(rule_entry, 'path-type')
            or self._child_text(rule_entry, 'type')
        )
        if new_path_type:
            payload['new_path_type'] = new_path_type

        new_tag = self._child_text(rule_entry, 'new-tag') or self._child_text(rule_entry, 'tag')
        if new_tag:
            payload['new_tag'] = new_tag

        metric = self._child_text(rule_entry, 'metric')
        if metric and metric.isdigit():
            payload['metric'] = int(metric)

        return payload

    def _ospf_redistribution_profile_name(self, ospf):
        explicit = (
            self._child_text(ospf, 'redistribution-profile')
            or self._child_text(ospf, 'redist-profile')
        )
        if explicit:
            return explicit
        return None

    def _convert_ospf_virtual_link(self, virtual_link_entry):
        link_name = virtual_link_entry.get('name')
        if not link_name:
            return None

        payload = {'name': link_name}
        for panos_name, scm_name in [
            ('neighbor-id', 'neighbor_id'),
            ('transit-area-id', 'transit_area_id'),
            ('authentication', 'authentication'),
            ('timing', 'timing'),
        ]:
            value = self._child_text(virtual_link_entry, panos_name)
            if value:
                payload[scm_name] = value

        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('passive', 'passive'),
        ]:
            value = self._child_text(virtual_link_entry, panos_name)
            if value:
                payload[scm_name] = value.lower() == 'yes'

        for panos_name, scm_name in [
            ('interface-id', 'interface_id'),
            ('instance-id', 'instance_id'),
        ]:
            value = self._child_text(virtual_link_entry, panos_name)
            if value and value.isdigit():
                payload[scm_name] = int(value)

        vr_timing = self._convert_ospf_vr_timing(virtual_link_entry.find('vr-timing'))
        if vr_timing:
            payload['vr_timing'] = vr_timing

        bfd_profile = self._child_text(virtual_link_entry, 'bfd/profile')
        if bfd_profile:
            payload['bfd'] = {'profile': bfd_profile}

        return payload

    def _convert_ospf_interface(self, interface_entry):
        interface_name = interface_entry.get('name')
        if not interface_name:
            return None

        payload = {'name': interface_name}
        for panos_name, scm_name in [
            ('enable', 'enable'),
            ('passive', 'passive'),
            ('mtu-ignore', 'mtu_ignore'),
            ('priority', 'priority'),
            ('metric', 'metric'),
            ('instance-id', 'instance_id'),
            ('authentication', 'authentication'),
            ('timing', 'timing'),
        ]:
            value = self._child_text(interface_entry, panos_name)
            if not value:
                continue
            if value.lower() in {'yes', 'no'}:
                payload[scm_name] = value.lower() == 'yes'
            elif value.isdigit():
                payload[scm_name] = int(value)
            else:
                payload[scm_name] = value

        link_type = interface_entry.find('link-type')
        if link_type is not None:
            child_name = self._first_child_name(link_type)
            if child_name:
                payload['link_type'] = {child_name: {}}

        bfd_profile = self._child_text(interface_entry, 'bfd/profile')
        if bfd_profile:
            payload['bfd'] = {'profile': bfd_profile}

        neighbors = []
        for neighbor_entry in interface_entry.findall('neighbor/entry'):
            neighbor_name = neighbor_entry.get('name')
            if neighbor_name:
                neighbors.append({'name': neighbor_name})
        if neighbors:
            payload['neighbor'] = neighbors

        vr_timing = self._convert_ospf_vr_timing(interface_entry.find('vr-timing'))
        if vr_timing:
            payload['vr_timing'] = vr_timing

        return payload

    def _convert_ospf_vr_timing(self, timing_entry):
        if timing_entry is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('hello-interval', 'hello_interval'),
            ('dead-counts', 'dead_counts'),
            ('retransmit-interval', 'retransmit_interval'),
            ('transit-delay', 'transit_delay'),
            ('gr-delay', 'gr_delay'),
        ]:
            value = self._child_text(timing_entry, panos_name)
            if value and value.isdigit():
                payload[scm_name] = int(value)
        return payload or None

    def _bgp_policy_rule_entries(self, router_entry, direction):
        entries = []
        for path in [
            f'protocol/bgp/policy/{direction}/rules/entry',
            f'protocol/bgp/policy/{direction}/entry',
        ]:
            entries.extend(router_entry.findall(path))
        return entries

    def _bgp_policy_route_map_names(self, router_entry, direction, family=None):
        names = []
        for rule_entry in self._bgp_policy_rule_entries(router_entry, direction):
            if family and self._bgp_policy_rule_family(rule_entry) != family:
                continue
            names.append(self._bgp_policy_route_map_name(router_entry, direction, rule_entry))
        return names

    def _bgp_policy_route_map_name(self, router_entry, direction, rule_entry):
        return self._sanitize_name(f"{router_entry.get('name')}-{direction}-{rule_entry.get('name')}-rm")

    def _bgp_policy_prefix_list_name(self, router_entry, direction, rule_entry):
        return self._sanitize_name(f"{router_entry.get('name')}-{direction}-{rule_entry.get('name')}-pl")

    def _bgp_policy_access_list_name(self, router_entry, direction, rule_entry):
        return self._sanitize_name(f"{router_entry.get('name')}-{direction}-{rule_entry.get('name')}-acl")

    def _bgp_policy_community_list_name(self, router_entry, direction, rule_entry):
        return self._sanitize_name(f"{router_entry.get('name')}-{direction}-{rule_entry.get('name')}-cl")

    def _bgp_policy_path_access_list_name(self, router_entry, direction, rule_entry):
        return self._sanitize_name(f"{router_entry.get('name')}-{direction}-{rule_entry.get('name')}-pal")

    def _bgp_policy_access_list_name_if_needed(self, router_entry, direction, rule_entry):
        if self._member_texts(rule_entry.find('match/route-table/access-list')):
            return self._bgp_policy_access_list_name(router_entry, direction, rule_entry)
        return None

    def _bgp_policy_community_list_name_if_needed(self, router_entry, direction, rule_entry):
        for path in ['match/community', 'match/regular-community']:
            if self._member_texts(rule_entry.find(path)):
                return self._bgp_policy_community_list_name(router_entry, direction, rule_entry)
        return None

    def _bgp_policy_path_access_list_name_if_needed(self, router_entry, direction, rule_entry):
        for path in ['match/as-path', 'match/as-path-access-list']:
            if self._member_texts(rule_entry.find(path)):
                return self._bgp_policy_path_access_list_name(router_entry, direction, rule_entry)
        return None

    def _bgp_policy_rule_family(self, rule_entry):
        for prefix in self._bgp_policy_rule_prefixes(rule_entry):
            if ':' in prefix.get('prefix', ''):
                return 'ipv6'
        for path in ['match/ipv6-address-prefix', 'match/ipv6-nlri', 'match/ipv6-route-table']:
            if rule_entry.find(path) is not None:
                return 'ipv6'
        return 'ipv4'

    def _bgp_redist_rule_entries(self, router_entry):
        entries = []
        for path in [
            'protocol/bgp/redist-rules/entry',
            'protocol/bgp/redistribution-rule/entry',
            'protocol/bgp/redist-profile/entry',
        ]:
            entries.extend(router_entry.findall(path))
        return entries

    def _bgp_redist_route_map_name(self, router_entry, redist_entry):
        return self._sanitize_name(f"{router_entry.get('name')}-redist-{redist_entry.get('name')}-rm")

    def _bgp_redist_profile_name_if_needed(self, router_entry):
        if self._bgp_redist_rule_entries(router_entry):
            return self._sanitize_name(f"{router_entry.get('name')}-bgp-redist")
        return None

    def _bgp_redist_source_type(self, redist_entry):
        source_type = self._child_text(redist_entry, 'source/type') or self._child_text(redist_entry, 'type')
        if source_type:
            source_type = source_type.replace('-', '_')
        if source_type in {'connect', 'connected'}:
            return 'connected'
        if source_type in {'static', 'ospf'}:
            return source_type
        rule_name = redist_entry.get('name') or ''
        for candidate in ['static', 'connected', 'ospf']:
            if candidate in rule_name.lower():
                return candidate
        return None

    def _bgp_policy_rule_action(self, rule_entry):
        action = self._child_text(rule_entry, 'action')
        if action in {'allow', 'permit'}:
            return 'permit'
        if action == 'deny':
            return 'deny'
        return 'permit'

    def _bgp_policy_rule_prefixes(self, rule_entry):
        prefixes = []
        for path in [
            'match/address-prefix',
            'match/ipv6-address-prefix',
            'match/route-table',
            'match/ipv6-route-table',
            'match/nlri',
            'match/ipv6-nlri',
        ]:
            prefixes.extend(self._route_prefix_values(rule_entry.find(path)))
        return prefixes

    def _route_prefix_values(self, entry):
        if entry is None:
            return []

        values = []
        for member in entry.findall('member'):
            if member.text and member.text.strip():
                values.append({'prefix': member.text.strip()})

        for child in entry.findall('entry'):
            prefix = child.get('name') or self._child_text(child, 'prefix')
            if not prefix:
                continue
            payload = {'prefix': prefix}
            for panos_name, scm_name in [
                ('exact', 'exact'),
                ('greater-equal', 'ge'),
                ('less-equal', 'le'),
            ]:
                value = self._child_text(child, panos_name)
                if not value:
                    continue
                if panos_name == 'exact':
                    payload[scm_name] = value.lower() == 'yes'
                elif value.isdigit():
                    payload[scm_name] = int(value)
                else:
                    payload[scm_name] = value
            values.append(payload)

        return values

    @staticmethod
    def _route_prefix_list_rule(index, prefix, action):
        rule = {
            'name': index,
            'action': action,
            'prefix': prefix['prefix'],
        }
        for optional_key in ['exact', 'ge', 'le']:
            if optional_key in prefix:
                rule[optional_key] = prefix[optional_key]
        return rule

    def _convert_bgp_policy_match(self, match_entry):
        if match_entry is None:
            return None

        payload = {}
        scalar_fields = {
            'metric': 'metric',
            'local-preference': 'local_preference',
            'local-preference-value': 'local_preference',
            'origin': 'origin',
            'peer': 'peer',
            'interface': 'interface',
            'tag': 'tag',
        }
        for panos_name, scm_name in scalar_fields.items():
            value = self._first_text_or_member(match_entry.find(panos_name))
            if not value:
                continue
            payload[scm_name] = int(value) if value.isdigit() else value

        extended_communities = []
        for path in ['extended-community', 'ext-community']:
            extended_communities.extend(self._member_texts(match_entry.find(path)))
        if extended_communities:
            payload['extended_community'] = extended_communities

        large_communities = self._member_texts(match_entry.find('large-community'))
        if large_communities:
            payload['large_community'] = large_communities

        return payload or None

    def _convert_bgp_policy_set(self, set_entry):
        if set_entry is None:
            return None

        payload = {}
        for panos_name, scm_name in [
            ('local-preference', 'local_preference'),
            ('weight', 'weight'),
            ('tag', 'tag'),
            ('med', 'med'),
        ]:
            value = self._child_text(set_entry, panos_name)
            if value and value.isdigit():
                payload[scm_name] = int(value)

        metric = self._child_text(set_entry, 'metric') or self._child_text(set_entry, 'metric-value')
        if metric and metric.isdigit():
            payload['metric'] = {'action': 'set', 'value': int(metric)}

        origin = self._child_text(set_entry, 'origin')
        if origin:
            payload['origin'] = origin

        next_hop = self._child_text(set_entry, 'nexthop') or self._child_text(set_entry, 'next-hop')
        if next_hop:
            family = 'ipv6' if ':' in next_hop else 'ipv4'
            payload[family] = {'next_hop': next_hop}

        regular_communities = []
        for path in ['community', 'regular-community']:
            regular_communities.extend(self._member_texts(set_entry.find(path)))
        if regular_communities:
            payload['regular_community'] = regular_communities

        extended_communities = []
        for path in ['extended-community', 'ext-community']:
            extended_communities.extend(self._member_texts(set_entry.find(path)))
        if extended_communities:
            payload['extended_community'] = extended_communities

        large_communities = self._member_texts(set_entry.find('large-community'))
        if large_communities:
            payload['large_community'] = large_communities

        as_path_prepend = []
        for path in ['as-path-prepend', 'aspath-prepend']:
            as_path_prepend.extend(self._member_texts(set_entry.find(path)))
        if as_path_prepend:
            payload['as_path_prepend'] = [
                int(value) if value.isdigit() else value
                for value in as_path_prepend
            ]

        as_path_exclude = []
        for path in ['as-path-exclude', 'aspath-exclude']:
            as_path_exclude.extend(self._member_texts(set_entry.find(path)))
        if as_path_exclude:
            payload['as_path_exclude'] = as_path_exclude

        remove_communities = []
        for path in ['remove-community', 'remove-regular-community']:
            remove_communities.extend(self._member_texts(set_entry.find(path)))
            value = self._child_text(set_entry, path)
            if value:
                remove_communities.append(value)
        if remove_communities:
            payload['remove_regular_community'] = remove_communities

        overwrite_community = self._child_text(set_entry, 'overwrite-community')
        if overwrite_community:
            payload['overwrite_regular_community'] = overwrite_community.lower() == 'yes'

        return payload or None

    def _convert_lifetime(self, lifetime):
        if lifetime is None:
            return None

        for unit in ['seconds', 'minutes', 'hours', 'days']:
            value = self._child_text(lifetime, unit)
            if value and value.isdigit():
                return {unit: int(value)}

        return None

    def _convert_named_text_fields(self, entry, field_map):
        if entry is None:
            return None

        payload = {}
        for panos_name, scm_name in field_map.items():
            value = self._child_text(entry, panos_name)
            if value:
                payload[scm_name] = value

        return payload or None

    @staticmethod
    def _member_texts(entry):
        if entry is None:
            return []

        return [
            member.text.strip()
            for member in entry.findall('member')
            if member.text and member.text.strip()
        ]

    def _first_text_or_member(self, entry):
        if entry is None:
            return None

        if entry.text and entry.text.strip():
            return entry.text.strip()

        members = self._member_texts(entry)
        return members[0] if members else None

    def _entry_names_or_member_texts(self, entry):
        if entry is None:
            return []

        names = [
            child.get('name')
            for child in entry.findall('entry')
            if child.get('name')
        ]
        names.extend(self._member_texts(entry))
        return names

    @staticmethod
    def _child_text(entry, path):
        child = entry.find(path)
        if child is not None and child.text:
            return child.text.strip()
        return None

    def _zones(self):
        if self.config_type != 'local':
            self.logger.warning("Zone migration currently supports local firewall/vsys XML only.")
            return []

        zone_entries = []
        layer_map = {
            'layer3': 'layer3',
            'layer2': 'layer2',
            'v-wire': 'virtual_wire',
            'tap': 'tap',
        }

        for zone_entry in self.root.findall('./devices/entry/vsys/entry/zone/entry'):
            zone_name = zone_entry.get('name')
            if not zone_name:
                continue

            network_data = {}
            for panos_layer, scm_layer in layer_map.items():
                layer_element = zone_entry.find(f'network/{panos_layer}')
                if layer_element is None:
                    continue

                interfaces = [
                    member.text.strip()
                    for member in layer_element.findall('member')
                    if member.text and member.text.strip()
                ]
                if interfaces:
                    network_data[scm_layer] = interfaces

            zone_protection_profile = zone_entry.find('network/zone-protection-profile')
            if zone_protection_profile is not None and zone_protection_profile.text:
                network_data['zone_protection_profile'] = zone_protection_profile.text.strip()

            zone_payload = {'name': zone_name}
            if network_data:
                zone_payload['network'] = network_data

            zone_entries.append(zone_payload)

        return zone_entries

    def _convert_application(self, application):
        obj = {}
        obj['name'] = application.attrib['name']
        if application.find("description") is not None:
            obj['description'] = application.find("description").text.strip()

        subcategory = application.find("subcategory")
        if subcategory is not None:
            obj['subcategory'] = subcategory.text.strip()

        category = application.find("category")
        if category is not None:
            obj['category'] = category.text.strip()

        technology = application.find("technology")
        if technology is not None:
            obj['technology'] = technology.text.strip()

        parentapp = application.find("parent-app")
        if parentapp is not None:
            obj['parent_app'] = parentapp.text.strip()

        risk = application.find("risk")
        if risk is not None:
            obj['risk'] = int(risk.text.strip())

        transferfiles = application.find("able-to-transfer-file")
        if transferfiles is not None:
            obj['able_to_transfer_file'] = self._toBool(transferfiles.text.strip())

        noappidCaching = application.find("no-appid-caching")
        if noappidCaching is not None:
            obj['no_appid_caching'] = self._toBool(noappidCaching.text.strip())

        tunnapps = application.find("tunnel-applications")
        if tunnapps is not None:
            obj['tunnel_applications'] = self._toBool(tunnapps.text.strip())

        tunnelotherapps = application.find("tunnel-other-application")
        if tunnelotherapps is not None:
            obj['tunnel_other_application'] = self._toBool(tunnelotherapps.text.strip())

        pervasive = application.find("pervasive-use")
        if pervasive is not None:
            obj['pervasive_use'] = self._toBool(pervasive.text.strip())

        evasive = application.find("evasive-behavior")
        if evasive is not None:
            obj['evasive_behavior'] = self._toBool(evasive.text.strip())

        algdisable = application.find("alg-disable-capability")
        if algdisable is not None:
            obj['alg_disable_capability'] = algdisable.text.strip()

        consumebw = application.find("consume-big-bandwidth")
        if consumebw is not None:
            obj['consume_big_bandwidth'] = self._toBool(consumebw.text.strip())

        prone = application.find("prone-to-misuse")
        if prone is not None:
            obj['prone_to_misuse'] = self._toBool(prone.text.strip())

        malware = application.find("used-by-malware")
        if malware is not None:
            obj['used_by_malware'] = self._toBool(malware.text.strip())

        vulns = application.find("has-known-vulnerability")
        if vulns is not None:
            obj['has_known_vulnerability'] = self._toBool(vulns.text.strip())

        fileTypeIdent = application.find("file-type-ident")
        if fileTypeIdent is not None:
            obj['file_type_ident'] = self._toBool(fileTypeIdent.text.strip())

        virusIdent = application.find("virus-ident")
        if virusIdent is not None:
            obj['virus_ident'] = self._toBool(virusIdent.text.strip())

        dataIdent = application.find("data-ident")
        if dataIdent is not None:
            obj['data_ident'] = self._toBool(dataIdent.text.strip())

        timeout = application.find('timeout')
        if timeout is not None:
            obj['timeout'] = int(timeout.text.strip())

        udpTimeout = application.find('udp-timeout')
        if udpTimeout is not None:
            obj['udp_timeout'] = int(udpTimeout.text.strip())

        tcpTimeout = application.find('tcp-timeout')
        if tcpTimeout is not None:
            obj['tcp_timeout'] = int(tcpTimeout.text.strip())

        tcpTimeWaitTimeout = application.find('tcp-time-wait-timeout')
        if tcpTimeWaitTimeout is not None:
            obj['tcp_time_wait_timeout'] = int(tcpTimeWaitTimeout.text.strip())

        tcpHalfClosedTimeout = application.find('tcp-half-closed-timeout')
        if tcpHalfClosedTimeout is not None:
            obj['tcp_half_closed_timeout'] = int(tcpHalfClosedTimeout.text.strip())

        default = {}
        port = application.find('default/port')
        if port is not None:
            members = port.findall(".//member")
            if len(members) > 0:
                default['port'] = list(set(member.text for member in members))

        identByIpPort = application.find('default/ident-by-ip-protocol')
        if identByIpPort is not None:
            default['ident_by_ip_protocol'] = identByIpPort.text.strip()

        identByIcmpType = application.find('default/ident-by-icmp-type')
        if identByIcmpType is not None:
            code = identByIcmpType.find("code")
            if code is not None:
                default['ident_by_icmp_type'] = {'code': code.text.strip()}
            type = identByIcmpType.find("type")
            if type is not None:
                if default.get('ident_by_icmp_type') is None:
                    default['ident_by_icmp_type'] = {'type': type.text.strip()}
                else:
                    default['ident_by_icmp_type'].update({'type': type.text.strip()})

        identByIcmp6Type = application.find('default/ident-by-icmp6-type')
        if identByIcmp6Type is not None:
            code = identByIcmp6Type.find("code")
            if code is not None:
                default['ident_by_icmp6_type'] = {'code': code.text.strip()}
            type = identByIcmp6Type.find("type")
            if type is not None:
                if default.get('ident_by_icmp6_type') is None:
                    default['ident_by_icmp6_type'] = {'type': type.text.strip()}
                else:
                    default['ident_by_icmp6_type'].update({'type': type.text.strip()})

        if default != {}:
            obj['default'] = default

        if application.find("tag") is not None:
            tags = application.findall(".//tag/member")
            obj["tag"] = [tag.text for tag in tags]

        signature = application.find("signature")
        signatures = []
        if signature is not None:
            sigs = signature.findall("./entry")
            if sigs is not None:
                for entry in sigs:
                    objSignature = {}
                    objSignature['name'] = entry.attrib['name']
                    comment = entry.find("comment")
                    if comment is not None:
                        objSignature['comment'] = comment.text.strip()
                    scope = entry.find("scope")
                    if scope is not None:
                        objSignature['scope'] = scope.text.strip()
                    orderFree = entry.find("order-free")
                    if orderFree is not None:
                        objSignature['order_free'] = self._toBool(orderFree.text.strip())

                    if entry.find("and-condition") is not None:
                        andConditions = entry.findall("and-condition/entry")
                        if andConditions is not None:
                            objAndConditions = []
                            for andCondition in andConditions:
                                objAndCondition = {}
                                objAndCondition['name'] = andCondition.attrib['name']
                                if andCondition.find('or-condition') is not None:
                                    orConditions = andCondition.findall("or-condition/entry")
                                    if orConditions is not None:
                                        objOrConditions = []
                                        for orCondition in orConditions:
                                            objOrCondition = {}
                                            objOrCondition['name'] = orCondition.attrib['name']
                                            objOrCondition['operator'] = {}
                                            patternMatch = orCondition.find("operator/pattern-match")
                                            if patternMatch is not None:
                                                objOrCondition['operator']['pattern_match'] = {}
                                                context = patternMatch.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['pattern_match']['context'] = context.text.strip()
                                                pattern = patternMatch.find("pattern")
                                                if pattern is not None:
                                                    objOrCondition['operator']['pattern_match']['pattern'] = pattern.text.strip()

                                                if patternMatch.find("qualifier") is not None:
                                                    qualifiers = patternMatch.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['pattern_match']['qualifier'] = objQualifiers

                                            greaterThan = orCondition.find("operator/greater-than")
                                            if greaterThan is not None:
                                                objOrCondition['operator']['greater_than'] = {}
                                                context = greaterThan.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['greater_than']['context'] = context.text.strip()
                                                value = greaterThan.find("value")
                                                if value is not None:
                                                    objOrCondition['operator']['greater_than']['value'] = int(value.text.strip())

                                                if greaterThan.find("qualifier") is not None:
                                                    qualifiers = greaterThan.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['greater_than']['qualifier'] = objQualifiers
                                            lessThan = orCondition.find("operator/less-than")
                                            if lessThan is not None:
                                                objOrCondition['operator']['less_than'] = {}
                                                context = lessThan.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['less_than']['context'] = context.text.strip()
                                                value = lessThan.find("value")
                                                if value is not None:
                                                    objOrCondition['operator']['less_than']['value'] = int(value.text.strip())

                                                if lessThan.find("qualifier") is not None:
                                                    qualifiers = lessThan.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['less_than']['qualifier'] = objQualifiers

                                            equalTo = orCondition.find("operator/equal-to")
                                            if equalTo is not None:
                                                objOrCondition['operator']['equal_to'] = {}
                                                context = equalTo.find("context")
                                                if context is not None:
                                                    objOrCondition['operator']['equal_to']['context'] = context.text.strip()
                                                value = equalTo.find("value")
                                                if value is not None:
                                                    objOrCondition['operator']['equal_to']['value'] = int(value.text.strip())
                                                position = equalTo.find("position")
                                                if position is not None:
                                                    objOrCondition['operator']['equal_to']['position'] = position.text.strip()
                                                mask = equalTo.find("mask")
                                                if mask is not None:
                                                    objOrCondition['operator']['equal_to']['mask'] = mask.text.strip()

                                                if equalTo.find("qualifier") is not None:
                                                    qualifiers = equalTo.findall("qualifier/entry")
                                                    if qualifiers is not None:
                                                        objQualifiers = []
                                                        for qualifier in qualifiers:
                                                            objQualifier = {}
                                                            objQualifier['name'] = qualifier.attrib['name']
                                                            objQualifier['value'] = qualifier.find('value').text.strip()
                                                            objQualifiers.append(objQualifier)
                                                        objOrCondition['operator']['equal_to']['qualifier'] = objQualifiers

                                            objOrConditions.append(objOrCondition)
                                    objAndCondition["or_condition"] = objOrConditions
                                objAndConditions.append(objAndCondition)

                            objSignature['and_condition'] = objAndConditions

                    signatures.append(objSignature)

            obj['signature'] = signatures

        return obj

    def _toBool(self, value):
        if value.lower() == 'yes':
            return True
        elif value.lower() == 'no':
            return False
        else:
            raise ValueError(f"Cannot convert {value} to boolean")
