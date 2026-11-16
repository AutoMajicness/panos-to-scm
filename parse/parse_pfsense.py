import logging
import re
import xml.etree.ElementTree as ET
from ipaddress import ip_network

from . import map_port


class PfSenseParser:
    """Parse pfSense config.xml backups into the shared SCM migration shape."""

    DEFAULT_VMWARE_INTERFACE_MAP = {
        "vmx0": "ethernet1/1",
        "vmx1": "ethernet1/2",
    }

    EMPTY_RULEBASES = {
        "security_post_rules": [],
        "app_override_pre_rules": [],
        "app_override_post_rules": [],
        "decryption_pre_rules": [],
        "decryption_post_rules": [],
        "nat_post_rules": [],
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.logger = logging.getLogger(__name__)
        self.tree = ET.parse(file_path)
        self.root = self.tree.getroot()
        if self.root.tag.lower() != "pfsense":
            raise ValueError("pfSense parser requires a config.xml backup with root element <pfsense>")
        self.data = {
            "Address": [],
            "AddressGroup": [],
            "Service": [],
            "ServiceGroup": [],
            "EthernetInterface": [],
            "Layer3Subinterface": [],
            "LogicalRouter": [],
            "RoutePrefixList": [],
            "RouteCommunityList": [],
            "BgpRouteMap": [],
            "BgpRouteMapRedistribution": [],
            "BgpRedistributionProfile": [],
            "BgpFilteringProfile": [],
            "Zones": [],
            "security_pre_rules": [],
            "nat_pre_rules": [],
            "Unsupported": [],
            "_migration_warnings": [],
        }
        self.address_names = set()
        self.service_names = set()
        self.interface_zones = {}
        self.interface_targets = {}
        self.interface_network_addresses = {}
        self.interface_address_addresses = {}
        self.aliases_by_name = {}
        self.alias_types = {}
        self.port_alias_values = {}
        self.used_rule_names = set()

    def parse(self):
        self._parse_interfaces()
        self._parse_routes()
        self._index_aliases()
        self._parse_aliases()
        self._parse_firewall_rules()
        self._parse_nat_rules()
        self._warn_unmapped_sections()

    def parse_all(self):
        self.parse()
        return self.get_parsed_data()

    def parse_specific_types(self, object_types):
        self.parse()
        parsed = self.get_parsed_data()
        selected = {object_type: parsed.get(object_type, []) for object_type in object_types}
        selected["_migration_warnings"] = parsed.get("_migration_warnings", [])
        for key, value in self.EMPTY_RULEBASES.items():
            if key in object_types:
                selected[key] = value
        return selected

    def get_parsed_data(self):
        parsed_data = self.data.copy()
        for key, value in self.EMPTY_RULEBASES.items():
            parsed_data.setdefault(key, value)
        return parsed_data

    def _parse_interfaces(self):
        interfaces = self.root.find("interfaces")
        if interfaces is None:
            return
        for iface in interfaces:
            if not (iface.tag in {"wan", "lan"} or iface.tag.startswith("opt")):
                continue
            name = self._zone_name(self._child_text(iface, "descr") or iface.tag)
            source_interface = self._child_text(iface, "if") or iface.tag
            target_interface = self._target_interface_name(source_interface)
            self.interface_zones[iface.tag] = name
            self.interface_targets[iface.tag] = target_interface
            self.data["Zones"].append({"name": name, "network": {"layer3": [target_interface]}})
            self._add_interface_payload(iface, source_interface, target_interface)
            ipaddr = self._child_text(iface, "ipaddr")
            subnet = self._child_text(iface, "subnet")
            network = self._normalize_network(f"{ipaddr}/{subnet}") if ipaddr and subnet else ""
            if network:
                address_name = self._sanitize_name(f"{iface.tag}-net")
                self.interface_network_addresses[iface.tag] = self._add_address(
                    address_name,
                    network,
                    description=f"pfSense {name} interface network",
                )
            if ipaddr and self._normalize_network(ipaddr):
                address_name = self._sanitize_name(f"{iface.tag}-ip")
                self.interface_address_addresses[f"{iface.tag}ip"] = self._add_address(
                    address_name,
                    ipaddr,
                    description=f"pfSense {name} interface address",
                )

    def _index_aliases(self):
        aliases = self.root.find("aliases")
        if aliases is None:
            return
        for alias in aliases.findall("alias"):
            name = self._child_text(alias, "name")
            if not name:
                continue
            self.aliases_by_name[name] = alias
            self.alias_types[name] = self._child_text(alias, "type", "host").lower()
            self.port_alias_values[name] = self._alias_values(alias)

    def _parse_routes(self):
        routes = []
        gateways = self.root.find("gateways")
        if gateways is not None:
            default_gateway_names = {
                self._child_text(gateways, "defaultgw4"),
                self._child_text(gateways, "defaultgw6"),
            }
            for gateway in gateways.findall("gateway_item"):
                gateway_name = self._child_text(gateway, "name")
                if gateway_name not in default_gateway_names:
                    self._unsupported(
                        "unsupported-pfsense-gateway",
                        f"pfSense gateway '{gateway_name}' is not selected as a default route and has no destination network.",
                        object_type="LogicalRouter",
                        name=gateway_name,
                    )
                    continue
                interface = self.interface_targets.get(self._child_text(gateway, "interface"))
                next_hop = self._child_text(gateway, "gateway")
                if not interface or not next_hop:
                    self._unsupported(
                        "unsupported-pfsense-gateway",
                        f"pfSense default gateway '{gateway_name}' is missing a mapped interface or next-hop address.",
                        object_type="LogicalRouter",
                        name=gateway_name,
                    )
                    continue
                routes.append({
                    "name": self._sanitize_name(f"default-{gateway_name}"),
                    "destination": "0.0.0.0/0",
                    "interface": interface,
                    "nexthop": {"ip_address": next_hop},
                })

        static_routes = self.root.find("staticroutes")
        if static_routes is not None:
            for index, route in enumerate(static_routes.findall("route"), start=1):
                destination = self._child_text(route, "network")
                next_hop = self._child_text(route, "gateway")
                interface = self.interface_targets.get(self._child_text(route, "interface"))
                if not destination or not next_hop:
                    self._unsupported(
                        "unsupported-pfsense-static-route",
                        "pfSense static route is missing a destination or gateway address.",
                        object_type="LogicalRouter",
                        name=self._child_text(route, "descr") or f"static-route-{index}",
                    )
                    continue
                route_payload = {
                    "name": self._sanitize_name(self._child_text(route, "descr") or f"static-route-{index}"),
                    "destination": destination,
                    "nexthop": {"ip_address": next_hop},
                }
                if interface:
                    route_payload["interface"] = interface
                routes.append(route_payload)

        bgp = self._parse_frr_bgp()
        if routes or bgp:
            vrf = {
                "name": "default",
                "interface": list(dict.fromkeys(self.interface_targets.values())),
            }
            if routes:
                vrf["routing_table"] = {"ip": {"static_route": routes}}
            if bgp:
                vrf["bgp"] = bgp
            self.data["LogicalRouter"].append({
                "name": "pfsense-default",
                "routing_stack": "advanced",
                "vrf": [vrf],
            })

    def _parse_frr_bgp(self):
        """Convert the FRR package section used by pfSense into SCM BGP objects."""
        frrbgp = self.root.find(".//frrbgp")
        if frrbgp is None:
            return None
        config = frrbgp.find("config")
        if config is None:
            return None

        enabled = self._child_text(config, "enable").lower() in {"on", "yes", "true", "1"}
        payload = {"enable": enabled}
        local_as = self._child_text(config, "asnum")
        router_id = self._child_text(config, "routerid")
        if local_as:
            payload["local_as"] = local_as
        if router_id:
            payload["router_id"] = router_id

        keepalive = self._integer_text(config, "timers_keepalive")
        holdtime = self._integer_text(config, "timers_holdtime")
        if keepalive is not None or holdtime is not None:
            payload["timers"] = {}
            if keepalive is not None:
                payload["timers"]["keep_alive_interval"] = keepalive
            if holdtime is not None:
                payload["timers"]["hold_time"] = holdtime

        self._parse_frr_prefix_lists()
        self._parse_frr_communities()
        self._parse_frr_route_maps()

        redistribution = self._child_text(config, "redistributeconnected")
        if redistribution and redistribution.lower() not in {"no", "none"}:
            profile_name = self._sanitize_name("pfsense-bgp-redist")
            payload["redistribution_profile"] = profile_name
            self.data["BgpRedistributionProfile"].append({
                "name": profile_name,
                "ipv4": {"unicast": {"connected": {
                    "enable": True,
                    "route_map": self._sanitize_name(redistribution),
                }}},
            })
        elif self._child_text(config, "redistributestatic").lower() not in {"", "no", "none"}:
            profile_name = self._sanitize_name("pfsense-bgp-redist")
            payload["redistribution_profile"] = profile_name
            self.data["BgpRedistributionProfile"].append({
                "name": profile_name,
                "ipv4": {"unicast": {"static": {"enable": True}}},
            })

        peer_group = {"name": "pfsense-bgp-peers", "type": "ebgp" if local_as else "ibgp"}
        peers = []
        for peer_config in self.root.findall(".//frrbgpneighbors/config"):
            peer = self._parse_frr_neighbor(peer_config, local_as)
            if peer:
                peers.append(peer)
        if peers:
            peer_group["peer"] = peers
            payload["peer_group"] = [peer_group]
        return payload or None

    def _parse_frr_neighbor(self, config, local_as):
        address = self._child_text(config, "neighbor") or self._child_text(config, "peer")
        if not address:
            return None
        peer_as = self._child_text(config, "asnum")
        group_name = self._sanitize_name(self._child_text(config, "peergroup"))
        peer = {
            "name": self._sanitize_name(self._child_text(config, "descr") or address),
            "peer_address": address,
        }
        if peer_as:
            peer["peer_as"] = peer_as
        enabled = self._child_text(config, "shutdown").lower()
        if enabled:
            peer["enable"] = enabled not in {"on", "yes", "true", "1"}
        update_source = self._child_text(config, "updatesource")
        if update_source:
            peer["local_address"] = {"interface": self.interface_targets.get(update_source, self._target_interface_name(update_source))}
        keepalive = self._integer_text(config, "timers_keepalive")
        holdtime = self._integer_text(config, "timers_holdtime")
        if keepalive is not None or holdtime is not None:
            peer["timers"] = {}
            if keepalive is not None:
                peer["timers"]["keep_alive_interval"] = keepalive
            if holdtime is not None:
                peer["timers"]["hold_time"] = holdtime
        af = {}
        route_in = self._child_text(config, "routemap_in")
        route_out = self._child_text(config, "routemap_out")
        if route_in or route_out:
            profile_name = self._sanitize_name(f"pfsense-bgp-filter-{peer['name']}")
            unicast = {"route_maps": {}}
            if route_in:
                unicast["route_maps"]["inbound"] = self._sanitize_name(route_in)
            if route_out:
                unicast["route_maps"]["outbound"] = self._sanitize_name(route_out)
            self.data["BgpFilteringProfile"].append({"name": profile_name, "ipv4": {"unicast": unicast}})
            af["ipv4"] = {"unicast": {"filtering_profile": profile_name}}
        if af:
            peer["address_family"] = af
        if group_name not in {"", "none"}:
            peer["description"] = f"pfSense peer group: {group_name}"
        return peer

    def _parse_frr_prefix_lists(self):
        for config in self.root.findall(".//frrglobalprefixes/config"):
            name = self._sanitize_name(self._child_text(config, "name"))
            if not name:
                continue
            entries = []
            for row in config.findall("./row"):
                prefix = self._child_text(row, "source")
                if not prefix:
                    continue
                item = {"name": self._integer_text(row, "seq") or len(entries) + 1,
                        "action": self._child_text(row, "action", "permit"), "prefix": prefix}
                entries.append(item)
            if entries:
                self.data["RoutePrefixList"].append({"name": name, "ipv4": {"prefix_list": entries}})

    def _parse_frr_communities(self):
        for config in self.root.findall(".//frrbgpcommunities/config"):
            name = self._sanitize_name(self._child_text(config, "name"))
            rows = []
            for row in config.findall("./row"):
                community = self._child_text(row, "community")
                if community:
                    rows.append({"name": self._integer_text(row, "seq") or len(rows) + 1,
                                 "action": self._child_text(row, "action", "permit"),
                                 "community": community})
            if name and rows:
                self.data["RouteCommunityList"].append({"name": name, "community_list": rows})

    def _parse_frr_route_maps(self):
        grouped = {}
        for config in self.root.findall(".//frrglobalroutemaps/config"):
            name = self._sanitize_name(self._child_text(config, "name"))
            if not name:
                continue
            rows = grouped.setdefault(name, {"description": self._child_text(config, "descr"), "route_map": []})["route_map"]
            source_rows = config.findall("./row") or [config]
            for row in source_rows:
                seq = self._integer_text(row, "seq") or len(rows) + 1
                item = {"name": seq, "action": self._child_text(row, "action", "permit")}
                match = {}
                prefix = self._child_text(row, "prefix_match")
                community = self._child_text(row, "community_match")
                source_proto = self._child_text(row, "source_proto")
                if prefix.lower() not in {"", "none"}:
                    match["ipv4"] = {"address": {"prefix_list": self._sanitize_name(prefix)}}
                if community.lower() not in {"", "none"}:
                    match["regular_community"] = self._sanitize_name(community)
                if source_proto.lower() not in {"", "none"}:
                    match["source_protocol"] = source_proto
                if match:
                    item["match"] = match
                community_set = self._child_text(row, "community_set")
                if community_set and community_set.lower() not in {"none"}:
                    item["set"] = {"regular_community": [community_set]}
                rows.append(item)
        for name, value in grouped.items():
            if value["route_map"]:
                key = "BgpRouteMapRedistribution" if name.startswith("MAP.REDIST") else "BgpRouteMap"
                entry = {"name": name, "route_map": value["route_map"]}
                if value["description"]:
                    entry["description"] = value["description"]
                self.data[key].append(entry)

    def _integer_text(self, parent, tag):
        value = self._child_text(parent, tag)
        try:
            return int(value) if value else None
        except ValueError:
            return None

    def _target_interface_name(self, source_interface):
        if source_interface in self.DEFAULT_VMWARE_INTERFACE_MAP:
            return self.DEFAULT_VMWARE_INTERFACE_MAP[source_interface]
        parent, separator, suffix = source_interface.partition(".")
        if separator and parent in self.DEFAULT_VMWARE_INTERFACE_MAP:
            return f"{self.DEFAULT_VMWARE_INTERFACE_MAP[parent]}.{suffix}"
        return source_interface

    def _add_interface_payload(self, iface, source_interface, target_interface):
        if target_interface == source_interface and not re.fullmatch(r"(?:ethernet|ae)\d+/\d+(?:\.\d+)?", target_interface):
            self._unsupported(
                "unmapped-pfsense-interface",
                f"pfSense interface '{source_interface}' has no PAN-OS target mapping; retaining the source name for review.",
                object_type="Zones",
                name=source_interface,
            )

        ipaddr = self._child_text(iface, "ipaddr")
        subnet = self._child_text(iface, "subnet")
        ip_value = ""
        if self._normalize_network(ipaddr) and subnet and subnet.isdigit():
            ip_value = f"{ipaddr}/{subnet}"

        if "." in target_interface:
            parent_interface, _, suffix = target_interface.partition(".")
            payload = {
                "name": self._scm_interface_object_name(target_interface),
                "default_value": target_interface,
                "parent_interface": parent_interface,
                "tag": int(suffix) if suffix.isdigit() else suffix,
            }
            if ip_value:
                payload["ip"] = [{"name": ip_value}]
            self.data["Layer3Subinterface"].append(payload)
            return

        payload = {
            "name": self._scm_interface_object_name(target_interface),
            "default_value": target_interface,
            "layer3": {},
        }
        if ip_value:
            payload["layer3"]["ip"] = [{"name": ip_value}]
        elif ipaddr.lower() == "dhcp":
            payload["layer3"]["dhcp_client"] = {"enable": True}
        mtu = self._child_text(iface, "mtu")
        if mtu.isdigit():
            payload["layer3"]["mtu"] = int(mtu)
        self.data["EthernetInterface"].append(payload)

    def _parse_aliases(self):
        aliases = self.root.find("aliases")
        if aliases is None:
            return
        for alias in aliases.findall("alias"):
            name = self._sanitize_name(self._child_text(alias, "name"))
            alias_type = self._child_text(alias, "type", "host").lower()
            description = self._child_text(alias, "descr")
            values = self._alias_values(alias)
            if not name:
                continue
            if alias_type in {"host", "network"}:
                self._add_address_alias(name, alias_type, values, description)
            elif alias_type == "port":
                self._add_port_alias(name, values, description)
            else:
                self._unsupported(
                    "unsupported-pfsense-alias-type",
                    f"pfSense alias '{name}' uses unsupported type '{alias_type}'",
                    object_type="Alias",
                    name=name,
                )

    def _add_address_alias(self, name, alias_type, values, description):
        if len(values) == 1 and self._is_literal_address(values[0]):
            self._add_address(name, values[0], description=description)
            return
        members = [
            self._alias_or_address_member(value, name, index)
            for index, value in enumerate(values, start=1)
        ]
        members = [member for member in members if member]
        if members:
            self.data["AddressGroup"].append({
                "name": name,
                "description": description or f"pfSense {alias_type} alias",
                "static": members,
            })

    def _add_port_alias(self, name, values, description):
        if len(values) == 1 and self._is_literal_port(values[0]):
            self._add_service(name, values[0], description=description)
            return
        members = []
        for index, value in enumerate(values, start=1):
            member_name = self._sanitize_name(f"{name}-{index}")
            if value in self.aliases_by_name:
                members.append(self._sanitize_name(value))
            else:
                members.append(self._add_service(member_name, value))
        if members:
            self.data["ServiceGroup"].append({
                "name": name,
                "description": description or "pfSense port alias",
                "static": members,
            })

    def _parse_firewall_rules(self):
        filter_elem = self.root.find("filter")
        if filter_elem is None:
            return
        for index, rule in enumerate(filter_elem.findall("rule"), start=1):
            rule_name = self._unique_rule_name(rule, index, "pf-rule")
            interface = self._child_text(rule, "interface")
            from_zones = self._zones_for_interface(interface, rule_name)
            self.data["security_pre_rules"].append({
                "name": rule_name,
                "description": self._child_text(rule, "descr") or None,
                "from": from_zones,
                "to": ["any"],
                "source": [self._address_ref(rule.find("source"))],
                "source_user": ["any"],
                "source_hip": ["any"],
                "destination": [self._address_ref(rule.find("destination"))],
                "negate_destination": rule.find("destination/not") is not None,
                "destination_hip": ["any"],
                "application": ["ping"] if self._child_text(rule, "protocol").lower() == "icmp" else ["any"],
                "service": [self._service_ref(rule)],
                "category": ["any"],
                "action": self._rule_action(rule),
                "disabled": rule.find("disabled") is not None,
                "log_setting": "Cortex Data Lake" if rule.find("log") is not None else None,
            })

    def _parse_nat_rules(self):
        nat = self.root.find("nat")
        if nat is None:
            return
        for index, rule in enumerate(nat.findall("rule"), start=1):
            rule_name = self._unique_rule_name(rule, index, "pf-port-forward")
            self.data["nat_pre_rules"].append(self._destination_nat_rule(rule, index, rule_name))
        outbound = nat.find("outbound")
        if outbound is not None:
            for index, rule in enumerate(outbound.findall("rule"), start=1):
                target = self._child_text(rule, "target") or self._child_text(rule, "address")
                if not target:
                    self._unsupported(
                        "unsupported-pfsense-nat-rule",
                        "pfSense outbound NAT rule has no target translation address",
                        object_type="NAT",
                        name=self._rule_name(rule, index, "pf-outbound-nat"),
                    )
                    continue
                rule_name = self._unique_rule_name(rule, index, "pf-outbound-nat")
                self.data["nat_pre_rules"].append(self._source_nat_rule(rule, index, target, rule_name))
        for index, rule in enumerate(nat.findall("onetoone"), start=1):
            self._unsupported(
                "unsupported-pfsense-nat-rule",
                "pfSense 1:1 NAT is not mapped in the initial SCM parser",
                object_type="NAT",
                name=self._rule_name(rule, index, "pf-one-to-one-nat"),
            )

    def _destination_nat_rule(self, rule, index, rule_name=None):
        translated_address = self._child_text(rule, "target")
        translated_port = self._child_text(rule, "local-port")
        translation = {"translated_address": translated_address}
        if translated_port:
            translation["translated_port"] = map_port(translated_port)
        interface = self._child_text(rule, "interface")
        return {
            "name": rule_name or self._rule_name(rule, index, "pf-port-forward"),
            "description": self._child_text(rule, "descr") or None,
            "from": self._zones_for_interface(interface, rule_name or self._rule_name(rule, index, "pf-port-forward")),
            "to": ["any"],
            "source": [self._address_ref(rule.find("source"))],
            "destination": [self._address_ref(rule.find("destination"))],
            "service": self._service_ref(rule),
            "disabled": rule.find("disabled") is not None,
            "destination_translation": translation,
        }

    def _source_nat_rule(self, rule, index, target, rule_name=None):
        interface = self._child_text(rule, "interface")
        return {
            "name": rule_name or self._rule_name(rule, index, "pf-outbound-nat"),
            "description": self._child_text(rule, "descr") or None,
            "from": self._zones_for_interface(interface, rule_name or self._rule_name(rule, index, "pf-outbound-nat")),
            "to": ["any"],
            "source": [self._address_ref(rule.find("source"))],
            "destination": [self._address_ref(rule.find("destination"))],
            "service": self._service_ref(rule),
            "disabled": rule.find("disabled") is not None,
            "source_translation": {
                "dynamic_ip_and_port": {
                    "translated_address": [target],
                },
            },
        }

    def _address_ref(self, element):
        if element is None or element.find("any") is not None:
            return "any"
        value = self._child_text(element, "address") or self._child_text(element, "network")
        if value in self.interface_address_addresses:
            return self.interface_address_addresses[value]
        if value in self.interface_network_addresses:
            return self.interface_network_addresses[value]
        if value in self.aliases_by_name:
            return self._sanitize_name(value)
        return self._sanitize_name(value) if self._looks_like_alias(value) else value or "any"

    def _service_ref(self, rule):
        protocol = self._child_text(rule, "protocol", "any").lower()
        destination = rule.find("destination")
        port = self._child_text(destination, "port") if destination is not None else ""
        if protocol in {"any", ""} or not port:
            return "any"
        values = self.port_alias_values.get(port, [port])
        protocols = ["tcp", "udp"] if protocol == "tcp/udp" else [protocol]
        members = []
        for value in values:
            for member_protocol in protocols:
                normalized_port = self._normalize_port(value)
                service_name = self._sanitize_name(f"{member_protocol.upper()}-{normalized_port}")
                self._add_service(service_name, normalized_port, protocol=member_protocol)
                members.append(service_name)
        if port in self.port_alias_values:
            group_name = self._sanitize_name(f"{port}-{protocol.replace('/', '-')}")
            if not any(group.get("name") == group_name for group in self.data["ServiceGroup"]):
                self.data["ServiceGroup"].append({"name": group_name, "static": members})
            return group_name
        if len(members) > 1:
            group_name = self._sanitize_name(f"{protocol.replace('/', '-')}-{self._normalize_port(port)}")
            if not any(group.get("name") == group_name for group in self.data["ServiceGroup"]):
                self.data["ServiceGroup"].append({"name": group_name, "static": members})
            return group_name
        return members[0]

    def _rule_action(self, rule):
        action = self._child_text(rule, "type", "pass").lower()
        if action == "pass":
            return "allow"
        if action in {"block", "reject"}:
            return "deny"
        self._unsupported(
            "unsupported-pfsense-rule-action",
            f"pfSense rule action '{action}' is not directly mapped",
            object_type="SecurityRule",
            name=self._child_text(rule, "descr") or self._child_text(rule, "tracker"),
        )
        return action

    def _zones_for_interface(self, interface, rule_name):
        if not interface:
            self._unsupported(
                "unresolved-pfsense-zone",
                f"pfSense rule '{rule_name}' has no interface; using any source zone",
                object_type="Zones",
                name=rule_name,
            )
            return ["any"]
        zones = []
        for value in re.split(r"[, ]+", interface.strip()):
            if not value:
                continue
            zone = self.interface_zones.get(value)
            if zone:
                zones.append(zone)
            else:
                self._unsupported(
                    "unresolved-pfsense-zone",
                    f"pfSense interface '{value}' has no inferred SCM zone; using any source zone",
                    object_type="Zones",
                    name=rule_name,
                )
        return zones or ["any"]

    def _add_address(self, name, value, description=""):
        name = self._sanitize_name(name)
        if name in self.address_names:
            return name
        entry = {"name": name}
        normalized = self._normalize_network(value)
        if normalized:
            entry["ip_netmask"] = normalized
        elif value:
            entry["fqdn"] = value
        if description:
            entry["description"] = description
        self.data["Address"].append(entry)
        self.address_names.add(name)
        return name

    def _add_service(self, name, port, protocol="tcp", description=""):
        name = self._sanitize_name(name)
        if name in self.service_names:
            return name
        protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
        entry = {
            "name": name,
            "protocol": {
                protocol: {
                    "port": self._normalize_port(port),
                },
            },
        }
        if description:
            entry["description"] = description
        self.data["Service"].append(entry)
        self.service_names.add(name)
        return name

    def _alias_values(self, alias):
        address = self._child_text(alias, "address")
        if not address:
            return []
        return [value for value in re.split(r"[\s,]+", address.strip()) if value]

    def _alias_or_address_member(self, value, alias_name, index):
        if value in self.aliases_by_name:
            return self._sanitize_name(value)
        if self._is_literal_address(value):
            member_name = self._sanitize_name(f"{alias_name}-{index}")
            return self._add_address(member_name, value)
        return self._add_address(self._sanitize_name(value), value)

    def _is_literal_address(self, value):
        return bool(self._normalize_network(value))

    def _is_literal_port(self, value):
        return bool(re.fullmatch(r"\d+(?::\d+|-\d+)?", str(value or "").strip()))

    def _normalize_port(self, value):
        return map_port(str(value or "").replace(":", "-"))

    def _warn_unmapped_sections(self):
        sections = {
            "dhcpd": "DHCP server configuration is not migrated yet.",
            "virtualip": "Virtual IP/CARP configuration is not migrated yet.",
            "ipsec": "IPsec configuration is not migrated yet.",
        }
        for section, message in sections.items():
            node = self.root.find(section)
            if node is not None and len(node):
                self._unsupported(
                    f"unsupported-pfsense-{section}",
                    f"pfSense {section} section was detected but is not migrated: {message}",
                    object_type=section,
                )
        outbound = self.root.find("nat/outbound")
        if outbound is not None and self._child_text(outbound, "mode") not in {"", "disabled", "hybrid", "advanced", "manual"}:
            self._unsupported(
                "unsupported-pfsense-nat-mode",
                f"pfSense outbound NAT mode '{self._child_text(outbound, 'mode')}' is not expanded into rules.",
                object_type="NAT",
            )

    def _rule_name(self, rule, index, prefix):
        return self._sanitize_name(
            self._child_text(rule, "descr")
            or self._child_text(rule, "tracker")
            or f"{prefix}-{index}"
        )

    def _unique_rule_name(self, rule, index, prefix):
        base_name = self._rule_name(rule, index, prefix)
        if base_name not in self.used_rule_names:
            self.used_rule_names.add(base_name)
            return base_name

        suffix = self._sanitize_name(
            self._child_text(rule, "tracker") or self._child_text(rule, "id") or str(index)
        )
        candidate = self._sanitize_name(f"{base_name}-{suffix}")
        counter = 2
        while candidate in self.used_rule_names:
            candidate = self._sanitize_name(f"{base_name}-{suffix}-{counter}")
            counter += 1
        self.used_rule_names.add(candidate)
        return candidate

    def _unsupported(self, code, message, object_type="", name=""):
        entry = {
            "code": code,
            "message": message,
            "object_type": object_type,
            "name": name,
        }
        self.data["Unsupported"].append(entry)
        self.data["_migration_warnings"].append(entry)
        self.logger.warning(message)

    def _child_text(self, parent, tag, default=""):
        if parent is None:
            return default
        child = parent.find(tag)
        if child is None or child.text is None:
            return default
        return child.text.strip()

    def _sanitize_name(self, value):
        value = str(value or "").strip()
        value = re.sub(r"[^A-Za-z0-9._-]+", "-", value)
        value = value.strip("-._")
        return (value or "unnamed")[:63]

    def _scm_interface_object_name(self, interface_name):
        return f"${self._sanitize_name(interface_name)}"

    def _zone_name(self, value):
        return self._sanitize_name(value).lower()

    def _normalize_network(self, value):
        value = str(value or "").strip()
        if not value:
            return ""
        try:
            if "/" in value:
                return str(ip_network(value, strict=False))
            ip_network(f"{value}/32", strict=False)
            return value
        except ValueError:
            return ""

    def _looks_like_alias(self, value):
        return bool(value) and not self._normalize_network(value) and value.lower() != "any"
