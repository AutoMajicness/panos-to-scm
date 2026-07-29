import unittest
from pathlib import Path

from migration import build_plan
from parse.parse_panos import XMLParser


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "panos"


class PanosRoutingFixtureTests(unittest.TestCase):
    def test_real_world_edge_stack_fixture_parses_network_dependencies(self):
        object_types = [
            "InterfaceManagementProfile",
            "DHCPInterface",
            "EthernetInterface",
            "Layer3Subinterface",
            "TunnelInterface",
            "LogicalRouter",
            "IKECryptoProfile",
            "IPsecCryptoProfile",
            "IKEGateway",
            "IPsecTunnel",
            "Zones",
        ]
        parsed = XMLParser(
            str(FIXTURE_DIR / "local_real_world_edge_stack.xml"),
            "local",
        ).parse_specific_types(object_types)

        self.assertEqual(
            [profile["name"] for profile in parsed["InterfaceManagementProfile"]],
            ["InternetManagement", "Ping_Only"],
        )
        self.assertEqual(
            parsed["EthernetInterface"],
            [
                {
                    "name": "$ethernet1-1",
                    "default_value": "ethernet1/1",
                    "comment": "Primary ISP",
                    "layer3": {
                        "interface_management_profile": "InternetManagement",
                        "ip": [{"name": "198.51.100.10/29"}],
                    },
                },
                {
                    "name": "$ethernet1-2",
                    "default_value": "ethernet1/2",
                    "comment": "Inside trunk",
                    "layer3": {},
                },
            ],
        )
        self.assertEqual(
            parsed["Layer3Subinterface"],
            [
                {
                    "name": "ethernet1/2.10",
                    "parent_interface": "ethernet1/2",
                    "tag": 10,
                    "comment": "Users",
                    "interface_management_profile": "Ping_Only",
                    "ip": [{"name": "10.10.10.1/24"}],
                },
                {
                    "name": "ethernet1/2.20",
                    "parent_interface": "ethernet1/2",
                    "tag": 20,
                    "comment": "Voice",
                    "interface_management_profile": "Ping_Only",
                    "ip": [{"name": "10.10.20.1/24"}],
                },
            ],
        )
        self.assertEqual(
            parsed["DHCPInterface"],
            [
                {
                    "name": "ethernet1/2.10",
                    "server": {
                        "mode": "auto",
                        "ip_pool": ["10.10.10.50-10.10.10.200"],
                        "option": {
                            "gateway": "10.10.10.1",
                            "subnet_mask": "255.255.255.0",
                            "primary_dns": "9.9.9.9",
                        },
                    },
                },
                {
                    "name": "ethernet1/2.20",
                    "relay": {
                        "enable": True,
                        "server": ["10.10.10.10", "10.10.10.11"],
                    },
                },
            ],
        )
        self.assertEqual(
            parsed["TunnelInterface"],
            [
                {
                    "name": "tunnel.1",
                    "default_value": "tunnel.1",
                    "comment": "Data center VPN",
                    "ip": [{"name": "169.254.10.2/30"}],
                }
            ],
        )
        self.assertEqual(parsed["IKECryptoProfile"][0]["name"], "ike-edge-a")
        self.assertEqual(parsed["IPsecCryptoProfile"][0]["name"], "ipsec-edge-a")
        self.assertEqual(parsed["IKEGateway"][0]["name"], "dc-vpn-gw")
        self.assertEqual(parsed["IPsecTunnel"][0]["auto_key"]["ike_gateway"], [{"name": "dc-vpn-gw"}])
        self.assertEqual(
            parsed["Zones"],
            [
                {"name": "Untrust", "network": {"layer3": ["ethernet1/1"]}},
                {"name": "Trust", "network": {"layer3": ["ethernet1/2.10", "tunnel.1"]}},
                {"name": "Voice", "network": {"layer3": ["ethernet1/2.20"]}},
            ],
        )

        vrf = parsed["LogicalRouter"][0]["vrf"][0]
        self.assertEqual(
            vrf["interface"],
            ["ethernet1/1", "ethernet1/2.10", "ethernet1/2.20", "tunnel.1"],
        )
        self.assertEqual(vrf["bgp"], {"enable": False})
        self.assertEqual(vrf["ospf"], {"enable": False})
        self.assertEqual(vrf["ospfv3"], {"enable": False})
        self.assertEqual(
            vrf["routing_table"]["ip"]["static_route"][0],
            {
                "name": "Primary-Default",
                "destination": "0.0.0.0/0",
                "interface": "ethernet1/1",
                "metric": 10,
                "nexthop": {"ip_address": "198.51.100.9"},
                "bfd": {"profile": "None"},
                "path_monitor": {
                    "enable": True,
                    "failure_condition": "all",
                    "hold_time": 1,
                    "monitor_destinations": [
                        {
                            "name": "SLA-9.9.9.9",
                            "enable": True,
                            "source": "198.51.100.10/29",
                            "destination": "9.9.9.9",
                            "interval": 3,
                            "count": 3,
                        }
                    ],
                },
                "route_table": {"unicast": {}},
            },
        )
        self.assertEqual(
            vrf["routing_table"]["ip"]["static_route"][1],
            {
                "name": "Data-Center",
                "destination": "10.20.0.0/16",
                "interface": "tunnel.1",
                "metric": 230,
                "admin_dist": 230,
                "nexthop": {"ip_address": "169.254.10.1"},
                "route_table": {"unicast": {}},
            },
        )

        plan = build_plan(parsed, object_types=object_types)
        self.assertEqual(plan.summary()["unsupported"], 0)
        self.assertEqual(plan.summary()["conflicts"], 0)
        self.assertEqual(plan.summary()["warnings"], 2)
        self.assertEqual(
            [warning.code for warning in plan.warnings],
            ["logical-router-static-route-option", "logical-router-static-route-option"],
        )

    def test_bgp_fixture_variants_parse_to_scm_network_objects(self):
        parsed = XMLParser(
            str(FIXTURE_DIR / "local_routing_bgp_variants.xml"),
            "local",
        ).parse_specific_types(
            [
                "BgpAuthProfile",
                "BgpAddressFamilyProfile",
                "BgpFilteringProfile",
                "RoutePrefixList",
                "BgpRouteMap",
                "LogicalRouter",
            ]
        )

        self.assertEqual(
            parsed["BgpAuthProfile"],
            [{"name": "edge-md5", "secret": "sanitized-secret"}],
        )
        self.assertEqual(
            parsed["BgpAddressFamilyProfile"],
            [
                {
                    "name": "edge-vr-transit-ipv4-af",
                    "ipv4": {
                        "unicast": {
                            "soft_reconfig_with_stored_info": True,
                            "next_hop": {"self_force": {}},
                            "remove_private_AS": {"all": {}},
                            "send_community": {"standard": {}},
                        }
                    },
                },
                {
                    "name": "edge-vr-transit-transit-v6-ipv6-af",
                    "ipv6": {
                        "unicast": {
                            "default_originate": True,
                            "maximum_prefix": {
                                "num_prefixes": 500,
                                "action": {"restart": {}},
                            },
                        }
                    },
                },
            ],
        )
        self.assertEqual(
            [item["name"] for item in parsed["BgpFilteringProfile"]],
            ["edge-vr-ipv4-bgp-filtering", "edge-vr-ipv6-bgp-filtering"],
        )
        self.assertEqual(
            [item["name"] for item in parsed["RoutePrefixList"]],
            ["edge-vr-import-import-corp-pl", "edge-vr-export-export-corp-v6-pl"],
        )

        router = parsed["LogicalRouter"][0]
        self.assertEqual(router["name"], "edge-vr")
        peer_group = router["vrf"][0]["bgp"]["peer_group"][0]
        self.assertEqual(peer_group["authentication_profile"], "edge-md5")
        self.assertEqual(
            peer_group["address_family"]["ipv4"]["unicast"]["address_family_profile"],
            "edge-vr-transit-ipv4-af",
        )
        peer = peer_group["peer"][0]
        self.assertEqual(
            peer["address_family"]["ipv6"]["unicast"]["address_family_profile"],
            "edge-vr-transit-transit-v6-ipv6-af",
        )
        self.assertEqual(
            peer["address_family"]["ipv6"]["unicast"]["filtering_profile"],
            "edge-vr-ipv6-bgp-filtering",
        )

    def test_ospf_static_fixture_variants_parse_to_logical_router(self):
        routers = XMLParser(
            str(FIXTURE_DIR / "local_routing_ospf_static_variants.xml"),
            "local",
        ).parse_specific_types(["LogicalRouter"])["LogicalRouter"]

        vrf = routers[0]["vrf"][0]
        self.assertEqual(vrf["interface"], ["ethernet1/4"])
        self.assertEqual(
            vrf["routing_table"]["ip"]["static_route"],
            [
                {
                    "name": "branch-summary",
                    "destination": "10.10.0.0/16",
                    "interface": "ethernet1/4",
                    "metric": 15,
                    "route_table": {"both": {}},
                    "nexthop": {"fqdn": "next-hop.example.com"},
                }
            ],
        )
        self.assertEqual(
            vrf["ospf"]["area"],
            [
                {
                    "name": "0.0.0.10",
                    "type": {
                        "nssa": {
                            "default_route_advertise": True,
                            "default_route_metric": 30,
                            "accept_summary": True,
                        }
                    },
                    "interface": [
                        {
                            "name": "ethernet1/4",
                            "enable": True,
                            "priority": 5,
                            "instance_id": 2,
                            "neighbor": [{"name": "10.10.10.2"}],
                            "vr_timing": {
                                "hello_interval": 5,
                                "dead_counts": 3,
                                "gr_delay": 10,
                            },
                        }
                    ],
                },
            ],
        )

    def test_unsupported_routing_fixture_emits_parser_warnings(self):
        parsed = XMLParser(
            str(FIXTURE_DIR / "local_routing_unsupported_nodes.xml"),
            "local",
        ).parse_specific_types(["LogicalRouter"])

        self.assertEqual(
            [
                {
                    "code": warning["code"],
                    "path": warning["path"],
                }
                for warning in parsed["_migration_warnings"]
            ],
            [
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].ecmp",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].protocol.bgp.dampening-profile.entry[default]",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].protocol.bgp.conditional-advertisement",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].protocol.bgp.routing-options.graceful-restart",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].protocol.bgp.redist-rules.entry[rip-to-bgp]",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].protocol.pim",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].protocol.multicast",
                },
                {
                    "code": "unsupported-panos-routing-node",
                    "path": "network.virtual-router.entry[unsupported-vr].routing-table.ip.static-route.entry[qualified-route].nexthop.qualified-next-hop",
                },
            ],
        )

        plan = build_plan(parsed, object_types=["LogicalRouter"])

        self.assertEqual(plan.summary()["warnings"], 9)
        warning_codes = [warning.code for warning in plan.warnings]
        self.assertEqual(warning_codes.count("unsupported-panos-routing-node"), 8)
        self.assertEqual(warning_codes.count("missing-network-reference"), 1)

    def test_template_routing_layout_emits_parser_warning_for_local_mode(self):
        parsed = XMLParser(
            str(FIXTURE_DIR / "panorama_template_routing_layout.xml"),
            "local",
        ).parse_specific_types(["LogicalRouter"])

        self.assertEqual(parsed["LogicalRouter"], [])
        self.assertEqual(
            parsed["_migration_warnings"],
            [
                {
                    "object_type": "LogicalRouter",
                    "name": "local",
                    "path": "network.virtual-router",
                    "code": "unsupported-panos-config-layout",
                    "severity": "warning",
                    "message": "PAN-OS virtual routers were found outside the local firewall network path; use a supported local running-config XML or add Panorama template parsing before migrating this file.",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
