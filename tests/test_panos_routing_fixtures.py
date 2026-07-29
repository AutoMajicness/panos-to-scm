import unittest
from pathlib import Path

from migration import build_plan
from parse.parse_panos import XMLParser


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "panos"


class PanosRoutingFixtureTests(unittest.TestCase):
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
