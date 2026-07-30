import unittest

from migration import build_network_report, build_plan


class BuildPlanTests(unittest.TestCase):
    def test_build_plan_creates_missing_objects(self):
        parsed_data = {
            "Address": [
                {"name": "web-1", "ip_netmask": "192.0.2.10"},
                {"name": "web-2", "fqdn": "example.com"},
            ]
        }

        plan = build_plan(parsed_data, current_data={"Address": []})

        self.assertEqual(
            plan.summary(),
            {
                "creates": 2,
                "updates": 0,
                "skips": 0,
                "conflicts": 0,
                "unsupported": 0,
                "warnings": 0,
            },
        )
        self.assertEqual([change.name for change in plan.creates], ["web-1", "web-2"])

    def test_build_plan_skips_normalized_matches(self):
        parsed_data = {"Address": [{"name": "web-1", "tag": [], "ip_netmask": "192.0.2.10"}]}
        current_data = {
            "Address": [
                {
                    "id": "123",
                    "name": "web-1",
                    "folder": "All",
                    "ip_netmask": "192.0.2.10",
                }
            ]
        }

        plan = build_plan(parsed_data, current_data=current_data)

        self.assertEqual(plan.summary()["skips"], 1)
        self.assertEqual(plan.skips[0].name, "web-1")

    def test_build_plan_reports_conflicts_by_default(self):
        parsed_data = {"Address": [{"name": "web-1", "ip_netmask": "192.0.2.10"}]}
        current_data = {"Address": [{"name": "web-1", "ip_netmask": "192.0.2.11"}]}

        plan = build_plan(parsed_data, current_data=current_data)

        self.assertEqual(plan.summary()["conflicts"], 1)
        self.assertEqual(plan.conflicts[0].reason, "desired object differs from current object")

    def test_build_plan_can_mark_differences_as_updates(self):
        parsed_data = {"Address": [{"name": "web-1", "ip_netmask": "192.0.2.10"}]}
        current_data = {"Address": [{"name": "web-1", "ip_netmask": "192.0.2.11"}]}

        plan = build_plan(parsed_data, current_data=current_data, conflict_policy="replace")

        self.assertEqual(plan.summary()["updates"], 1)
        self.assertEqual(plan.updates[0].name, "web-1")

    def test_build_plan_flags_bad_entries_as_unsupported(self):
        parsed_data = {"Address": [{"fqdn": "missing-name.example"}, "not-an-object"]}

        plan = build_plan(parsed_data)

        self.assertEqual(plan.summary()["unsupported"], 2)

    def test_plan_to_dict_contains_stable_sorted_sections(self):
        parsed_data = {
            "Address": [
                {"name": "z-last", "ip_netmask": "192.0.2.10"},
                {"name": "a-first", "fqdn": "example.com"},
            ]
        }

        plan = build_plan(parsed_data)
        report = plan.to_dict()

        self.assertEqual(
            list(report.keys()),
            [
                "summary",
                "warning_summary",
                "remediation",
                "posting_preview",
                "creates",
                "updates",
                "skips",
                "conflicts",
                "unsupported",
                "warnings",
            ],
        )
        self.assertEqual([item["name"] for item in report["creates"]], ["a-first", "z-last"])
        self.assertEqual(report["creates"][0]["action"], "create")

    def test_plan_to_dict_groups_warnings_by_code_and_object_type(self):
        parsed_data = {
            "BgpFilteringProfile": [
                {
                    "name": "default-ipv4-bgp-filtering",
                    "ipv4": {"unicast": {"route_maps": {"inbound": "missing-rm"}}},
                }
            ],
            "LogicalRouter": [
                {
                    "name": "default",
                    "vrf": [
                        {
                            "name": "default",
                            "routing_table": {
                                "ip": {
                                    "static_route": [
                                        {
                                            "name": "static-a",
                                            "route_table": {"no_install": {}},
                                        }
                                    ]
                                }
                            },
                        }
                    ],
                }
            ],
        }

        report = build_plan(parsed_data).to_dict()

        self.assertEqual(
            report["warning_summary"],
            {
                "generated-bgp-filtering-profile": {
                    "count": 1,
                    "object_types": {"BgpFilteringProfile": 1},
                },
                "logical-router-static-route-option": {
                    "count": 1,
                    "object_types": {"LogicalRouter": 1},
                },
                "missing-network-reference": {
                    "count": 1,
                    "object_types": {"BgpFilteringProfile": 1},
                },
            },
        )

    def test_plan_to_dict_contains_dependency_ordered_posting_preview(self):
        parsed_data = {
            "LogicalRouter": [{"name": "default", "routing_stack": "advanced", "vrf": [{"name": "default"}]}],
            "IPsecTunnel": [{"name": "vpn-tunnel-a", "tunnel_interface": "tunnel.1"}],
            "IKEGateway": [{"name": "vpn-gw-a"}],
            "TunnelInterface": [{"name": "tunnel.1", "default_value": "tunnel.1"}],
            "EthernetInterface": [{"name": "$ethernet1-1", "default_value": "ethernet1/1"}],
            "Address": [{"name": "addr-a", "ip_netmask": "192.0.2.10"}],
        }

        plan = build_plan(
            parsed_data,
            object_types=[
                "LogicalRouter",
                "IPsecTunnel",
                "IKEGateway",
                "TunnelInterface",
                "EthernetInterface",
                "Address",
            ],
        )
        preview = plan.to_dict()["posting_preview"]

        self.assertEqual(
            [batch["object_type"] for batch in preview["creates"]],
            ["EthernetInterface", "TunnelInterface", "IKEGateway", "IPsecTunnel", "LogicalRouter", "Address"],
        )
        self.assertEqual(preview["updates"], [])

    def test_build_plan_reports_schema_sensitive_network_warnings(self):
        parsed_data = {
            "BgpFilteringProfile": [
                {
                    "name": "default-ipv4-bgp-filtering",
                    "ipv4": {"unicast": {"route_maps": {"inbound": "import-rm"}}},
                }
            ],
            "BgpAddressFamilyProfile": [
                {
                    "name": "default-upstream-ipv4-af",
                    "ipv4": {"unicast": {"send_community": {"both": {}}}},
                }
            ],
            "BgpRouteMap": [
                {
                    "name": "import-rm",
                    "route_map": [{"name": "rule-a", "action": {"permit": {}}}],
                }
            ],
            "LogicalRouter": [
                {
                    "name": "default",
                    "vrf": [
                        {
                            "name": "default",
                            "routing_table": {
                                "ip": {
                                    "static_route": [
                                        {
                                            "name": "static-a",
                                            "destination": "192.0.2.0/24",
                                            "route_table": {"no_install": {}},
                                            "option": {"passive": {}},
                                        }
                                    ]
                                }
                            },
                            "bgp": {
                                "peer_group": [
                                    {
                                        "name": "upstream",
                                        "peer": [
                                            {
                                                "name": "peer-a",
                                                "address_family": {
                                                    "ipv4": {
                                                        "unicast": {
                                                            "filtering_profile": "default-ipv4-bgp-filtering",
                                                            "import_route_map": "import-rm",
                                                        }
                                                    }
                                                },
                                            }
                                        ],
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }

        plan = build_plan(parsed_data)

        self.assertEqual(plan.summary()["warnings"], 6)
        self.assertEqual(
            {
                warning.code
                for warning in plan.warnings
            },
            {
                "generated-bgp-filtering-profile",
                "bgp-address-family-profile",
                "logical-router-bgp-reference",
                "logical-router-static-route-option",
            },
        )
        self.assertTrue(all(warning.severity == "warning" for warning in plan.warnings))

    def test_build_plan_warns_for_missing_network_references(self):
        parsed_data = {
            "BgpFilteringProfile": [
                {
                    "name": "default-ipv4-bgp-filtering",
                    "ipv4": {
                        "unicast": {
                            "route_maps": {"inbound": "import-rm"},
                            "network_filter": {"prefix_list": "pl-missing"},
                        }
                    },
                }
            ],
            "BgpRouteMap": [
                {
                    "name": "import-rm",
                    "route_map": [
                        {
                            "name": "rule-a",
                            "match": {
                                "prefix_list": "pl-missing",
                                "regular_community": "community-missing",
                                "as_path_access_list": "aspath-missing",
                            },
                        }
                    ],
                }
            ],
            "LogicalRouter": [
                {
                    "name": "default",
                    "vrf": [
                        {
                            "name": "default",
                            "bgp": {
                                "redistribution_profile": "redist-missing",
                                "peer_group": [
                                    {
                                        "name": "upstream",
                                        "peer": [
                                            {
                                                "name": "peer-a",
                                                "authentication_profile": "bgp-auth-missing",
                                                "address_family": {
                                                    "ipv4": {
                                                        "unicast": {
                                                            "address_family_profile": "af-missing",
                                                            "filtering_profile": "filter-missing",
                                                            "import_route_map": "import-rm",
                                                        }
                                                    }
                                                },
                                            }
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                }
            ],
        }

        plan = build_plan(parsed_data)
        missing = [warning for warning in plan.warnings if warning.code == "missing-network-reference"]

        self.assertEqual(len(missing), 8)
        self.assertEqual(
            {
                warning.message.split("'")[1]
                for warning in missing
            },
            {
                "pl-missing",
                "community-missing",
                "aspath-missing",
                "redist-missing",
                "bgp-auth-missing",
                "af-missing",
                "filter-missing",
            },
        )

    def test_build_plan_uses_current_data_for_network_reference_validation(self):
        parsed_data = {
            "BgpFilteringProfile": [
                {
                    "name": "default-ipv4-bgp-filtering",
                    "ipv4": {"unicast": {"route_maps": {"inbound": "tenant-rm"}}},
                }
            ],
            "LogicalRouter": [
                {
                    "name": "default",
                    "vrf": [
                        {
                            "name": "default",
                            "bgp": {
                                "peer_group": [
                                    {
                                        "name": "upstream",
                                        "peer": [
                                            {
                                                "name": "peer-a",
                                                "address_family": {
                                                    "ipv4": {
                                                        "unicast": {
                                                            "address_family_profile": "tenant-af",
                                                            "filtering_profile": "default-ipv4-bgp-filtering",
                                                            "import_route_map": "tenant-rm",
                                                        }
                                                    }
                                                },
                                            }
                                        ],
                                    }
                                ]
                            },
                        }
                    ],
                }
            ],
        }
        current_data = {
            "BgpAddressFamilyProfile": [{"name": "tenant-af"}],
            "BgpRouteMap": [{"name": "tenant-rm"}],
        }

        plan = build_plan(parsed_data, current_data=current_data)

        self.assertNotIn(
            "missing-network-reference",
            {warning.code for warning in plan.warnings},
        )

    def test_build_plan_warns_for_missing_vpn_references(self):
        parsed_data = {
            "IKEGateway": [
                {
                    "name": "vpn-gw-a",
                    "protocol": {"ikev2": {"ike_crypto_profile": "ike-missing"}},
                }
            ],
            "IPsecTunnel": [
                {
                    "name": "vpn-tunnel-a",
                    "tunnel_interface": "tunnel.99",
                    "auto_key": {
                        "ike_gateway": [{"name": "vpn-gw-missing"}],
                        "ipsec_crypto_profile": "ipsec-missing",
                    },
                }
            ],
        }

        plan = build_plan(parsed_data)
        missing = [warning for warning in plan.warnings if warning.code == "missing-network-reference"]

        self.assertEqual(len(missing), 4)
        self.assertEqual(
            {
                warning.message.split("'")[1]
                for warning in missing
            },
            {"ike-missing", "tunnel.99", "vpn-gw-missing", "ipsec-missing"},
        )

    def test_build_plan_uses_current_data_for_vpn_reference_validation(self):
        parsed_data = {
            "IKEGateway": [
                {
                    "name": "vpn-gw-a",
                    "protocol": {"ikev2": {"ike_crypto_profile": "tenant-ike"}},
                }
            ],
            "IPsecTunnel": [
                {
                    "name": "vpn-tunnel-a",
                    "tunnel_interface": "tunnel.1",
                    "auto_key": {
                        "ike_gateway": [{"name": "vpn-gw-a"}],
                        "ipsec_crypto_profile": "tenant-ipsec",
                    },
                }
            ],
        }
        current_data = {
            "IKECryptoProfile": [{"name": "tenant-ike"}],
            "IPsecCryptoProfile": [{"name": "tenant-ipsec"}],
            "TunnelInterface": [{"name": "tunnel.1"}],
        }

        plan = build_plan(parsed_data, current_data=current_data)

        self.assertNotIn(
            "missing-network-reference",
            {warning.code for warning in plan.warnings},
        )

    def test_build_plan_warns_for_missing_interface_references(self):
        parsed_data = {
            "Zones": [{"name": "trust", "network": {"layer3": ["ethernet1/1", "tunnel.1"]}}],
            "LogicalRouter": [
                {
                    "name": "default",
                    "routing_stack": "advanced",
                    "vrf": [
                        {
                            "name": "default",
                            "interface": ["ethernet1/1"],
                            "routing_table": {
                                "ip": {
                                    "static_route": [
                                        {
                                            "name": "default-route",
                                            "destination": "0.0.0.0/0",
                                            "interface": "ethernet1/1",
                                        }
                                    ]
                                }
                            },
                        }
                    ],
                }
            ],
            "PbfRule": [{"name": "pbf-a", "action": {"forwarding": {"egress_interface": "ethernet1/2"}}}],
        }

        plan = build_plan(parsed_data)
        missing = [warning for warning in plan.warnings if warning.code == "missing-network-reference"]

        self.assertEqual(
            {
                warning.message.split("'")[1]
                for warning in missing
            },
            {"ethernet1/1", "tunnel.1", "ethernet1/2"},
        )

    def test_build_plan_uses_default_value_for_interface_reference_validation(self):
        parsed_data = {
            "EthernetInterface": [{"name": "$ethernet1-1", "default_value": "ethernet1/1"}],
            "TunnelInterface": [{"name": "tunnel.1", "default_value": "tunnel.1"}],
            "Zones": [{"name": "trust", "network": {"layer3": ["ethernet1/1", "tunnel.1"]}}],
            "LogicalRouter": [
                {
                    "name": "default",
                    "routing_stack": "advanced",
                    "vrf": [{"name": "default", "interface": ["ethernet1/1", "tunnel.1"]}],
                }
            ],
        }

        plan = build_plan(parsed_data)

        self.assertNotIn(
            "missing-network-reference",
            {warning.code for warning in plan.warnings},
        )

    def test_build_plan_warns_for_missing_policy_references(self):
        parsed_data = {
            "security_pre_rules": [
                {
                    "name": "allow-web",
                    "from": ["trust"],
                    "to": ["untrust"],
                    "source": ["users-net"],
                    "destination": ["web-dst"],
                    "service": ["tcp-443"],
                    "profile_setting": {"group": ["strict-profiles"]},
                    "schedule": "business-hours",
                }
            ],
            "app_override_pre_rules": [
                {
                    "name": "custom-app-override",
                    "from": ["trust"],
                    "to": ["untrust"],
                    "source": ["users-net"],
                    "destination": ["web-dst"],
                    "application": "custom-web-app",
                }
            ],
            "decryption_pre_rules": [
                {
                    "name": "decrypt-web",
                    "from": ["trust"],
                    "to": ["untrust"],
                    "source": ["10.0.0.0/24"],
                    "destination": ["any"],
                    "service": ["application-default"],
                    "profile": "forward-proxy-profile",
                }
            ],
            "nat_pre_rules": [
                {
                    "name": "dnat-web",
                    "from": ["untrust"],
                    "to": ["untrust"],
                    "source": ["any"],
                    "destination": ["203.0.113.10"],
                    "service": "tcp-443",
                    "destination_translation": {"translated_address": "inside-web"},
                }
            ],
        }

        plan = build_plan(
            parsed_data,
            object_types=[
                "app_override_pre_rules",
                "security_pre_rules",
                "decryption_pre_rules",
                "nat_pre_rules",
            ],
        )
        missing = [warning for warning in plan.warnings if warning.code == "missing-policy-reference"]

        self.assertEqual(
            {
                warning.message.split("'")[1]
                for warning in missing
            },
            {
                "trust",
                "untrust",
                "users-net",
                "web-dst",
                "tcp-443",
                "strict-profiles",
                "business-hours",
                "custom-web-app",
                "forward-proxy-profile",
                "inside-web",
            },
        )

    def test_plan_to_dict_includes_remediation_report(self):
        parsed_data = {
            "app_override_pre_rules": [
                {
                    "name": "custom-app-override",
                    "from": ["trust"],
                    "to": ["untrust"],
                    "source": ["users-net"],
                    "destination": ["web-dst"],
                    "application": "custom-web-app",
                }
            ]
        }

        remediation = build_plan(parsed_data, object_types=["app_override_pre_rules"]).to_dict()["remediation"]

        self.assertEqual(len(remediation), 1)
        self.assertEqual(remediation[0]["code"], "missing-policy-reference")
        self.assertEqual(remediation[0]["object_types"], {"app_override_pre_rules": 5})
        self.assertEqual(len(remediation[0]["examples"]), 5)

    def test_build_plan_uses_current_data_for_policy_reference_validation(self):
        parsed_data = {
            "security_pre_rules": [
                {
                    "name": "allow-web",
                    "from": ["trust"],
                    "to": ["untrust"],
                    "source": ["users-net"],
                    "destination": ["web-dst"],
                    "service": ["tcp-443"],
                    "profile_setting": {"group": ["strict-profiles"]},
                }
            ]
        }
        current_data = {
            "Zones": [{"name": "trust"}, {"name": "untrust"}],
            "Address": [{"name": "users-net"}, {"name": "web-dst"}],
            "Service": [{"name": "tcp-443"}],
            "ProfileGroup": [{"name": "strict-profiles"}],
        }

        plan = build_plan(parsed_data, current_data=current_data, object_types=["security_pre_rules"])

        self.assertNotIn(
            "missing-policy-reference",
            {warning.code for warning in plan.warnings},
        )

    def test_build_plan_treats_external_dynamic_lists_as_valid_policy_address_references(self):
        parsed_data = {
            "security_pre_rules": [
                {
                    "name": "block-edl",
                    "from": ["trust"],
                    "to": ["untrust"],
                    "source": ["panw-highrisk-ip-list"],
                    "destination": ["panw-known-ip-list"],
                }
            ]
        }
        current_data = {
            "Zones": [{"name": "trust"}, {"name": "untrust"}],
            "ExternalDynamicList": [
                {"name": "panw-highrisk-ip-list"},
                {"name": "panw-known-ip-list"},
            ],
        }

        plan = build_plan(parsed_data, current_data=current_data, object_types=["security_pre_rules"])

        self.assertNotIn(
            "missing-policy-reference",
            {warning.code for warning in plan.warnings},
        )

    def test_build_plan_warns_when_reference_target_is_parsed_but_not_selected(self):
        parsed_data = {
            "BgpFilteringProfile": [
                {
                    "name": "default-ipv4-bgp-filtering",
                    "ipv4": {"unicast": {"route_maps": {"inbound": "parsed-but-not-selected"}}},
                }
            ],
            "BgpRouteMap": [
                {
                    "name": "parsed-but-not-selected",
                    "route_map": [{"name": "rule-a", "action": {"permit": {}}}],
                }
            ],
        }

        plan = build_plan(parsed_data, object_types=["BgpFilteringProfile"])

        missing = [warning for warning in plan.warnings if warning.code == "missing-network-reference"]
        self.assertEqual(len(missing), 1)
        self.assertIn("parsed-but-not-selected", missing[0].message)

    def test_build_plan_uses_offline_current_data_for_mixed_results(self):
        parsed_data = {
            "Address": [
                {"name": "same", "ip_netmask": "192.0.2.10"},
                {"name": "changed", "ip_netmask": "192.0.2.20"},
                {"name": "new", "ip_netmask": "192.0.2.30"},
            ]
        }
        current_data = {
            "Address": [
                {"name": "same", "ip_netmask": "192.0.2.10", "folder": "All"},
                {"name": "changed", "ip_netmask": "192.0.2.21"},
            ]
        }

        plan = build_plan(parsed_data, current_data=current_data)

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.summary()["skips"], 1)
        self.assertEqual(plan.summary()["conflicts"], 1)

    def test_build_network_report_returns_selected_network_objects_and_warnings(self):
        parsed_data = {
            "LogicalRouter": [
                {
                    "name": "default",
                    "vrf": [
                        {
                            "name": "default",
                            "routing_table": {
                                "ip": {
                                    "static_route": [
                                        {
                                            "name": "static-a",
                                            "route_table": {"no_install": {}},
                                        }
                                    ]
                                }
                            },
                        }
                    ],
                }
            ],
            "Address": [{"name": "addr-a", "ip_netmask": "192.0.2.10"}],
            "_migration_warnings": [
                {
                    "object_type": "LogicalRouter",
                    "name": "default",
                    "path": "network.virtual-router.entry[default].ecmp",
                    "code": "unsupported-panos-routing-node",
                    "message": "ECMP not migrated",
                }
            ],
        }

        report = build_network_report(parsed_data, ["LogicalRouter"])

        self.assertEqual(report.objects, {"LogicalRouter": parsed_data["LogicalRouter"]})
        self.assertEqual(report.summary()["LogicalRouter"], 1)
        self.assertEqual(report.summary()["warnings"], 2)
        self.assertEqual(
            report.to_dict()["warning_summary"],
            {
                "logical-router-static-route-option": {
                    "count": 1,
                    "object_types": {"LogicalRouter": 1},
                },
                "unsupported-panos-routing-node": {
                    "count": 1,
                    "object_types": {"LogicalRouter": 1},
                },
            },
        )
        self.assertEqual(
            [warning.code for warning in report.warnings],
            ["unsupported-panos-routing-node", "logical-router-static-route-option"],
        )


if __name__ == "__main__":
    unittest.main()
