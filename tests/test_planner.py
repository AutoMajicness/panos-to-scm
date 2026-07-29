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
            ["summary", "creates", "updates", "skips", "conflicts", "unsupported", "warnings"],
        )
        self.assertEqual([item["name"] for item in report["creates"]], ["a-first", "z-last"])
        self.assertEqual(report["creates"][0]["action"], "create")

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
            [warning.code for warning in report.warnings],
            ["unsupported-panos-routing-node", "logical-router-static-route-option"],
        )


if __name__ == "__main__":
    unittest.main()
