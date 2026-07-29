import unittest

from migration import build_plan


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
            ["summary", "creates", "updates", "skips", "conflicts", "unsupported"],
        )
        self.assertEqual([item["name"] for item in report["creates"]], ["a-first", "z-last"])
        self.assertEqual(report["creates"][0]["action"], "create")

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


if __name__ == "__main__":
    unittest.main()
