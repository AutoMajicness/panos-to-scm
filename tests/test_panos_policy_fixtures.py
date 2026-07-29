import unittest
from pathlib import Path

from migration import build_plan
from parse.parse_panos import XMLParser


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "panos"


class PanosPolicyFixtureTests(unittest.TestCase):
    def test_local_policy_fixture_resolves_policy_references_when_targets_are_selected(self):
        fixture_path = FIXTURE_DIR / "local_policy_reference_variants.xml"
        object_types = [
            "Address",
            "EthernetInterface",
            "Service",
            "ProfileGroup",
            "DecryptionProfile",
            "Zones",
            "security_pre_rules",
            "nat_pre_rules",
            "decryption_pre_rules",
        ]

        parsed = XMLParser(str(fixture_path), "local").parse_specific_types(object_types)

        self.assertEqual({entry["name"] for entry in parsed["Address"]}, {"users-net", "web-public", "web-private"})
        self.assertEqual({entry["default_value"] for entry in parsed["EthernetInterface"]}, {"ethernet1/1", "ethernet1/2"})
        self.assertEqual(parsed["Service"][0]["name"], "tcp-443")
        self.assertEqual({entry["name"] for entry in parsed["Zones"]}, {"trust", "untrust"})
        self.assertEqual(parsed["ProfileGroup"][0]["name"], "strict-profiles")
        self.assertEqual(parsed["DecryptionProfile"][0]["name"], "decrypt-forward")
        self.assertEqual(parsed["security_pre_rules"][0]["profile_setting"], {"group": ["strict-profiles"]})
        self.assertEqual(parsed["nat_pre_rules"][0]["destination_translation"]["translated_address"], "web-private")
        self.assertEqual(parsed["decryption_pre_rules"][0]["profile"], "decrypt-forward")

        plan = build_plan(parsed, object_types=object_types)

        self.assertNotIn(
            "missing-policy-reference",
            {warning.code for warning in plan.warnings},
        )

    def test_local_policy_fixture_warns_when_policy_targets_are_not_selected(self):
        fixture_path = FIXTURE_DIR / "local_policy_reference_variants.xml"
        object_types = [
            "Address",
            "EthernetInterface",
            "Service",
            "ProfileGroup",
            "DecryptionProfile",
            "Zones",
            "security_pre_rules",
            "nat_pre_rules",
            "decryption_pre_rules",
        ]
        policy_types = ["security_pre_rules", "nat_pre_rules", "decryption_pre_rules"]

        parsed = XMLParser(str(fixture_path), "local").parse_specific_types(object_types)
        plan = build_plan(parsed, object_types=policy_types)
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
                "web-public",
                "web-private",
                "tcp-443",
                "strict-profiles",
                "decrypt-forward",
            },
        )


if __name__ == "__main__":
    unittest.main()
