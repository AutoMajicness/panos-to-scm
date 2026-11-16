import tempfile
import unittest
from pathlib import Path

import main
from config import AppConfig
from parse.parse_pfsense import PfSenseParser


FIXTURE = Path(__file__).parent / "fixtures" / "pfsense" / "basic_config.xml"


class PfSenseParserTests(unittest.TestCase):
    def test_parse_aliases_zones_rules_and_nat(self):
        parsed = PfSenseParser(str(FIXTURE)).parse_all()

        self.assertIn({"name": "web_server", "ip_netmask": "192.168.20.10", "description": "Internal web server"}, parsed["Address"])
        self.assertIn({"name": "corp_nets", "description": "Corporate networks", "static": ["corp_nets-1", "corp_nets-2"]}, parsed["AddressGroup"])
        self.assertIn({"name": "web_ports", "description": "Web ports", "static": ["web_ports-1", "web_ports-2"]}, parsed["ServiceGroup"])
        self.assertEqual(
            [{"name": "wan", "network": {"layer3": ["ethernet1/1"]}}, {"name": "lan", "network": {"layer3": ["ethernet1/2"]}}, {"name": "dmz", "network": {"layer3": ["ethernet1/2.1000"]}}],
            parsed["Zones"],
        )
        self.assertEqual(["ethernet1/1", "ethernet1/2"], [entry["default_value"] for entry in parsed["EthernetInterface"]])
        self.assertEqual("ethernet1/2.1000", parsed["Layer3Subinterface"][0]["default_value"])
        self.assertEqual(
            {
                "name": "default-Default",
                "destination": "0.0.0.0/0",
                "interface": "ethernet1/2",
                "nexthop": {"ip_address": "192.168.10.1"},
            },
            parsed["LogicalRouter"][0]["vrf"][0]["routing_table"]["ip"]["static_route"][0],
        )

        allow_rule = parsed["security_pre_rules"][0]
        self.assertEqual("Allow-LAN-to-web", allow_rule["name"])
        self.assertEqual(["lan"], allow_rule["from"])
        self.assertEqual(["web_server"], allow_rule["destination"])
        self.assertEqual(["TCP-443"], allow_rule["service"])
        self.assertEqual("allow", allow_rule["action"])
        self.assertEqual("Cortex Data Lake", allow_rule["log_setting"])

        block_rule = parsed["security_pre_rules"][1]
        self.assertEqual("deny", block_rule["action"])
        self.assertTrue(block_rule["disabled"])

        protocol_rule = parsed["security_pre_rules"][2]
        self.assertEqual(["lan-ip"], protocol_rule["source"])
        self.assertTrue(protocol_rule["negate_destination"])
        self.assertEqual(["range_ports-tcp-udp"], protocol_rule["service"])
        service_group = next(
            group for group in parsed["ServiceGroup"] if group["name"] == "range_ports-tcp-udp"
        )
        self.assertEqual(["TCP-1000-1002", "UDP-1000-1002"], service_group["static"])

        destination_nat = parsed["nat_pre_rules"][0]
        self.assertEqual("Forward-HTTPS-to-web", destination_nat["name"])
        self.assertEqual({"translated_address": "web_server", "translated_port": "443"}, destination_nat["destination_translation"])

        source_nat = parsed["nat_pre_rules"][1]
        self.assertEqual("LAN-outbound-NAT", source_nat["name"])
        self.assertEqual({"dynamic_ip_and_port": {"translated_address": ["wan"]}}, source_nat["source_translation"])

        warning_codes = [warning["code"] for warning in parsed["_migration_warnings"]]
        self.assertIn("unsupported-pfsense-alias-type", warning_codes)
        self.assertIn("unsupported-pfsense-nat-rule", warning_codes)

    def test_parse_specific_types_filters_output(self):
        parsed = PfSenseParser(str(FIXTURE)).parse_specific_types(["Address", "security_pre_rules"])

        self.assertIn("Address", parsed)
        self.assertIn("security_pre_rules", parsed)
        self.assertIn("_migration_warnings", parsed)
        self.assertNotIn("Service", parsed)

    def test_parse_frr_bgp_into_logical_router_and_policy_objects(self):
        parsed = PfSenseParser(str(FIXTURE)).parse_all()
        bgp = parsed["LogicalRouter"][0]["vrf"][0]["bgp"]

        self.assertEqual(True, bgp["enable"])
        self.assertEqual("64640", bgp["local_as"])
        self.assertEqual("192.168.10.1", bgp["router_id"])
        self.assertEqual({"keep_alive_interval": 3, "hold_time": 9}, bgp["timers"])
        self.assertEqual("pfsense-bgp-redist", bgp["redistribution_profile"])
        peer = bgp["peer_group"][0]["peer"][0]
        self.assertEqual("192.168.10.2", peer["peer_address"])
        self.assertEqual("64641", peer["peer_as"])
        self.assertEqual({"interface": "ethernet1/2"}, peer["local_address"])
        self.assertEqual("pfsense-bgp-filter-upstream-a", peer["address_family"]["ipv4"]["unicast"]["filtering_profile"])

        self.assertEqual("PFX.REDIST.CONNECTED", parsed["RoutePrefixList"][0]["name"])
        self.assertEqual("CL.TRANSIT", parsed["RouteCommunityList"][0]["name"])
        self.assertEqual("MAP.BGP.IN", parsed["BgpRouteMap"][0]["name"])
        self.assertEqual("MAP.REDIST.CONNECTED", parsed["BgpRouteMapRedistribution"][0]["name"])

    def test_rejects_non_pfsense_xml(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.xml"
            path.write_text("<config/>", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "root element <pfsense>"):
                PfSenseParser(str(path))

    def test_main_validate_only_accepts_pfsense_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = main.main(
                AppConfig(),
                parser_type="pfsense",
                config_file=str(FIXTURE),
                validate_only=True,
                output_folder=directory,
            )

        summary = plan.summary()
        self.assertGreaterEqual(summary["creates"], 1)
        self.assertGreaterEqual(summary["warnings"], 1)


if __name__ == "__main__":
    unittest.main()
