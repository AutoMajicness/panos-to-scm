import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_PBF_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <rulebase>
            <pbf>
              <rules>
                <entry name="send-guest-to-isp2">
                  <description>Guest backup ISP</description>
                  <from>
                    <member>guest</member>
                  </from>
                  <source>
                    <member>10.50.0.0/24</member>
                  </source>
                  <source-user>
                    <member>any</member>
                  </source-user>
                  <destination>
                    <member>any</member>
                  </destination>
                  <application>
                    <member>any</member>
                  </application>
                  <service>
                    <member>application-default</member>
                  </service>
                  <negate-source>no</negate-source>
                  <negate-destination>no</negate-destination>
                  <disabled>no</disabled>
                  <tag>
                    <member>migration</member>
                  </tag>
                  <action>
                    <forwarding>
                      <egress-interface>ethernet1/2</egress-interface>
                      <nexthop>
                        <ip-address>198.51.100.1</ip-address>
                      </nexthop>
                      <symmetric-return>yes</symmetric-return>
                      <monitor>
                        <ip-address>8.8.8.8</ip-address>
                        <profile>default</profile>
                        <disable-if-unreachable>yes</disable-if-unreachable>
                      </monitor>
                    </forwarding>
                  </action>
                </entry>
              </rules>
            </pbf>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


class PanosPbfRuleParserTests(unittest.TestCase):
    def test_local_pbf_rules_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_PBF_XML, encoding="utf-8")

            rules = XMLParser(str(xml_path), "local").parse_specific_types(["PbfRule"])["PbfRule"]

        self.assertEqual(
            rules,
            [
                {
                    "name": "send-guest-to-isp2",
                    "description": "Guest backup ISP",
                    "from": ["guest"],
                    "source": ["10.50.0.0/24"],
                    "source_user": ["any"],
                    "destination": ["any"],
                    "application": ["any"],
                    "service": ["application-default"],
                    "negate_source": False,
                    "negate_destination": False,
                    "disabled": False,
                    "tag": ["migration"],
                    "action": {
                        "forwarding": {
                            "egress_interface": "ethernet1/2",
                            "nexthop": {"ip_address": "198.51.100.1"},
                            "symmetric_return": True,
                            "monitor": {
                                "ip_address": "8.8.8.8",
                                "profile": "default",
                                "disable_if_unreachable": True,
                            },
                        }
                    },
                }
            ],
        )

    def test_panorama_pbf_rule_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_PBF_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                rules = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["PbfRule"])["PbfRule"]

        self.assertEqual(rules, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
