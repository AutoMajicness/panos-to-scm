import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_LAYER3_SUBINTERFACE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <units>
                  <entry name="ethernet1/1.100">
                    <tag>100</tag>
                    <comment>Users VLAN</comment>
                    <ip>
                      <entry name="10.100.0.1/24" />
                      <entry name="10.100.0.2/24" />
                    </ip>
                    <mtu>1500</mtu>
                    <interface-management-profile>allow-ping</interface-management-profile>
                    <netflow-profile>netflow-default</netflow-profile>
                  </entry>
                  <entry name="ethernet1/1.200">
                    <tag>200</tag>
                    <ip>
                      <entry name="10.200.0.1/24" />
                    </ip>
                  </entry>
                </units>
              </layer3>
            </entry>
          </ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosLayer3SubinterfaceParserTests(unittest.TestCase):
    def test_local_layer3_subinterfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LAYER3_SUBINTERFACE_XML, encoding="utf-8")

            subinterfaces = XMLParser(str(xml_path), "local").parse_specific_types(["Layer3Subinterface"])["Layer3Subinterface"]

        self.assertEqual(
            subinterfaces,
            [
                {
                    "name": "$ethernet1-1.100",
                    "default_value": "ethernet1/1.100",
                    "parent_interface": "ethernet1/1",
                    "tag": 100,
                    "comment": "Users VLAN",
                    "netflow_profile": "netflow-default",
                    "interface_management_profile": "allow-ping",
                    "mtu": 1500,
                    "ip": [
                        {"name": "10.100.0.1/24"},
                        {"name": "10.100.0.2/24"},
                    ],
                },
                {
                    "name": "$ethernet1-1.200",
                    "default_value": "ethernet1/1.200",
                    "parent_interface": "ethernet1/1",
                    "tag": 200,
                    "ip": [{"name": "10.200.0.1/24"}],
                },
            ],
        )

    def test_panorama_layer3_subinterface_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LAYER3_SUBINTERFACE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                subinterfaces = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["Layer3Subinterface"])["Layer3Subinterface"]

        self.assertEqual(subinterfaces, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
