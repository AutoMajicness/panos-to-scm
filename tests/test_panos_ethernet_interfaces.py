import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_ETHERNET_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <comment>WAN</comment>
              <link-speed>1000</link-speed>
              <link-duplex>full</link-duplex>
              <link-state>up</link-state>
              <layer3>
                <ip>
                  <entry name="203.0.113.1/24" />
                  <entry name="203.0.113.2/24" />
                </ip>
                <mtu>1500</mtu>
                <interface-management-profile>allow-ping</interface-management-profile>
              </layer3>
            </entry>
            <entry name="ethernet1/2">
              <layer2 />
            </entry>
            <entry name="ethernet1/3">
              <tap />
            </entry>
            <entry name="ethernet1/4">
              <aggregate-group>ae1</aggregate-group>
            </entry>
            <entry name="ethernet1/6">
              <virtual-wire />
            </entry>
            <entry name="ethernet1/5">
              <comment>Unsupported empty interface</comment>
            </entry>
          </ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosEthernetInterfaceParserTests(unittest.TestCase):
    def test_local_ethernet_interfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_ETHERNET_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                interfaces = XMLParser(str(xml_path), "local").parse_specific_types(["EthernetInterface"])["EthernetInterface"]

        self.assertEqual(
            interfaces,
            [
                {
                    "name": "$ethernet1-1",
                    "default_value": "ethernet1/1",
                    "comment": "WAN",
                    "link_speed": "1000",
                    "link_duplex": "full",
                    "link_state": "up",
                    "layer3": {
                        "ip": [
                            {"name": "203.0.113.1/24"},
                            {"name": "203.0.113.2/24"},
                        ],
                        "mtu": 1500,
                        "interface_management_profile": "allow-ping",
                    },
                },
                {"name": "$ethernet1-2", "default_value": "ethernet1/2", "layer2": {}},
                {"name": "$ethernet1-3", "default_value": "ethernet1/3", "tap": {}},
                {"name": "$ethernet1-4", "default_value": "ethernet1/4", "aggregate_group": "ae1"},
                {"name": "$ethernet1-6", "default_value": "ethernet1/6", "virtual_wire": {}},
            ],
        )
        self.assertIn("ethernet1/5", logs.output[0])

    def test_panorama_ethernet_interface_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_ETHERNET_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                interfaces = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["EthernetInterface"])["EthernetInterface"]

        self.assertEqual(interfaces, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
