import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_VLAN_TUNNEL_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <vlan>
            <units>
              <entry name="vlan.100">
                <tag>100</tag>
                <comment>Users SVI</comment>
                <ip>
                  <entry name="10.100.0.1/24" />
                </ip>
                <mtu>1500</mtu>
                <interface-management-profile>allow-ping</interface-management-profile>
                <netflow-profile>netflow-default</netflow-profile>
              </entry>
            </units>
          </vlan>
          <tunnel>
            <units>
              <entry name="tunnel.1">
                <comment>VPN tunnel</comment>
                <ip>
                  <entry name="169.254.1.1/30" />
                </ip>
                <mtu>1400</mtu>
                <interface-management-profile>allow-ping</interface-management-profile>
                <netflow-profile>netflow-default</netflow-profile>
              </entry>
            </units>
          </tunnel>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosVlanTunnelInterfaceParserTests(unittest.TestCase):
    def test_local_vlan_interfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_VLAN_TUNNEL_XML, encoding="utf-8")

            vlans = XMLParser(str(xml_path), "local").parse_specific_types(["VlanInterface"])["VlanInterface"]

        self.assertEqual(
            vlans,
            [
                {
                    "name": "vlan.100",
                    "vlan_tag": "100",
                    "comment": "Users SVI",
                    "interface_management_profile": "allow-ping",
                    "netflow_profile": "netflow-default",
                    "mtu": 1500,
                    "ip": [{"name": "10.100.0.1/24"}],
                }
            ],
        )

    def test_local_tunnel_interfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_VLAN_TUNNEL_XML, encoding="utf-8")

            tunnels = XMLParser(str(xml_path), "local").parse_specific_types(["TunnelInterface"])["TunnelInterface"]

        self.assertEqual(
            tunnels,
            [
                {
                    "name": "tunnel.1",
                    "default_value": "tunnel.1",
                    "comment": "VPN tunnel",
                    "interface_management_profile": "allow-ping",
                    "netflow_profile": "netflow-default",
                    "mtu": 1400,
                    "ip": [{"name": "169.254.1.1/30"}],
                }
            ],
        )

    def test_panorama_vlan_and_tunnel_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_VLAN_TUNNEL_XML, encoding="utf-8")
            parser = XMLParser(str(xml_path), "panorama/shared")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                parsed = parser.parse_specific_types(["VlanInterface", "TunnelInterface"])

        self.assertEqual(parsed["VlanInterface"], [])
        self.assertEqual(parsed["TunnelInterface"], [])
        self.assertIn("VLAN interface migration currently supports local firewall XML only.", logs.output[0])
        self.assertIn("Tunnel interface migration currently supports local firewall XML only.", logs.output[1])


if __name__ == "__main__":
    unittest.main()
