import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_DHCP_INTERFACE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/1">
              <layer3>
                <dhcp-client>
                  <enable>yes</enable>
                  <create-default-route>yes</create-default-route>
                  <default-route-metric>10</default-route-metric>
                  <send-hostname>
                    <enable>yes</enable>
                    <hostname>edge-fw</hostname>
                  </send-hostname>
                </dhcp-client>
                <mtu>1500</mtu>
                <interface-management-profile>allow-mgmt</interface-management-profile>
              </layer3>
            </entry>
            <entry name="ethernet1/2">
              <layer3>
                <units>
                  <entry name="ethernet1/2.100">
                    <tag>100</tag>
                    <dhcp-client>
                      <enable>yes</enable>
                      <create-default-route>no</create-default-route>
                    </dhcp-client>
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


class PanosDhcpInterfaceParserTests(unittest.TestCase):
    def test_ethernet_layer3_dhcp_is_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_DHCP_INTERFACE_XML, encoding="utf-8")

            interfaces = XMLParser(str(xml_path), "local").parse_specific_types(["EthernetInterface"])["EthernetInterface"]

        self.assertEqual(
            interfaces[0],
            {
                "name": "$ethernet1-1",
                "default_value": "ethernet1/1",
                "layer3": {
                    "dhcp_client": {
                        "enable": True,
                        "create_default_route": True,
                        "default_route_metric": 10,
                        "send_hostname": {"enable": True, "hostname": "edge-fw"},
                    },
                    "mtu": 1500,
                    "interface_management_profile": "allow-mgmt",
                },
            },
        )

    def test_layer3_subinterface_dhcp_is_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_DHCP_INTERFACE_XML, encoding="utf-8")

            subinterfaces = XMLParser(str(xml_path), "local").parse_specific_types(["Layer3Subinterface"])["Layer3Subinterface"]

        self.assertEqual(
            subinterfaces,
            [
                {
                    "name": "$ethernet1-2.100",
                    "default_value": "ethernet1/2.100",
                    "parent_interface": "ethernet1/2",
                    "tag": 100,
                    "dhcp_client": {
                        "enable": True,
                        "create_default_route": False,
                    },
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
