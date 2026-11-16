import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_DHCP_INTERFACE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <dhcp>
          <interface>
            <entry name="vlan.100">
              <server>
                <mode>enabled</mode>
                <ip-pool>
                  <member>10.100.0.10-10.100.0.200</member>
                </ip-pool>
                <option>
                  <gateway>10.100.0.1</gateway>
                  <subnet-mask>255.255.255.0</subnet-mask>
                  <primary-dns>8.8.8.8</primary-dns>
                  <secondary-dns>1.1.1.1</secondary-dns>
                  <domain>example.com</domain>
                  <lease>
                    <timeout>
                      <days>1</days>
                      <hours>2</hours>
                    </timeout>
                  </lease>
                  <dns-suffix>
                    <member>corp.example.com</member>
                  </dns-suffix>
                </option>
                <reserved>
                  <entry name="printer">
                    <mac>00:11:22:33:44:55</mac>
                    <ip>10.100.0.50</ip>
                    <description>Office printer</description>
                  </entry>
                </reserved>
              </server>
            </entry>
            <entry name="ethernet1/3">
              <relay>
                <enable>yes</enable>
                <server>
                  <member>192.0.2.10</member>
                  <member>192.0.2.11</member>
                </server>
              </relay>
            </entry>
          </interface>
        </dhcp>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosDhcpServiceInterfaceParserTests(unittest.TestCase):
    def test_local_dhcp_interfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_DHCP_INTERFACE_XML, encoding="utf-8")

            interfaces = XMLParser(str(xml_path), "local").parse_specific_types(["DHCPInterface"])["DHCPInterface"]

        self.assertEqual(
            interfaces,
            [
                {
                    "name": "vlan.100",
                    "server": {
                        "mode": "enabled",
                        "ip_pool": ["10.100.0.10-10.100.0.200"],
                        "option": {
                            "gateway": "10.100.0.1",
                            "subnet_mask": "255.255.255.0",
                            "primary_dns": "8.8.8.8",
                            "secondary_dns": "1.1.1.1",
                            "domain": "example.com",
                            "lease": {"timeout": {"days": 1, "hours": 2}},
                            "dns_suffix": ["corp.example.com"],
                        },
                        "reserved": [
                            {
                                "name": "printer",
                                "mac": "00:11:22:33:44:55",
                                "ip": "10.100.0.50",
                                "description": "Office printer",
                            }
                        ],
                    },
                },
                {
                    "name": "ethernet1/3",
                    "relay": {
                        "enable": True,
                        "server": ["192.0.2.10", "192.0.2.11"],
                    },
                },
            ],
        )

    def test_panorama_dhcp_interface_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_DHCP_INTERFACE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                interfaces = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["DHCPInterface"])["DHCPInterface"]

        self.assertEqual(interfaces, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
