import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_LOGICAL_ROUTER_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <virtual-router>
          <entry name="default">
            <interface>
              <member>ethernet1/1</member>
              <member>ethernet1/1.100</member>
            </interface>
            <routing-table>
              <ip>
                <static-route>
                  <entry name="default-route">
                    <destination>0.0.0.0/0</destination>
                    <interface>ethernet1/1</interface>
                    <nexthop>
                      <ip-address>203.0.113.254</ip-address>
                    </nexthop>
                    <metric>10</metric>
                    <admin-dist>10</admin-dist>
                  </entry>
                  <entry name="discard-rfc1918">
                    <destination>10.0.0.0/8</destination>
                    <nexthop>
                      <discard />
                    </nexthop>
                  </entry>
                </static-route>
              </ip>
            </routing-table>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosLogicalRouterParserTests(unittest.TestCase):
    def test_local_virtual_routers_are_normalized_as_logical_routers(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LOGICAL_ROUTER_XML, encoding="utf-8")

            routers = XMLParser(str(xml_path), "local").parse_specific_types(["LogicalRouter"])["LogicalRouter"]

        self.assertEqual(
            routers,
            [
                {
                    "name": "default",
                    "routing_stack": "legacy",
                    "vrf": [
                        {
                            "name": "default",
                            "interface": ["ethernet1/1", "ethernet1/1.100"],
                            "routing_table": {
                                "ip": {
                                    "static_route": [
                                        {
                                            "name": "default-route",
                                            "destination": "0.0.0.0/0",
                                            "interface": "ethernet1/1",
                                            "metric": 10,
                                            "admin_dist": 10,
                                            "nexthop": {"ip_address": "203.0.113.254"},
                                        },
                                        {
                                            "name": "discard-rfc1918",
                                            "destination": "10.0.0.0/8",
                                            "nexthop": {"discard": {}},
                                        },
                                    ]
                                }
                            },
                        }
                    ],
                }
            ],
        )

    def test_panorama_logical_router_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LOGICAL_ROUTER_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                routers = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["LogicalRouter"])["LogicalRouter"]

        self.assertEqual(routers, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
