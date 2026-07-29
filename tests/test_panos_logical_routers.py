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
            <protocol>
              <bgp>
                <enable>yes</enable>
                <router-id>192.0.2.1</router-id>
                <local-as>65001</local-as>
                <peer-group>
                  <entry name="upstream">
                    <enable>yes</enable>
                    <peer>
                      <entry name="peer-a">
                        <enable>yes</enable>
                        <peer-as>65002</peer-as>
                        <local-address>
                          <interface>ethernet1/1</interface>
                          <ip>192.0.2.1/24</ip>
                        </local-address>
                        <peer-address>
                          <ip>192.0.2.2</ip>
                        </peer-address>
                      </entry>
                    </peer>
                  </entry>
                </peer-group>
                <policy>
                  <import>
                    <rules>
                      <entry name="import-private">
                        <action>allow</action>
                        <match>
                          <address-prefix>
                            <entry name="10.0.0.0/8">
                              <exact>yes</exact>
                            </entry>
                          </address-prefix>
                          <as-path>
                            <member>^65010_</member>
                          </as-path>
                        </match>
                      </entry>
                      <entry name="import-access-list">
                        <action>allow</action>
                        <match>
                          <route-table>
                            <access-list>
                              <member>corp-routes</member>
                            </access-list>
                          </route-table>
                        </match>
                      </entry>
                    </rules>
                  </import>
                  <export>
                    <rules>
                      <entry name="export-default">
                        <description>Export default only</description>
                        <action>allow</action>
                        <match>
                          <address-prefix>
                            <entry name="0.0.0.0/0" />
                          </address-prefix>
                          <community>
                            <member>65001:100</member>
                          </community>
                        </match>
                        <set>
                          <local-preference>200</local-preference>
                          <metric>50</metric>
                        </set>
                      </entry>
                    </rules>
                  </export>
                </policy>
                <redist-rules>
                  <entry name="static-to-bgp">
                    <type>static</type>
                    <metric>100</metric>
                    <action>allow</action>
                  </entry>
                  <entry name="connected-to-bgp">
                    <type>connected</type>
                    <metric>20</metric>
                    <action>allow</action>
                  </entry>
                </redist-rules>
              </bgp>
              <ospf>
                <enable>yes</enable>
                <router-id>192.0.2.1</router-id>
                <area>
                  <entry name="0.0.0.0">
                    <type>
                      <normal />
                    </type>
                    <interface>
                      <entry name="ethernet1/1">
                        <enable>yes</enable>
                        <passive>no</passive>
                        <metric>10</metric>
                        <link-type>
                          <p2p />
                        </link-type>
                        <bfd>
                          <profile>default</profile>
                        </bfd>
                      </entry>
                    </interface>
                  </entry>
                </area>
              </ospf>
              <ospfv3>
                <enable>yes</enable>
                <router-id>192.0.2.1</router-id>
                <area>
                  <entry name="0.0.0.0">
                    <interface>
                      <entry name="ethernet1/1">
                        <enable>yes</enable>
                        <metric>20</metric>
                      </entry>
                    </interface>
                  </entry>
                </area>
              </ospfv3>
            </protocol>
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
                    <bfd>
                      <profile>default</profile>
                    </bfd>
                    <path-monitor>
                      <enable>yes</enable>
                      <failure-condition>any</failure-condition>
                      <hold-time>2</hold-time>
                      <monitor-destinations>
                        <entry name="probe1">
                          <enable>yes</enable>
                          <source>10.0.0.1</source>
                          <destination>10.0.0.254</destination>
                          <interval>3</interval>
                          <count>5</count>
                        </entry>
                      </monitor-destinations>
                    </path-monitor>
                  </entry>
                </static-route>
              </ip>
              <ipv6>
                <static-route>
                  <entry name="default-v6">
                    <destination>::/0</destination>
                    <interface>ethernet1/1</interface>
                    <nexthop>
                      <ipv6-address>2001:db8::1</ipv6-address>
                    </nexthop>
                    <metric>20</metric>
                  </entry>
                </static-route>
              </ipv6>
            </routing-table>
          </entry>
        </virtual-router>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosLogicalRouterParserTests(unittest.TestCase):
    def test_local_panos_virtual_router_entries_are_mapped_to_scm_logical_routers(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LOGICAL_ROUTER_XML, encoding="utf-8")

            routers = XMLParser(str(xml_path), "local").parse_specific_types(["LogicalRouter"])["LogicalRouter"]

        self.assertEqual(
            routers,
            [
                {
                    "name": "default",
                    "routing_stack": "advanced",
                    "vrf": [
                        {
                            "name": "default",
                            "interface": ["ethernet1/1", "ethernet1/1.100"],
                            "rib_filter": {
                                "ipv4": {
                                    "bgp": {
                                        "route_map": "default-export-export-default-rm",
                                    }
                                }
                            },
                            "bgp": {
                                "enable": True,
                                "router_id": "192.0.2.1",
                                "local_as": "65001",
                                "redistribution_profile": "default-bgp-redist",
                                "peer_group": [
                                    {
                                        "name": "upstream",
                                        "enable": True,
                                        "peer": [
                                            {
                                                "name": "peer-a",
                                                "enable": True,
                                                "peer_as": "65002",
                                                "local_interface": "ethernet1/1",
                                                "local_address": "192.0.2.1/24",
                                                "peer_address": "192.0.2.2",
                                                "address_family": {
                                                    "ipv4": {
                                                        "unicast": {
                                                            "import_route_map": "default-import-import-private-rm",
                                                            "export_route_map": "default-export-export-default-rm",
                                                        }
                                                    }
                                                },
                                            }
                                        ],
                                    }
                                ],
                            },
                            "ospf": {
                                "enable": True,
                                "router_id": "192.0.2.1",
                                "area": [
                                    {
                                        "name": "0.0.0.0",
                                        "type": {"normal": {}},
                                        "interface": [
                                            {
                                                "name": "ethernet1/1",
                                                "enable": True,
                                                "passive": False,
                                                "metric": 10,
                                                "link_type": {"p2p": {}},
                                                "bfd": {"profile": "default"},
                                            }
                                        ],
                                    }
                                ],
                            },
                            "ospfv3": {
                                "enable": True,
                                "router_id": "192.0.2.1",
                                "area": [
                                    {
                                        "name": "0.0.0.0",
                                        "interface": [
                                            {
                                                "name": "ethernet1/1",
                                                "enable": True,
                                                "metric": 20,
                                            }
                                        ],
                                    }
                                ],
                            },
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
                                            "bfd": {"profile": "default"},
                                            "path_monitor": {
                                                "enable": True,
                                                "failure_condition": "any",
                                                "hold_time": 2,
                                                "monitor_destinations": [
                                                    {
                                                        "name": "probe1",
                                                        "enable": True,
                                                        "source": "10.0.0.1",
                                                        "destination": "10.0.0.254",
                                                        "interval": 3,
                                                        "count": 5,
                                                    }
                                                ],
                                            },
                                        },
                                    ]
                                },
                                "ipv6": {
                                    "static_route": [
                                        {
                                            "name": "default-v6",
                                            "destination": "::/0",
                                            "interface": "ethernet1/1",
                                            "metric": 20,
                                            "nexthop": {"ipv6_address": "2001:db8::1"},
                                        }
                                    ]
                                },
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

    def test_local_bgp_policy_filters_are_mapped_to_prefix_lists_and_route_maps(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LOGICAL_ROUTER_XML, encoding="utf-8")

            parsed = XMLParser(str(xml_path), "local").parse_specific_types(
                [
                    "RoutePrefixList",
                    "RouteAccessList",
                    "RouteCommunityList",
                    "RoutePathAccessList",
                    "BgpRouteMap",
                    "BgpRouteMapRedistribution",
                    "BgpRedistributionProfile",
                ]
            )

        self.assertEqual(
            parsed["RoutePrefixList"],
            [
                {
                    "name": "default-import-import-private-pl",
                    "prefix_list": [
                        {
                            "name": 1,
                            "action": "permit",
                            "prefix": "10.0.0.0/8",
                            "exact": True,
                        }
                    ],
                },
                {
                    "name": "default-export-export-default-pl",
                    "prefix_list": [
                        {
                            "name": 1,
                            "action": "permit",
                            "prefix": "0.0.0.0/0",
                        }
                    ],
                },
            ],
        )
        self.assertEqual(
            parsed["RouteAccessList"],
            [
                {
                    "name": "default-import-import-access-list-acl",
                    "access_list": [
                        {
                            "name": 1,
                            "action": "permit",
                            "source": "corp-routes",
                        }
                    ],
                }
            ],
        )
        self.assertEqual(
            parsed["RouteCommunityList"],
            [
                {
                    "name": "default-export-export-default-cl",
                    "community_list": [
                        {
                            "name": 1,
                            "action": "permit",
                            "community": "65001:100",
                        }
                    ],
                }
            ],
        )
        self.assertEqual(
            parsed["RoutePathAccessList"],
            [
                {
                    "name": "default-import-import-private-pal",
                    "path_access_list": [
                        {
                            "name": 1,
                            "action": "permit",
                            "regular_expression": "^65010_",
                        }
                    ],
                }
            ],
        )
        self.assertEqual(
            parsed["BgpRouteMap"],
            [
                {
                    "name": "default-import-import-private-rm",
                    "description": "Generated from PAN-OS BGP import rule import-private",
                    "route_map": [
                        {
                            "name": 10,
                            "action": "permit",
                            "match": {
                                "as_path_access_list": "default-import-import-private-pal",
                                "ipv4": {
                                    "address": {
                                        "prefix_list": "default-import-import-private-pl",
                                    }
                                }
                            },
                        }
                    ],
                },
                {
                    "name": "default-import-import-access-list-rm",
                    "description": "Generated from PAN-OS BGP import rule import-access-list",
                    "route_map": [
                        {
                            "name": 20,
                            "action": "permit",
                            "match": {
                                "ipv4": {
                                    "address": {
                                        "access_list": "default-import-import-access-list-acl",
                                    }
                                }
                            },
                        }
                    ],
                },
                {
                    "name": "default-export-export-default-rm",
                    "description": "Generated from PAN-OS BGP export rule export-default",
                    "route_map": [
                        {
                            "name": 10,
                            "description": "Export default only",
                            "action": "permit",
                            "match": {
                                "regular_community": "default-export-export-default-cl",
                                "ipv4": {
                                    "address": {
                                        "prefix_list": "default-export-export-default-pl",
                                    }
                                }
                            },
                            "set": {
                                "local_preference": 200,
                                "metric": {"action": "set", "value": 50},
                            },
                        }
                    ],
                },
            ],
        )
        self.assertEqual(
            parsed["BgpRouteMapRedistribution"],
            [
                {
                    "name": "default-redist-static-to-bgp-rm",
                    "route_map": [
                        {
                            "name": 10,
                            "action": "permit",
                            "set": {"metric": {"action": "set", "value": 100}},
                        }
                    ],
                },
                {
                    "name": "default-redist-connected-to-bgp-rm",
                    "route_map": [
                        {
                            "name": 10,
                            "action": "permit",
                            "set": {"metric": {"action": "set", "value": 20}},
                        }
                    ],
                },
            ],
        )
        self.assertEqual(
            parsed["BgpRedistributionProfile"],
            [
                {
                    "name": "default-bgp-redist",
                    "ipv4": {
                        "unicast": {
                            "static": {
                                "enable": True,
                                "metric": 100,
                                "route_map": "default-redist-static-to-bgp-rm",
                            },
                            "connected": {
                                "enable": True,
                                "metric": 20,
                                "route_map": "default-redist-connected-to-bgp-rm",
                            },
                        }
                    },
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
