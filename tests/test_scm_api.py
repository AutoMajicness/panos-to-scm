import unittest

import scm.obj as obj
from scm import PanApiHandler
from scm.process import Processor, SCMObjectManager


class FakeResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self):
        self.get_calls = []
        self.post_calls = []
        self.put_calls = []
        self.get_response = FakeResponse(200, {"data": []})
        self.post_response = FakeResponse(201, {"id": "created"})
        self.put_response = FakeResponse(200, {"id": "updated"})

    def ensure_valid_token(self):
        pass

    def get(self, url, params=None, timeout=20):
        self.get_calls.append({"url": url, "params": params, "timeout": timeout})
        return self.get_response

    def post(self, url, json=None, timeout=20):
        self.post_calls.append({"url": url, "json": json, "timeout": timeout})
        return self.post_response

    def put(self, url, json=None, timeout=20):
        self.put_calls.append({"url": url, "json": json, "timeout": timeout})
        return self.put_response


class EndpointRegistryTests(unittest.TestCase):
    def test_core_object_endpoints_are_modern_and_payload_scoped(self):
        self.assertEqual(obj.Address.get_endpoint(), "/config/objects/v1/addresses")
        self.assertEqual(obj.Tag.get_endpoint(), "/config/objects/v1/tags")
        self.assertTrue(obj.Address.uses_payload_scope())
        self.assertTrue(obj.ServiceGroup.uses_payload_scope())

    def test_zones_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.Zones.get_endpoint(), "/config/network/v1/zones")
        self.assertTrue(obj.Zones.uses_payload_scope())

    def test_interface_management_profile_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.InterfaceManagementProfile.get_endpoint(), "/config/network/v1/interface-management-profiles")
        self.assertTrue(obj.InterfaceManagementProfile.uses_payload_scope())

    def test_zone_protection_profile_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.ZoneProtectionProfile.get_endpoint(), "/config/network/v1/zone-protection-profiles")
        self.assertTrue(obj.ZoneProtectionProfile.uses_payload_scope())

    def test_dhcp_interface_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.DHCPInterface.get_endpoint(), "/config/network/v1/dhcp-interfaces")
        self.assertTrue(obj.DHCPInterface.uses_payload_scope())

    def test_aggregate_interface_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.AggregateInterface.get_endpoint(), "/config/network/v1/aggregate-interfaces")
        self.assertTrue(obj.AggregateInterface.uses_payload_scope())

    def test_ethernet_interface_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.EthernetInterface.get_endpoint(), "/config/network/v1/ethernet-interfaces")
        self.assertTrue(obj.EthernetInterface.uses_payload_scope())

    def test_layer3_subinterface_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.Layer3Subinterface.get_endpoint(), "/config/network/v1/layer3-subinterfaces")
        self.assertTrue(obj.Layer3Subinterface.uses_payload_scope())

    def test_layer2_subinterface_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.Layer2Subinterface.get_endpoint(), "/config/network/v1/layer2-subinterfaces")
        self.assertTrue(obj.Layer2Subinterface.uses_payload_scope())

    def test_vlan_and_tunnel_interface_endpoints_are_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.VlanInterface.get_endpoint(), "/config/network/v1/vlan-interfaces")
        self.assertEqual(obj.TunnelInterface.get_endpoint(), "/config/network/v1/tunnel-interfaces")
        self.assertTrue(obj.VlanInterface.uses_payload_scope())
        self.assertTrue(obj.TunnelInterface.uses_payload_scope())

    def test_loopback_interface_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.LoopbackInterface.get_endpoint(), "/config/network/v1/loopback-interfaces")
        self.assertTrue(obj.LoopbackInterface.uses_payload_scope())

    def test_logical_router_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.LogicalRouter.get_endpoint(), "/config/network/v1/logical-routers")
        self.assertTrue(obj.LogicalRouter.uses_payload_scope())

    def test_route_filter_endpoints_are_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.RoutePrefixList.get_endpoint(), "/config/network/v1/route-prefix-lists")
        self.assertEqual(obj.BgpRouteMap.get_endpoint(), "/config/network/v1/bgp-route-maps")
        self.assertTrue(obj.RoutePrefixList.uses_payload_scope())
        self.assertTrue(obj.BgpRouteMap.uses_payload_scope())

    def test_vpn_object_endpoints_are_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.IKECryptoProfile.get_endpoint(), "/config/network/v1/ike-crypto-profiles")
        self.assertEqual(obj.IPsecCryptoProfile.get_endpoint(), "/config/network/v1/ipsec-crypto-profiles")
        self.assertEqual(obj.IKEGateway.get_endpoint(), "/config/network/v1/ike-gateways")
        self.assertEqual(obj.IPsecTunnel.get_endpoint(), "/config/network/v1/ipsec-tunnels")
        self.assertTrue(obj.IKECryptoProfile.uses_payload_scope())
        self.assertTrue(obj.IPsecCryptoProfile.uses_payload_scope())
        self.assertTrue(obj.IKEGateway.uses_payload_scope())
        self.assertTrue(obj.IPsecTunnel.uses_payload_scope())

    def test_pbf_rule_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.PbfRule.get_endpoint(), "/config/network/v1/pbf-rules")
        self.assertTrue(obj.PbfRule.uses_payload_scope())


class PanApiHandlerTests(unittest.TestCase):
    def test_get_uses_strata_base_url_and_query_params(self):
        session = FakeSession()
        handler = PanApiHandler(session)

        handler.get("/config/objects/v1/addresses", params={"folder": "All", "limit": 100})

        self.assertEqual(
            session.get_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/objects/v1/addresses",
        )
        self.assertEqual(session.get_calls[0]["params"], {"folder": "All", "limit": 100})

    def test_post_returns_created_status(self):
        session = FakeSession()
        handler = PanApiHandler(session)

        result = handler.post("/config/objects/v1/addresses", {"name": "addr"})

        self.assertEqual(result["status"], "created")


class ProcessorTests(unittest.TestCase):
    def test_core_object_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&folder=All", obj, [obj.Address], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&folder=All",
            [{"name": "addr", "fqdn": "example.com"}],
            obj.Address,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/objects/v1/addresses",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {"name": "addr", "fqdn": "example.com", "folder": "All"},
        )

    def test_fetch_objects_uses_query_scope(self):
        session = FakeSession()
        session.get_response = FakeResponse(200, {"data": [{"name": "addr", "folder": "All"}]})
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&folder=All", obj, [obj.Address], obj.SecurityRule, obj.NatRule)

        objects = manager.fetch_objects(obj.Address, limit="100")

        self.assertEqual(objects, [{"name": "addr", "folder": "All"}])
        self.assertEqual(session.get_calls[0]["params"]["folder"], "All")
        self.assertNotIn("folder", session.get_calls[0]["url"])

    def test_zone_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.Zones], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "trust", "network": {"layer3": ["ethernet1/1"]}}],
            obj.Zones,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/zones",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {"name": "trust", "network": {"layer3": ["ethernet1/1"]}, "snippet": "Network-Stack"},
        )

    def test_interface_management_profile_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.InterfaceManagementProfile], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "allow-mgmt", "ping": True, "permitted_ip": ["192.0.2.0/24"]}],
            obj.InterfaceManagementProfile,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/interface-management-profiles",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "allow-mgmt",
                "ping": True,
                "permitted_ip": ["192.0.2.0/24"],
                "snippet": "Network-Stack",
            },
        )

    def test_zone_protection_profile_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.ZoneProtectionProfile], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "internet-zpp", "description": "edge"}],
            obj.ZoneProtectionProfile,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/zone-protection-profiles",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "internet-zpp",
                "description": "edge",
                "snippet": "Network-Stack",
            },
        )

    def test_dhcp_interface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.DHCPInterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "vlan.100", "server": {"ip_pool": ["10.100.0.10-10.100.0.200"]}}],
            obj.DHCPInterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/dhcp-interfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "vlan.100",
                "server": {"ip_pool": ["10.100.0.10-10.100.0.200"]},
                "snippet": "Network-Stack",
            },
        )

    def test_aggregate_interface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.AggregateInterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "$ae1", "default_value": "ae1", "layer3": {"ip": [{"name": "198.51.100.1/24"}]}}],
            obj.AggregateInterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/aggregate-interfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "$ae1",
                "default_value": "ae1",
                "layer3": {"ip": [{"name": "198.51.100.1/24"}]},
                "snippet": "Network-Stack",
            },
        )

    def test_ethernet_interface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.EthernetInterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "$ethernet1-1", "default_value": "ethernet1/1", "layer3": {"ip": [{"name": "203.0.113.1/24"}]}}],
            obj.EthernetInterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/ethernet-interfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "$ethernet1-1",
                "default_value": "ethernet1/1",
                "layer3": {"ip": [{"name": "203.0.113.1/24"}]},
                "snippet": "Network-Stack",
            },
        )

    def test_layer3_subinterface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.Layer3Subinterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "ethernet1/1.100", "parent_interface": "ethernet1/1", "tag": 100}],
            obj.Layer3Subinterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/layer3-subinterfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "ethernet1/1.100",
                "parent_interface": "ethernet1/1",
                "tag": 100,
                "snippet": "Network-Stack",
            },
        )

    def test_layer2_subinterface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.Layer2Subinterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "ethernet1/6.200", "parent_interface": "ethernet1/6", "tag": 200}],
            obj.Layer2Subinterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/layer2-subinterfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "ethernet1/6.200",
                "parent_interface": "ethernet1/6",
                "tag": 200,
                "snippet": "Network-Stack",
            },
        )

    def test_vlan_interface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.VlanInterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "vlan.100", "vlan_tag": "100", "ip": [{"name": "10.100.0.1/24"}]}],
            obj.VlanInterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/vlan-interfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "vlan.100",
                "vlan_tag": "100",
                "ip": [{"name": "10.100.0.1/24"}],
                "snippet": "Network-Stack",
            },
        )

    def test_tunnel_interface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.TunnelInterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "tunnel.1", "default_value": "tunnel.1", "ip": [{"name": "169.254.1.1/30"}]}],
            obj.TunnelInterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/tunnel-interfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "tunnel.1",
                "default_value": "tunnel.1",
                "ip": [{"name": "169.254.1.1/30"}],
                "snippet": "Network-Stack",
            },
        )

    def test_loopback_interface_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.LoopbackInterface], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "loopback.1", "ip": ["10.255.0.1/32"]}],
            obj.LoopbackInterface,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/loopback-interfaces",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "loopback.1",
                "ip": ["10.255.0.1/32"],
                "snippet": "Network-Stack",
            },
        )

    def test_logical_router_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.LogicalRouter], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "default", "routing_stack": "advanced", "vrf": [{"name": "default"}]}],
            obj.LogicalRouter,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/logical-routers",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "default",
                "routing_stack": "advanced",
                "vrf": [{"name": "default"}],
                "snippet": "Network-Stack",
            },
        )

    def test_route_prefix_list_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.RoutePrefixList], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "default-export-default-pl", "prefix_list": [{"name": 1, "action": "permit", "prefix": "0.0.0.0/0"}]}],
            obj.RoutePrefixList,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/route-prefix-lists",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "default-export-default-pl",
                "prefix_list": [{"name": 1, "action": "permit", "prefix": "0.0.0.0/0"}],
                "snippet": "Network-Stack",
            },
        )

    def test_bgp_route_map_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.BgpRouteMap], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "default-export-default-rm", "route_map": [{"name": 10, "action": "permit"}]}],
            obj.BgpRouteMap,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/bgp-route-maps",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "default-export-default-rm",
                "route_map": [{"name": 10, "action": "permit"}],
                "snippet": "Network-Stack",
            },
        )

    def test_vpn_object_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.IPsecTunnel], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [
                {
                    "name": "vpn-tunnel-a",
                    "tunnel_interface": "tunnel.1",
                    "auto_key": {
                        "ike_gateway": [{"name": "vpn-gw-a"}],
                        "ipsec_crypto_profile": "ipsec-crypto-a",
                    },
                }
            ],
            obj.IPsecTunnel,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/ipsec-tunnels",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "vpn-tunnel-a",
                "tunnel_interface": "tunnel.1",
                "auto_key": {
                    "ike_gateway": [{"name": "vpn-gw-a"}],
                    "ipsec_crypto_profile": "ipsec-crypto-a",
                },
                "snippet": "Network-Stack",
            },
        )

    def test_pbf_rule_post_puts_scope_in_payload_not_url(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj.PbfRule], obj.SecurityRule, obj.NatRule)

        manager.configure.post_entries(
            "&snippet=Network-Stack",
            [{"name": "send-guest-to-isp2", "action": {"forwarding": {"egress_interface": "ethernet1/2"}}}],
            obj.PbfRule,
            extra_query_params="",
        )

        self.assertEqual(
            session.post_calls[0]["url"],
            "https://api.strata.paloaltonetworks.com/config/network/v1/pbf-rules",
        )
        self.assertEqual(
            session.post_calls[0]["json"],
            {
                "name": "send-guest-to-isp2",
                "action": {"forwarding": {"egress_interface": "ethernet1/2"}},
                "snippet": "Network-Stack",
            },
        )

    def test_analyze_results_counts_modern_statuses(self):
        processor = Processor(None, 1, obj, None)

        _, exists_count, error_count, error_objects = processor.analyze_results(
            [
                {"status": "created", "name": "created"},
                {"status": "exists", "name": "exists"},
                {"status": "error", "name": "bad"},
                {"status": "exception", "name": "boom"},
            ]
        )

        self.assertEqual(exists_count, 1)
        self.assertEqual(error_count, 2)
        self.assertEqual(error_objects, ["bad", "boom"])


if __name__ == "__main__":
    unittest.main()
