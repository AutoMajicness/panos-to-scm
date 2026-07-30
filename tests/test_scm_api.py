import unittest

import scm.obj as obj
from scm import ApiRequestError, PanApiHandler
from scm.process import Processor, SCMObjectManager, order_object_types_for_dependencies


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


class FailingObjectFetchHandler:
    def get(self, endpoint, params=None):
        if endpoint == obj.Application.get_endpoint():
            raise ApiRequestError("applications endpoint failed")
        return [{"name": "existing-object"}]


class RuleMoveHandler:
    def __init__(self):
        self.post_calls = []
        self.fetch_count = 0

    def get(self, endpoint, params=None):
        self.fetch_count += 1
        if self.fetch_count == 1:
            return [
                {"id": "rule-b", "name": "rule-b", "folder": "All"},
                {"id": "rule-a", "name": "rule-a", "folder": "All"},
            ]
        return [
            {"id": "rule-a", "name": "rule-a", "folder": "All"},
            {"id": "rule-b", "name": "rule-b", "folder": "All"},
        ]

    def post(self, endpoint, item_data, retries=2, delay=0.5):
        self.post_calls.append({"endpoint": endpoint, "item_data": item_data})
        return {"status": "created", "message": "Object created", "name": None}


class MixedRulebaseHandler:
    def get(self, endpoint, params=None):
        return [
            {"id": "default-a", "name": "Web-Security-Default", "folder": "All"},
            {"id": "default-b", "name": "hip-default", "folder": "All"},
            {"id": "rule-a", "name": "rule-a", "folder": "All"},
            {"id": "rule-b", "name": "rule-b", "folder": "All"},
        ]


class FallbackFetchSession:
    def __init__(self):
        self.get_calls = []

    def ensure_valid_token(self):
        pass

    def get(self, url, params=None, timeout=20):
        self.get_calls.append({"url": url, "params": dict(params or {}), "timeout": timeout})
        if params and params.get("limit", 0) > 500:
            return FakeResponse(502, {"fault": {"faultstring": "Body buffer overflow"}}, "too big")
        return FakeResponse(200, {"data": [{"name": "tenant-object"}]})


class EndpointRegistryTests(unittest.TestCase):
    def test_core_object_endpoints_are_modern_and_payload_scoped(self):
        self.assertEqual(obj.Address.get_endpoint(), "/config/objects/v1/addresses")
        self.assertEqual(obj.Tag.get_endpoint(), "/config/objects/v1/tags")
        self.assertTrue(obj.Address.uses_payload_scope())
        self.assertTrue(obj.ServiceGroup.uses_payload_scope())

    def test_network_object_types_are_ordered_for_post_dependencies(self):
        unordered = [
            obj.LogicalRouter,
            obj.BgpFilteringProfile,
            obj.BgpRouteMap,
            obj.RoutePrefixList,
            obj.IPsecTunnel,
            obj.IKEGateway,
            obj.IKECryptoProfile,
            obj.EthernetInterface,
            obj.DHCPInterface,
            obj.Zones,
        ]

        ordered = order_object_types_for_dependencies(unordered)

        self.assertEqual(
            [object_type.__name__ for object_type in ordered],
            [
                "EthernetInterface",
                "DHCPInterface",
                "Zones",
                "RoutePrefixList",
                "BgpRouteMap",
                "BgpFilteringProfile",
                "IKECryptoProfile",
                "IKEGateway",
                "IPsecTunnel",
                "LogicalRouter",
            ],
        )

    def test_scm_object_manager_applies_network_dependency_order(self):
        session = FakeSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(
            handler,
            "&snippet=Network-Stack",
            obj,
            [obj.LogicalRouter, obj.IPsecTunnel, obj.IKEGateway, obj.EthernetInterface],
            obj.SecurityRule,
            obj.NatRule,
        )

        self.assertEqual(
            [object_type.__name__ for object_type in manager.obj_types],
            ["EthernetInterface", "IKEGateway", "IPsecTunnel", "LogicalRouter"],
        )

    def test_current_object_fetch_continues_when_one_object_type_fails(self):
        manager = SCMObjectManager(
            FailingObjectFetchHandler(),
            "&folder=All",
            obj,
            [obj.Address, obj.Application],
            obj.SecurityRule,
            obj.NatRule,
        )

        current_objects = manager.get_current_objects(manager.obj_types, max_workers=2)

        self.assertEqual(current_objects[obj.Address], [{"name": "existing-object"}])
        self.assertEqual(current_objects[obj.Application], [])
        self.assertEqual(manager.fetch_failures[0]["object_type"], "Application")

    def test_noninteractive_conflict_uses_replace_policy(self):
        manager = SCMObjectManager(
            FailingObjectFetchHandler(),
            "&folder=All",
            obj,
            [obj.Address],
            obj.SecurityRule,
            obj.NatRule,
            conflict_policy="replace",
            interactive=False,
        )

        resolved = manager.resolve_conflicts(
            {"name": "addr-a", "ip_netmask": "192.0.2.10"},
            {"name": "addr-a", "ip_netmask": "192.0.2.11"},
        )

        self.assertEqual(resolved, {"name": "addr-a", "ip_netmask": "192.0.2.10"})

    def test_rule_reorder_verification_accepts_created_move_response(self):
        manager = SCMObjectManager(
            RuleMoveHandler(),
            "&folder=All",
            obj,
            [],
            obj.SecurityRule,
            obj.NatRule,
        )

        report = manager.configure.check_and_reorder_rules(
            obj.SecurityRule,
            "&folder=All",
            [{"name": "rule-a"}, {"name": "rule-b"}],
            limit="10000",
            position="pre",
        )

        self.assertTrue(report["reordered"])
        self.assertTrue(report["verified"])
        self.assertEqual(report["move_attempts"], 1)
        self.assertEqual(report["move_failures"], [])

    def test_rule_order_verification_accepts_migrated_rules_after_system_rules(self):
        manager = SCMObjectManager(
            MixedRulebaseHandler(),
            "&folder=All",
            obj,
            [],
            obj.SecurityRule,
            obj.NatRule,
        )

        report = manager.configure.check_and_reorder_rules(
            obj.SecurityRule,
            "&folder=All",
            [{"name": "rule-a"}, {"name": "rule-b"}],
            limit="10000",
            position="pre",
        )

        self.assertTrue(report["verified"])
        self.assertFalse(report["reordered"])
        self.assertEqual(report["verification_mode"], "relative-subsequence")
        self.assertEqual(report["matched_rule_count"], 2)

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

    def test_ospf_auth_profile_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.OSPFAuthProfile.get_endpoint(), "/config/network/v1/ospf-auth-profiles")
        self.assertTrue(obj.OSPFAuthProfile.uses_payload_scope())

    def test_bgp_auth_profile_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.BgpAuthProfile.get_endpoint(), "/config/network/v1/bgp-auth-profiles")
        self.assertTrue(obj.BgpAuthProfile.uses_payload_scope())

    def test_bgp_address_family_profile_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.BgpAddressFamilyProfile.get_endpoint(), "/config/network/v1/bgp-address-family-profiles")
        self.assertTrue(obj.BgpAddressFamilyProfile.uses_payload_scope())

    def test_bgp_filtering_profile_endpoint_is_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.BgpFilteringProfile.get_endpoint(), "/config/network/v1/bgp-filtering-profiles")
        self.assertTrue(obj.BgpFilteringProfile.uses_payload_scope())

    def test_route_filter_endpoints_are_modern_network_api_and_payload_scoped(self):
        self.assertEqual(obj.RoutePrefixList.get_endpoint(), "/config/network/v1/route-prefix-lists")
        self.assertEqual(obj.RouteAccessList.get_endpoint(), "/config/network/v1/route-access-lists")
        self.assertEqual(obj.RouteCommunityList.get_endpoint(), "/config/network/v1/route-community-lists")
        self.assertEqual(obj.RoutePathAccessList.get_endpoint(), "/config/network/v1/route-path-access-lists")
        self.assertEqual(obj.BgpRouteMap.get_endpoint(), "/config/network/v1/bgp-route-maps")
        self.assertEqual(obj.BgpRouteMapRedistribution.get_endpoint(), "/config/network/v1/bgp-route-map-redistributions")
        self.assertEqual(obj.BgpRedistributionProfile.get_endpoint(), "/config/network/v1/bgp-redistribution-profiles")
        self.assertTrue(obj.RoutePrefixList.uses_payload_scope())
        self.assertTrue(obj.RouteAccessList.uses_payload_scope())
        self.assertTrue(obj.RouteCommunityList.uses_payload_scope())
        self.assertTrue(obj.RoutePathAccessList.uses_payload_scope())
        self.assertTrue(obj.BgpRouteMap.uses_payload_scope())
        self.assertTrue(obj.BgpRouteMapRedistribution.uses_payload_scope())
        self.assertTrue(obj.BgpRedistributionProfile.uses_payload_scope())

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

    def test_get_raises_api_request_error_with_status_and_body(self):
        session = FakeSession()
        session.get_response = FakeResponse(400, {"_errors": [{"message": "bad scope"}]}, "bad scope")
        handler = PanApiHandler(session)

        with self.assertRaisesRegex(Exception, "Status Code: 400"):
            handler.get("/config/network/v1/zones", params={"snippet": "missing"})

    def test_post_returns_created_status(self):
        session = FakeSession()
        handler = PanApiHandler(session)

        result = handler.post("/config/objects/v1/addresses", {"name": "addr"})

        self.assertEqual(result["status"], "created")

    def test_post_treats_scm_name_not_unique_as_exists(self):
        session = FakeSession()
        session.post_response = FakeResponse(
            409,
            {
                "_errors": [
                    {
                        "details": {
                            "errorType": "Name Not Unique",
                            "message": "snippet with the same name already exists",
                        }
                    }
                ]
            },
        )
        handler = PanApiHandler(session)

        result = handler.post("/config/setup/v1/snippets", {"name": "FW1-network"})

        self.assertEqual(result["status"], "exists")


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

    def test_fetch_objects_retries_with_smaller_page_size_after_large_response_failure(self):
        session = FallbackFetchSession()
        handler = PanApiHandler(session)
        manager = SCMObjectManager(handler, "&folder=All", obj, [obj.Address], obj.SecurityRule, obj.NatRule)

        objects = manager.fetch_objects(obj.Address, limit="1000")

        self.assertEqual(objects, [{"name": "tenant-object"}])
        self.assertEqual([call["params"]["limit"] for call in session.get_calls], [1000, 1000, 500])

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
            [{"name": "allow-mgmt", "ping": True, "permitted_ip": [{"name": "192.0.2.0/24"}]}],
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
                "permitted_ip": [{"name": "192.0.2.0/24"}],
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
            [{"name": "$ethernet1-1.100", "parent_interface": "ethernet1/1", "tag": 100}],
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
                "name": "$ethernet1-1.100",
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
            [{"name": "$ethernet1-6.200", "parent_interface": "ethernet1/6", "tag": 200}],
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
                "name": "$ethernet1-6.200",
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
            [{"name": "$tunnel1", "default_value": "tunnel.1", "ip": [{"name": "169.254.1.1/30"}]}],
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
                "name": "$tunnel1",
                "default_value": "tunnel.1",
                "ip": [{"name": "169.254.1.1/30"}],
                "snippet": "Network-Stack",
            },
        )

    def test_interface_management_profile_normalizes_permitted_ip_entries(self):
        manager = SCMObjectManager(FailingObjectFetchHandler(), "&snippet=Network-Stack", obj, [], obj.SecurityRule, obj.NatRule)

        normalized = manager._normalize_entry_for_post(
            "InterfaceManagementProfile",
            {"name": "allow-mgmt", "permitted_ip": ["192.0.2.0/24"]},
            {},
        )

        self.assertEqual(
            normalized["permitted_ip"],
            [{"name": "192.0.2.0/24"}],
        )

    def test_network_object_normalization_rewrites_interface_references(self):
        manager = SCMObjectManager(FailingObjectFetchHandler(), "&snippet=Network-Stack", obj, [], obj.SecurityRule, obj.NatRule)
        aliases = {
            "ethernet1/1": "$ethernet1-1",
            "ethernet1/4": "$ethernet1-4",
            "ethernet1/4.2": "$ethernet1-4.2",
            "tunnel.1": "$tunnel1",
        }

        subinterface = manager._normalize_entry_for_post(
            "Layer3Subinterface",
            {"name": "$ethernet1-4.2", "parent_interface": "ethernet1/4", "tag": 2},
            aliases,
        )
        zone = manager._normalize_entry_for_post(
            "Zones",
            {"name": "Trust", "network": {"layer3": ["ethernet1/1", "ethernet1/4.2", "tunnel.1"]}},
            aliases,
        )
        ike_gateway = manager._normalize_entry_for_post(
            "IKEGateway",
            {"name": "gw-a", "local_address": {"interface": "ethernet1/1", "ip": "203.0.113.10/29"}},
            aliases,
        )
        ipsec_tunnel = manager._normalize_entry_for_post(
            "IPsecTunnel",
            {"name": "vpn-a", "tunnel_interface": "tunnel.1"},
            aliases,
        )
        logical_router = manager._normalize_entry_for_post(
            "LogicalRouter",
            {
                "name": "default",
                "vrf": [
                    {
                        "name": "default",
                        "interface": ["ethernet1/1", "ethernet1/4.2", "tunnel.1"],
                        "routing_table": {
                            "ip": {
                                "static_route": [
                                    {"name": "default-route", "interface": "ethernet1/1"},
                                    {"name": "vpn-route", "interface": "tunnel.1"},
                                ]
                            }
                        },
                    }
                ],
            },
            aliases,
        )

        self.assertEqual(subinterface["name"], "$ethernet1-4.2")
        self.assertEqual(subinterface["parent_interface"], "$ethernet1-4")
        self.assertEqual(zone["network"]["layer3"], ["$ethernet1-1", "$ethernet1-4.2", "$tunnel1"])
        self.assertEqual(ike_gateway["local_address"]["interface"], "$ethernet1-1")
        self.assertEqual(ipsec_tunnel["tunnel_interface"], "$tunnel1")
        self.assertEqual(
            logical_router["vrf"][0]["interface"],
            ["$ethernet1-1", "$ethernet1-4.2", "$tunnel1"],
        )
        self.assertEqual(
            [route["interface"] for route in logical_router["vrf"][0]["routing_table"]["ip"]["static_route"]],
            ["$ethernet1-1", "$tunnel1"],
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

    def test_route_access_community_path_and_redist_post_put_scope_in_payload(self):
        cases = [
            (
                obj.OSPFAuthProfile,
                "/config/network/v1/ospf-auth-profiles",
                {"name": "ospf-simple", "password": "ospf-secret"},
            ),
            (
                obj.BgpAuthProfile,
                "/config/network/v1/bgp-auth-profiles",
                {"name": "bgp-md5", "secret": "bgp-secret"},
            ),
            (
                obj.BgpAddressFamilyProfile,
                "/config/network/v1/bgp-address-family-profiles",
                {"name": "default-upstream-ipv4-af", "ipv4": {"unicast": {"send_community": {"both": {}}}}},
            ),
            (
                obj.BgpFilteringProfile,
                "/config/network/v1/bgp-filtering-profiles",
                {"name": "default-ipv4-bgp-filtering", "ipv4": {"unicast": {"route_maps": {"inbound": "import-rm"}}}},
            ),
            (
                obj.RouteAccessList,
                "/config/network/v1/route-access-lists",
                {"name": "routes-acl", "access_list": [{"name": 1, "action": "permit", "source": "corp-routes"}]},
            ),
            (
                obj.RouteCommunityList,
                "/config/network/v1/route-community-lists",
                {"name": "communities", "community_list": [{"name": 1, "action": "permit", "community": "65001:100"}]},
            ),
            (
                obj.RoutePathAccessList,
                "/config/network/v1/route-path-access-lists",
                {"name": "as-paths", "path_access_list": [{"name": 1, "action": "permit", "regular_expression": "^65010_"}]},
            ),
            (
                obj.BgpRouteMapRedistribution,
                "/config/network/v1/bgp-route-map-redistributions",
                {"name": "redist-rm", "route_map": [{"name": 10, "action": "permit"}]},
            ),
            (
                obj.BgpRedistributionProfile,
                "/config/network/v1/bgp-redistribution-profiles",
                {"name": "redist-profile", "ipv4": {"unicast": {"static": {"enable": True}}}},
            ),
        ]

        for obj_type, endpoint, payload in cases:
            with self.subTest(obj_type=obj_type.__name__):
                session = FakeSession()
                handler = PanApiHandler(session)
                manager = SCMObjectManager(handler, "&snippet=Network-Stack", obj, [obj_type], obj.SecurityRule, obj.NatRule)

                manager.configure.post_entries("&snippet=Network-Stack", [payload], obj_type, extra_query_params="")

                self.assertEqual(session.post_calls[0]["url"], f"https://api.strata.paloaltonetworks.com{endpoint}")
                self.assertEqual(session.post_calls[0]["json"], {**payload, "snippet": "Network-Stack"})

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
