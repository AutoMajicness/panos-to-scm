import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from config import AppConfig


class MainDryRunTests(unittest.TestCase):
    def test_dry_run_writes_plan_output_with_current_data(self):
        parsed_data = {
            "Address": [
                {"name": "same", "ip_netmask": "192.0.2.10"},
                {"name": "changed", "ip_netmask": "192.0.2.20"},
            ]
        }
        current_data = {
            "Address": [
                {"name": "same", "ip_netmask": "192.0.2.10", "folder": "All"},
                {"name": "changed", "ip_netmask": "192.0.2.21"},
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            parsed_path = directory_path / "parsed.json"
            current_path = directory_path / "current.json"
            output_path = directory_path / "plan.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")
            current_path.write_text(json.dumps(current_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Address",
                    json_file=str(parsed_path),
                    dry_run=True,
                    scope="folder:All",
                    current_data_file=str(current_path),
                    plan_output=str(output_path),
                )

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(plan.summary()["skips"], 1)
        self.assertEqual(plan.summary()["conflicts"], 1)
        self.assertEqual(report["summary"]["skips"], 1)
        self.assertEqual(report["summary"]["conflicts"], 1)
        self.assertEqual(report["skips"][0]["name"], "same")
        self.assertEqual(report["conflicts"][0]["name"], "changed")

    def test_dry_run_requires_scope_without_interactive(self):
        parsed_data = {"Address": [{"name": "addr", "ip_netmask": "192.0.2.10"}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("builtins.input") as input_mock:
                with self.assertRaises(SystemExit):
                    main.main(AppConfig(), json_file=str(parsed_path), dry_run=True)

        input_mock.assert_not_called()

    def test_config_file_json_source_works_for_dry_run(self):
        parsed_data = {"Address": [{"name": "addr", "ip_netmask": "192.0.2.10"}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Address",
                    config_file=str(parsed_path),
                    dry_run=True,
                    scope="folder:All",
                )

        self.assertEqual(plan.summary()["creates"], 1)

    def test_zones_can_be_selected_for_dry_run(self):
        parsed_data = {"Zones": [{"name": "trust", "network": {"layer3": ["ethernet1/1"]}}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Zones",
                    json_file=str(parsed_path),
                    dry_run=True,
                    scope="folder:All",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "Zones")

    def test_zones_can_use_network_scope_without_default_scope(self):
        parsed_data = {"Zones": [{"name": "trust", "network": {"layer3": ["ethernet1/1"]}}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Zones",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "Zones")

    def test_ethernet_interfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {
            "EthernetInterface": [
                {
                    "name": "$ethernet1-1",
                    "default_value": "ethernet1/1",
                    "layer3": {"ip": [{"name": "203.0.113.1/24"}]},
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="EthernetInterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "EthernetInterface")

    def test_ethernet_interfaces_and_zones_can_share_network_scope(self):
        parsed_data = {
            "InterfaceManagementProfile": [{"name": "allow-mgmt", "ping": True}],
            "ZoneProtectionProfile": [{"name": "internet-zpp", "description": "edge"}],
            "DHCPInterface": [{"name": "vlan.100", "server": {"ip_pool": ["10.100.0.10-10.100.0.200"]}}],
            "AggregateInterface": [{"name": "$ae1", "default_value": "ae1", "layer3": {}}],
            "EthernetInterface": [
                {
                    "name": "$ethernet1-1",
                    "default_value": "ethernet1/1",
                    "layer3": {"dhcp_client": {"enable": True}},
                }
            ],
            "Zones": [{"name": "trust", "network": {"layer3": ["ethernet1/1"]}}],
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="EthernetInterface,Zones",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 2)
        self.assertEqual([change.object_type for change in plan.creates], ["EthernetInterface", "Zones"])

    def test_layer3_subinterfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {
            "Layer3Subinterface": [
                {
                    "name": "ethernet1/1.100",
                    "parent_interface": "ethernet1/1",
                    "tag": 100,
                    "ip": [{"name": "10.100.0.1/24"}],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Layer3Subinterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "Layer3Subinterface")

    def test_ethernet_subinterfaces_and_zones_can_share_network_scope(self):
        parsed_data = {
            "AggregateInterface": [{"name": "$ae1", "default_value": "ae1", "layer3": {}}],
            "EthernetInterface": [{"name": "$ethernet1-1", "default_value": "ethernet1/1", "layer3": {}}],
            "Layer3Subinterface": [{"name": "ethernet1/1.100", "parent_interface": "ethernet1/1", "tag": 100}],
            "Zones": [{"name": "users", "network": {"layer3": ["ethernet1/1.100"]}}],
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="EthernetInterface,Layer3Subinterface,Zones",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 3)
        self.assertEqual(
            [change.object_type for change in plan.creates],
            ["EthernetInterface", "Layer3Subinterface", "Zones"],
        )

    def test_logical_routers_can_use_network_scope_for_dry_run(self):
        parsed_data = {
            "LogicalRouter": [
                {
                    "name": "default",
                    "routing_stack": "advanced",
                    "vrf": [{"name": "default", "interface": ["ethernet1/1"]}],
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="LogicalRouter",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "LogicalRouter")

    def test_full_network_stack_can_share_network_scope(self):
        parsed_data = {
            "InterfaceManagementProfile": [{"name": "allow-mgmt", "ping": True}],
            "ZoneProtectionProfile": [{"name": "internet-zpp", "description": "edge"}],
            "DHCPInterface": [{"name": "vlan.100", "server": {"ip_pool": ["10.100.0.10-10.100.0.200"]}}],
            "AggregateInterface": [{"name": "$ae1", "default_value": "ae1", "layer3": {}}],
            "EthernetInterface": [
                {
                    "name": "$ethernet1-1",
                    "default_value": "ethernet1/1",
                    "layer3": {"dhcp_client": {"enable": True}},
                }
            ],
            "Layer2Subinterface": [{"name": "ethernet1/6.200", "parent_interface": "ethernet1/6", "tag": 200}],
            "Layer3Subinterface": [{"name": "ethernet1/1.100", "parent_interface": "ethernet1/1", "tag": 100}],
            "VlanInterface": [{"name": "vlan.100", "vlan_tag": "100", "ip": [{"name": "10.100.0.1/24"}]}],
            "TunnelInterface": [{"name": "tunnel.1", "default_value": "tunnel.1", "ip": [{"name": "169.254.1.1/30"}]}],
            "LoopbackInterface": [{"name": "loopback.1", "ip": ["10.255.0.1/32"]}],
            "OSPFAuthProfile": [{"name": "ospf-simple", "password": "ospf-secret"}],
            "LogicalRouter": [{"name": "default", "routing_stack": "advanced", "vrf": [{"name": "default"}]}],
            "RoutePrefixList": [{"name": "default-export-default-pl", "prefix_list": [{"name": 1, "action": "permit", "prefix": "0.0.0.0/0"}]}],
            "RouteAccessList": [{"name": "routes-acl", "access_list": [{"name": 1, "action": "permit", "source": "corp-routes"}]}],
            "RouteCommunityList": [{"name": "communities", "community_list": [{"name": 1, "action": "permit", "community": "65001:100"}]}],
            "RoutePathAccessList": [{"name": "as-paths", "path_access_list": [{"name": 1, "action": "permit", "regular_expression": "^65010_"}]}],
            "BgpRouteMap": [{"name": "default-export-default-rm", "route_map": [{"name": 10, "action": "permit"}]}],
            "BgpRouteMapRedistribution": [{"name": "redist-rm", "route_map": [{"name": 10, "action": "permit"}]}],
            "BgpRedistributionProfile": [{"name": "redist-profile", "ipv4": {"unicast": {"static": {"enable": True}}}}],
            "IKECryptoProfile": [{"name": "ike-crypto-a", "hash": ["sha256"], "encryption": ["aes-256-cbc"], "dh_group": ["group14"]}],
            "IPsecCryptoProfile": [{"name": "ipsec-crypto-a", "esp": {"encryption": ["aes-256-gcm"]}}],
            "IKEGateway": [{"name": "vpn-gw-a", "protocol": {"ikev2": {"ike_crypto_profile": "ike-crypto-a"}}}],
            "IPsecTunnel": [{"name": "vpn-tunnel-a", "tunnel_interface": "tunnel.1"}],
            "PbfRule": [{"name": "send-guest-to-isp2", "action": {"forwarding": {"egress_interface": "ethernet1/2"}}}],
            "Zones": [{"name": "users", "network": {"layer3": ["ethernet1/1.100"]}}],
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="InterfaceManagementProfile,ZoneProtectionProfile,DHCPInterface,AggregateInterface,EthernetInterface,Layer2Subinterface,Layer3Subinterface,VlanInterface,TunnelInterface,LoopbackInterface,OSPFAuthProfile,RoutePrefixList,RouteAccessList,RouteCommunityList,RoutePathAccessList,BgpRouteMap,BgpRouteMapRedistribution,BgpRedistributionProfile,LogicalRouter,IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel,PbfRule,Zones",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 25)
        self.assertEqual(
            [change.object_type for change in plan.creates],
            [
                "InterfaceManagementProfile", "ZoneProtectionProfile", "DHCPInterface",
                "AggregateInterface", "EthernetInterface", "Layer2Subinterface", "Layer3Subinterface",
                "VlanInterface", "TunnelInterface", "LoopbackInterface", "OSPFAuthProfile", "RoutePrefixList",
                "RouteAccessList", "RouteCommunityList", "RoutePathAccessList", "BgpRouteMap",
                "BgpRouteMapRedistribution", "BgpRedistributionProfile", "LogicalRouter",
                "IKECryptoProfile", "IPsecCryptoProfile", "IKEGateway", "IPsecTunnel",
                "PbfRule", "Zones"
            ],
        )

    def test_interface_management_profiles_can_use_network_scope_for_dry_run(self):
        parsed_data = {"InterfaceManagementProfile": [{"name": "allow-mgmt", "ping": True}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="InterfaceManagementProfile",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "InterfaceManagementProfile")

    def test_zone_protection_profiles_can_use_network_scope_for_dry_run(self):
        parsed_data = {"ZoneProtectionProfile": [{"name": "internet-zpp", "description": "edge"}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="ZoneProtectionProfile",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "ZoneProtectionProfile")

    def test_dhcp_interfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {"DHCPInterface": [{"name": "vlan.100", "server": {"ip_pool": ["10.100.0.10-10.100.0.200"]}}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="DHCPInterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "DHCPInterface")

    def test_aggregate_interfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {"AggregateInterface": [{"name": "$ae1", "default_value": "ae1", "layer3": {}}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="AggregateInterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "AggregateInterface")

    def test_vlan_and_tunnel_interfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {
            "VlanInterface": [{"name": "vlan.100", "vlan_tag": "100"}],
            "TunnelInterface": [{"name": "tunnel.1", "default_value": "tunnel.1"}],
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="VlanInterface,TunnelInterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 2)
        self.assertEqual([change.object_type for change in plan.creates], ["VlanInterface", "TunnelInterface"])

    def test_layer2_subinterfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {"Layer2Subinterface": [{"name": "ethernet1/6.200", "parent_interface": "ethernet1/6", "tag": 200}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Layer2Subinterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "Layer2Subinterface")

    def test_loopback_interfaces_can_use_network_scope_for_dry_run(self):
        parsed_data = {"LoopbackInterface": [{"name": "loopback.1", "ip": ["10.255.0.1/32"]}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="LoopbackInterface",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "LoopbackInterface")

    def test_vpn_objects_can_use_network_scope_for_dry_run(self):
        parsed_data = {
            "IKECryptoProfile": [{"name": "ike-crypto-a", "hash": ["sha256"], "encryption": ["aes-256-cbc"], "dh_group": ["group14"]}],
            "IPsecCryptoProfile": [{"name": "ipsec-crypto-a", "esp": {"encryption": ["aes-256-gcm"]}}],
            "IKEGateway": [{"name": "vpn-gw-a", "protocol": {"ikev2": {"ike_crypto_profile": "ike-crypto-a"}}}],
            "IPsecTunnel": [{"name": "vpn-tunnel-a", "tunnel_interface": "tunnel.1"}],
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="IKECryptoProfile,IPsecCryptoProfile,IKEGateway,IPsecTunnel",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 4)
        self.assertEqual(
            [change.object_type for change in plan.creates],
            ["IKECryptoProfile", "IPsecCryptoProfile", "IKEGateway", "IPsecTunnel"],
        )

    def test_route_filters_can_use_network_scope_for_dry_run(self):
        parsed_data = {
            "OSPFAuthProfile": [{"name": "ospf-simple", "password": "ospf-secret"}],
            "RoutePrefixList": [{"name": "default-export-default-pl", "prefix_list": [{"name": 1, "action": "permit", "prefix": "0.0.0.0/0"}]}],
            "RouteAccessList": [{"name": "routes-acl", "access_list": [{"name": 1, "action": "permit", "source": "corp-routes"}]}],
            "RouteCommunityList": [{"name": "communities", "community_list": [{"name": 1, "action": "permit", "community": "65001:100"}]}],
            "RoutePathAccessList": [{"name": "as-paths", "path_access_list": [{"name": 1, "action": "permit", "regular_expression": "^65010_"}]}],
            "BgpRouteMap": [{"name": "default-export-default-rm", "route_map": [{"name": 10, "action": "permit"}]}],
            "BgpRouteMapRedistribution": [{"name": "redist-rm", "route_map": [{"name": 10, "action": "permit"}]}],
            "BgpRedistributionProfile": [{"name": "redist-profile", "ipv4": {"unicast": {"static": {"enable": True}}}}],
        }

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="OSPFAuthProfile,RoutePrefixList,RouteAccessList,RouteCommunityList,RoutePathAccessList,BgpRouteMap,BgpRouteMapRedistribution,BgpRedistributionProfile",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 8)
        self.assertEqual(
            [change.object_type for change in plan.creates],
            [
                "OSPFAuthProfile",
                "RoutePrefixList",
                "RouteAccessList",
                "RouteCommunityList",
                "RoutePathAccessList",
                "BgpRouteMap",
                "BgpRouteMapRedistribution",
                "BgpRedistributionProfile",
            ],
        )

    def test_pbf_rules_can_use_network_scope_for_dry_run(self):
        parsed_data = {"PbfRule": [{"name": "send-guest-to-isp2", "action": {"forwarding": {"egress_interface": "ethernet1/2"}}}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="PbfRule",
                    json_file=str(parsed_path),
                    dry_run=True,
                    network_scope="snippet:Network-Stack",
                )

        self.assertEqual(plan.summary()["creates"], 1)
        self.assertEqual(plan.creates[0].object_type, "PbfRule")

    def test_object_dry_run_falls_back_to_default_scope(self):
        parsed_data = {"Address": [{"name": "addr", "ip_netmask": "192.0.2.10"}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO):
                plan = main.main(
                    AppConfig(),
                    run_objects="Address",
                    json_file=str(parsed_path),
                    dry_run=True,
                    scope="folder:All",
                )

        self.assertEqual(plan.summary()["creates"], 1)

    def test_network_dry_run_requires_network_or_default_scope(self):
        parsed_data = {"Zones": [{"name": "trust", "network": {"layer3": ["ethernet1/1"]}}]}

        with tempfile.TemporaryDirectory() as directory:
            parsed_path = Path(directory) / "parsed.json"
            parsed_path.write_text(json.dumps(parsed_data), encoding="utf-8")

            with patch.object(main, "logger"), patch("builtins.input") as input_mock:
                with self.assertRaises(SystemExit):
                    main.main(
                        AppConfig(),
                        run_objects="Zones",
                        json_file=str(parsed_path),
                        dry_run=True,
                    )

        input_mock.assert_not_called()

    def test_cisco_parser_can_be_selected_without_detection_prompt(self):
        cisco_config = "\n".join(
            [
                "ASA Version 9.18",
                "hostname asa1",
                "object network WEB",
                " host 192.0.2.10",
            ]
        )

        with tempfile.TemporaryDirectory() as directory:
            cisco_path = Path(directory) / "cisco.txt"
            cisco_path.write_text(cisco_config, encoding="utf-8")

            with patch.object(main, "logger"), patch("sys.stdout", new_callable=io.StringIO), patch("builtins.input") as input_mock:
                plan = main.main(
                    AppConfig(),
                    parser_type="cisco",
                    config_file=str(cisco_path),
                    run_objects="Address",
                    dry_run=True,
                    scope="folder:All",
                )

        input_mock.assert_not_called()
        self.assertEqual(plan.summary()["creates"], 1)


if __name__ == "__main__":
    unittest.main()
