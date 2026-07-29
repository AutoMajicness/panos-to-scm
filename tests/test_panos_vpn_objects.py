import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_VPN_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <ike>
          <crypto-profiles>
            <ike-crypto-profiles>
              <entry name="ike-crypto-a">
                <hash>
                  <member>sha256</member>
                  <member>sha384</member>
                </hash>
                <encryption>
                  <member>aes-256-cbc</member>
                </encryption>
                <dh-group>
                  <member>group14</member>
                </dh-group>
                <lifetime>
                  <hours>8</hours>
                </lifetime>
                <authentication-multiple>0</authentication-multiple>
              </entry>
            </ike-crypto-profiles>
            <ipsec-crypto-profiles>
              <entry name="ipsec-crypto-a">
                <esp>
                  <encryption>
                    <member>aes-256-gcm</member>
                  </encryption>
                  <authentication>
                    <member>sha256</member>
                  </authentication>
                </esp>
                <dh-group>group14</dh-group>
                <lifetime>
                  <hours>1</hours>
                </lifetime>
              </entry>
            </ipsec-crypto-profiles>
          </crypto-profiles>
          <gateway>
            <entry name="vpn-gw-a">
              <protocol>
                <version>ikev2-preferred</version>
                <ikev2>
                  <ike-crypto-profile>ike-crypto-a</ike-crypto-profile>
                  <dpd>
                    <enable>yes</enable>
                    <interval>5</interval>
                    <retry>10</retry>
                  </dpd>
                </ikev2>
              </protocol>
              <local-address>
                <interface>ethernet1/1</interface>
                <ip>198.51.100.10/24</ip>
              </local-address>
              <peer-address>
                <ip>203.0.113.10</ip>
              </peer-address>
              <authentication>
                <pre-shared-key>
                  <key>encrypted-secret</key>
                </pre-shared-key>
              </authentication>
            </entry>
          </gateway>
        </ike>
        <tunnel>
          <ipsec>
            <entry name="vpn-tunnel-a">
              <tunnel-interface>tunnel.1</tunnel-interface>
              <auto-key>
                <ike-gateway>
                  <entry name="vpn-gw-a" />
                </ike-gateway>
                <ipsec-crypto-profile>ipsec-crypto-a</ipsec-crypto-profile>
                <proxy-id>
                  <entry name="proxy-a">
                    <local>10.0.0.0/24</local>
                    <remote>10.1.0.0/24</remote>
                    <protocol>
                      <number>0</number>
                    </protocol>
                  </entry>
                </proxy-id>
              </auto-key>
              <anti-replay>yes</anti-replay>
              <copy-tos>no</copy-tos>
              <enable-gre-encapsulation>no</enable-gre-encapsulation>
              <tunnel-monitor>
                <enable>yes</enable>
                <destination-ip>169.254.1.2</destination-ip>
                <proxy-id>proxy-a</proxy-id>
              </tunnel-monitor>
            </entry>
          </ipsec>
        </tunnel>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosVpnObjectParserTests(unittest.TestCase):
    def test_local_ike_crypto_profiles_are_normalized_for_scm(self):
        parsed = self._parse(["IKECryptoProfile"])

        self.assertEqual(
            parsed["IKECryptoProfile"],
            [
                {
                    "name": "ike-crypto-a",
                    "hash": ["sha256", "sha384"],
                    "encryption": ["aes-256-cbc"],
                    "dh_group": ["group14"],
                    "lifetime": {"hours": 8},
                    "authentication_multiple": 0,
                }
            ],
        )

    def test_local_ipsec_crypto_profiles_are_normalized_for_scm(self):
        parsed = self._parse(["IPsecCryptoProfile"])

        self.assertEqual(
            parsed["IPsecCryptoProfile"],
            [
                {
                    "name": "ipsec-crypto-a",
                    "esp": {
                        "encryption": ["aes-256-gcm"],
                        "authentication": ["sha256"],
                    },
                    "dh_group": "group14",
                    "lifetime": {"hours": 1},
                }
            ],
        )

    def test_local_ike_gateways_are_normalized_for_scm(self):
        parsed = self._parse(["IKEGateway"])

        self.assertEqual(
            parsed["IKEGateway"],
            [
                {
                    "name": "vpn-gw-a",
                    "protocol": {
                        "version": "ikev2-preferred",
                        "ikev2": {
                            "ike_crypto_profile": "ike-crypto-a",
                            "dpd": {"enable": True, "interval": 5, "retry": 10},
                        },
                    },
                    "local_address": {
                        "interface": "ethernet1/1",
                        "ip": "198.51.100.10/24",
                    },
                    "peer_address": {"ip": "203.0.113.10"},
                    "authentication": {"pre_shared_key": {"key": "encrypted-secret"}},
                }
            ],
        )

    def test_local_ipsec_tunnels_are_normalized_for_scm(self):
        parsed = self._parse(["IPsecTunnel"])

        self.assertEqual(
            parsed["IPsecTunnel"],
            [
                {
                    "name": "vpn-tunnel-a",
                    "tunnel_interface": "tunnel.1",
                    "auto_key": {
                        "ike_gateway": [{"name": "vpn-gw-a"}],
                        "ipsec_crypto_profile": "ipsec-crypto-a",
                        "proxy_id": [
                            {
                                "name": "proxy-a",
                                "local": "10.0.0.0/24",
                                "remote": "10.1.0.0/24",
                                "protocol": {"number": 0},
                            }
                        ],
                    },
                    "anti_replay": True,
                    "copy_tos": False,
                    "enable_gre_encapsulation": False,
                    "tunnel_monitor": {
                        "enable": True,
                        "destination_ip": "169.254.1.2",
                        "proxy_id": "proxy-a",
                    },
                }
            ],
        )

    def test_panorama_vpn_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_VPN_XML, encoding="utf-8")
            parser = XMLParser(str(xml_path), "panorama/shared")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                parsed = parser.parse_specific_types(["IKECryptoProfile", "IPsecCryptoProfile", "IKEGateway", "IPsecTunnel"])

        self.assertEqual(parsed["IKECryptoProfile"], [])
        self.assertEqual(parsed["IPsecCryptoProfile"], [])
        self.assertEqual(parsed["IKEGateway"], [])
        self.assertEqual(parsed["IPsecTunnel"], [])
        self.assertIn("IKE crypto profile migration currently supports local firewall XML only.", logs.output[0])
        self.assertIn("IPsec crypto profile migration currently supports local firewall XML only.", logs.output[1])
        self.assertIn("IKE gateway migration currently supports local firewall XML only.", logs.output[2])
        self.assertIn("IPsec tunnel migration currently supports local firewall XML only.", logs.output[3])

    def _parse(self, object_types):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_VPN_XML, encoding="utf-8")
            return XMLParser(str(xml_path), "local").parse_specific_types(object_types)


if __name__ == "__main__":
    unittest.main()
