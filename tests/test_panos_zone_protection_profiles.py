import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_ZONE_PROTECTION_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <profiles>
          <zone-protection-profile>
            <entry name="internet-zpp">
              <description>Internet edge protection</description>
              <flood>
                <tcp-syn>
                  <enable>yes</enable>
                  <red>
                    <alarm-rate>10000</alarm-rate>
                    <activate-rate>15000</activate-rate>
                    <maximal-rate>20000</maximal-rate>
                    <block-duration>300</block-duration>
                  </red>
                </tcp-syn>
                <udp>
                  <enable>yes</enable>
                  <red>
                    <alarm-rate>1000</alarm-rate>
                    <activate-rate>2000</activate-rate>
                    <maximal-rate>3000</maximal-rate>
                  </red>
                </udp>
              </flood>
              <scan>
                <entry name="tcp-port-scan">
                  <interval>2</interval>
                  <threshold>100</threshold>
                  <action>
                    <alert />
                  </action>
                </entry>
              </scan>
            </entry>
          </zone-protection-profile>
        </profiles>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosZoneProtectionProfileParserTests(unittest.TestCase):
    def test_local_zone_protection_profiles_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_ZONE_PROTECTION_XML, encoding="utf-8")

            profiles = XMLParser(str(xml_path), "local").parse_specific_types(["ZoneProtectionProfile"])["ZoneProtectionProfile"]

        self.assertEqual(
            profiles,
            [
                {
                    "name": "internet-zpp",
                    "description": "Internet edge protection",
                    "flood": {
                        "tcp_syn": {
                            "enable": True,
                            "red": {
                                "alarm_rate": 10000,
                                "activate_rate": 15000,
                                "maximal_rate": 20000,
                                "block_duration": 300,
                            },
                        },
                        "udp": {
                            "enable": True,
                            "red": {
                                "alarm_rate": 1000,
                                "activate_rate": 2000,
                                "maximal_rate": 3000,
                            },
                        },
                    },
                    "reconnaissance": {
                        "tcp_port_scan": {
                            "interval": 2,
                            "threshold": 100,
                            "action": "alert",
                        }
                    },
                }
            ],
        )

    def test_panorama_zone_protection_profile_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_ZONE_PROTECTION_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                profiles = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["ZoneProtectionProfile"])["ZoneProtectionProfile"]

        self.assertEqual(profiles, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
