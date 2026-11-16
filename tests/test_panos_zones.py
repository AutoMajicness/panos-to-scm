import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_ZONE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <vsys>
        <entry name="vsys1">
          <zone>
            <entry name="trust">
              <network>
                <layer3>
                  <member>ethernet1/1</member>
                  <member>ethernet1/2</member>
                </layer3>
                <zone-protection-profile>strict-zpp</zone-protection-profile>
              </network>
            </entry>
            <entry name="dmz">
              <network>
                <layer2>
                  <member>ethernet1/3</member>
                </layer2>
              </network>
            </entry>
            <entry name="tap-zone">
              <network>
                <tap>
                  <member>ethernet1/4</member>
                </tap>
              </network>
            </entry>
            <entry name="vwire-zone">
              <network>
                <v-wire>
                  <member>ethernet1/5</member>
                </v-wire>
              </network>
            </entry>
            <entry name="empty-zone">
              <network />
            </entry>
          </zone>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>
"""


class PanosZoneParserTests(unittest.TestCase):
    def test_local_zones_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_ZONE_XML, encoding="utf-8")

            zones = XMLParser(str(xml_path), "local").parse_specific_types(["Zones"])["Zones"]

        self.assertEqual(
            zones,
            [
                {
                    "name": "trust",
                    "network": {
                        "layer3": ["ethernet1/1", "ethernet1/2"],
                        "zone_protection_profile": "strict-zpp",
                    },
                },
                {"name": "dmz", "network": {"layer2": ["ethernet1/3"]}},
                {"name": "tap-zone", "network": {"tap": ["ethernet1/4"]}},
                {"name": "vwire-zone", "network": {"virtual_wire": ["ethernet1/5"]}},
                {"name": "empty-zone"},
            ],
        )

    def test_panorama_zone_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_ZONE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                zones = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["Zones"])["Zones"]

        self.assertEqual(zones, [])
        self.assertIn("local firewall/vsys XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
