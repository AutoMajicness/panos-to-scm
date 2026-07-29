import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_LAYER2_SUBINTERFACE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <ethernet>
            <entry name="ethernet1/6">
              <layer2>
                <units>
                  <entry name="ethernet1/6.200">
                    <tag>200</tag>
                    <comment>Users L2 VLAN</comment>
                    <netflow-profile>netflow-default</netflow-profile>
                  </entry>
                </units>
              </layer2>
            </entry>
          </ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosLayer2SubinterfaceParserTests(unittest.TestCase):
    def test_local_layer2_subinterfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LAYER2_SUBINTERFACE_XML, encoding="utf-8")

            subinterfaces = XMLParser(str(xml_path), "local").parse_specific_types(["Layer2Subinterface"])["Layer2Subinterface"]

        self.assertEqual(
            subinterfaces,
            [
                {
                    "name": "ethernet1/6.200",
                    "parent_interface": "ethernet1/6",
                    "tag": 200,
                    "comment": "Users L2 VLAN",
                    "netflow_profile": "netflow-default",
                }
            ],
        )

    def test_panorama_layer2_subinterface_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LAYER2_SUBINTERFACE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                subinterfaces = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["Layer2Subinterface"])["Layer2Subinterface"]

        self.assertEqual(subinterfaces, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
