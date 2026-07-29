import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_LOOPBACK_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <loopback>
            <units>
              <entry name="loopback.1">
                <comment>Management loopback</comment>
                <ip>
                  <entry name="10.255.0.1/32" />
                  <entry name="10.255.0.2/32" />
                </ip>
                <mtu>1500</mtu>
                <interface-management-profile>allow-ping</interface-management-profile>
              </entry>
            </units>
          </loopback>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosLoopbackInterfaceParserTests(unittest.TestCase):
    def test_local_loopback_interfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LOOPBACK_XML, encoding="utf-8")

            loopbacks = XMLParser(str(xml_path), "local").parse_specific_types(["LoopbackInterface"])["LoopbackInterface"]

        self.assertEqual(
            loopbacks,
            [
                {
                    "name": "loopback.1",
                    "comment": "Management loopback",
                    "interface_management_profile": "allow-ping",
                    "mtu": 1500,
                    "ip": ["10.255.0.1/32", "10.255.0.2/32"],
                }
            ],
        )

    def test_panorama_loopback_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_LOOPBACK_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                loopbacks = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["LoopbackInterface"])["LoopbackInterface"]

        self.assertEqual(loopbacks, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
