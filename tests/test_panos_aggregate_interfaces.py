import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_AGGREGATE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <interface>
          <aggregate-ethernet>
            <entry name="ae1">
              <comment>Core aggregate</comment>
              <lacp>
                <enable>yes</enable>
                <mode>active</mode>
                <transmission-rate>fast</transmission-rate>
              </lacp>
              <layer3>
                <ip>
                  <entry name="198.51.100.1/24" />
                </ip>
                <mtu>9000</mtu>
                <interface-management-profile>allow-ping</interface-management-profile>
              </layer3>
            </entry>
            <entry name="ae2">
              <layer2 />
            </entry>
            <entry name="ae3">
              <comment>Unsupported empty aggregate</comment>
            </entry>
          </aggregate-ethernet>
        </interface>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosAggregateInterfaceParserTests(unittest.TestCase):
    def test_local_aggregate_interfaces_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_AGGREGATE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                aggregates = XMLParser(str(xml_path), "local").parse_specific_types(["AggregateInterface"])["AggregateInterface"]

        self.assertEqual(
            aggregates,
            [
                {
                    "name": "$ae1",
                    "default_value": "ae1",
                    "comment": "Core aggregate",
                    "lacp": {
                        "enable": True,
                        "mode": "active",
                        "transmission_rate": "fast",
                    },
                    "layer3": {
                        "ip": [{"name": "198.51.100.1/24"}],
                        "mtu": 9000,
                        "interface_management_profile": "allow-ping",
                    },
                },
                {"name": "$ae2", "default_value": "ae2", "layer2": {}},
            ],
        )
        self.assertIn("ae3", logs.output[0])

    def test_panorama_aggregate_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_AGGREGATE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                aggregates = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["AggregateInterface"])["AggregateInterface"]

        self.assertEqual(aggregates, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
