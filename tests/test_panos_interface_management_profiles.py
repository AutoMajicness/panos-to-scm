import tempfile
import unittest
from pathlib import Path

from parse.parse_panos import XMLParser


LOCAL_INTERFACE_MANAGEMENT_PROFILE_XML = """<config>
  <devices>
    <entry name="localhost.localdomain">
      <network>
        <profiles>
          <interface-management-profile>
            <entry name="allow-mgmt">
              <ping>yes</ping>
              <https>yes</https>
              <ssh>yes</ssh>
              <snmp>no</snmp>
              <response-pages>no</response-pages>
              <userid-service>yes</userid-service>
              <permitted-ip>
                <entry name="192.0.2.0/24" />
                <member>198.51.100.10/32</member>
              </permitted-ip>
            </entry>
          </interface-management-profile>
        </profiles>
      </network>
    </entry>
  </devices>
</config>
"""


class PanosInterfaceManagementProfileParserTests(unittest.TestCase):
    def test_local_interface_management_profiles_are_normalized_for_scm(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_INTERFACE_MANAGEMENT_PROFILE_XML, encoding="utf-8")

            profiles = XMLParser(str(xml_path), "local").parse_specific_types(["InterfaceManagementProfile"])["InterfaceManagementProfile"]

        self.assertEqual(
            profiles,
            [
                {
                    "name": "allow-mgmt",
                    "ping": True,
                    "https": True,
                    "ssh": True,
                    "snmp": False,
                    "response_pages": False,
                    "userid_service": True,
                    "permitted_ip": ["198.51.100.10/32", "192.0.2.0/24"],
                }
            ],
        )

    def test_panorama_interface_management_profile_parsing_is_not_claimed_yet(self):
        with tempfile.TemporaryDirectory() as directory:
            xml_path = Path(directory) / "running.xml"
            xml_path.write_text(LOCAL_INTERFACE_MANAGEMENT_PROFILE_XML, encoding="utf-8")

            with self.assertLogs("parse.parse_panos", level="WARNING") as logs:
                profiles = XMLParser(str(xml_path), "panorama/shared").parse_specific_types(["InterfaceManagementProfile"])["InterfaceManagementProfile"]

        self.assertEqual(profiles, [])
        self.assertIn("local firewall XML only", logs.output[0])


if __name__ == "__main__":
    unittest.main()
