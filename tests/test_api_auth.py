import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api import PanApiSession
from api.config import panapi_config_path


class PanApiCredentialTests(unittest.TestCase):
    def test_runtime_credentials_override_file_values_without_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yml"
            config_path.write_text(
                "client_id: file-client\n"
                "client_secret: file-secret\n"
                "tsg_id: file-tenant\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"PANAPI_CONFIG": str(config_path)}, clear=False):
                session = PanApiSession(runtime_config={
                    "client_id": "runtime-client",
                    "client_secret": "runtime-secret",
                    "tsg_id": "runtime-tenant",
                })

            self.assertEqual("runtime-client", session.config["client_id"])
            self.assertEqual("runtime-secret", session.config["client_secret"])
            self.assertEqual("runtime-tenant", session.config["tsg_id"])
            self.assertIn("file-client", config_path.read_text(encoding="utf-8"))

    def test_session_loads_scm_credentials_from_panapi_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yml"
            config_path.write_text(
                "client_id: test-client\n"
                "client_secret: test-secret\n"
                "tsg_id: test-tsg\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"PANAPI_CONFIG": str(config_path)}, clear=False):
                session = PanApiSession()

        self.assertEqual(session.config["client_id"], "test-client")
        self.assertEqual(session.config["client_secret"], "test-secret")
        self.assertEqual(session.config["tsg_id"], "test-tsg")

    def test_default_path_is_under_panapi_directory(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(str(panapi_config_path()).endswith(".panapi/config.yml"))


if __name__ == "__main__":
    unittest.main()
