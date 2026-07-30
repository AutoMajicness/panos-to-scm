import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api import PanApiSession
from api.config import panapi_config_path


class PanApiCredentialTests(unittest.TestCase):
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
