import json
import tempfile
import unittest
from pathlib import Path

from backend.integrations.auth_exchange import write_grok2api_auth_bundle


class Grok2APIAuthExportTests(unittest.TestCase):
    def test_bundle_uses_one_sso_for_web_and_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_grok2api_auth_bundle(
                Path(tmp),
                {
                    "access_token": "access-token",
                    "refresh_token": "refresh-token",
                    "expires_in": 3600,
                },
                "sso=shared-sso; Path=/; Secure",
                email="person@example.com",
            )
            documents = {
                provider: json.loads(path.read_text(encoding="utf-8"))
                for provider, path in paths.items()
            }

        self.assertEqual(set(paths), {"build", "web", "console"})
        self.assertEqual(documents["build"]["accounts"][0]["provider"], "grok_build")
        self.assertEqual(documents["web"]["provider"], "grok_web")
        self.assertEqual(documents["console"]["provider"], "grok_console")
        self.assertEqual(documents["web"]["accounts"][0]["sso_token"], "shared-sso")
        self.assertEqual(documents["console"]["accounts"][0]["sso_token"], "shared-sso")
        self.assertEqual(documents["web"]["accounts"][0]["tier"], "auto")
        self.assertNotIn("tier", documents["console"]["accounts"][0])


if __name__ == "__main__":
    unittest.main()
