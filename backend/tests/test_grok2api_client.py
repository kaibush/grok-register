import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend.integrations import grok2api_client
from backend.integrations.grok2api_client import Grok2APIClient, Grok2APIImportError


class FakeResponse:
    def __init__(self, status=200, payload=None, lines=None):
        self.status_code = status
        self._payload = payload
        self._lines = lines or []
        self.closed = False

    def json(self):
        return self._payload

    def iter_lines(self):
        return iter(self._lines)

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.calls.append((url, dict(kwargs)))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class Grok2APIClientTests(unittest.TestCase):
    def test_owned_session_does_not_inherit_environment_proxy(self):
        session = mock.Mock()
        with mock.patch.object(
            grok2api_client.requests,
            "Session",
            return_value=session,
        ) as factory:
            client = Grok2APIClient("https://example.test", "admin", "secret")
        factory.assert_called_once_with(trust_env=False)
        self.assertIs(client.session, session)

    def test_from_config_validates_and_builds_client(self):
        config = {
            "grok2api_remote_url": "https://example.test/",
            "grok2api_remote_username": "admin",
            "grok2api_remote_password": "secret",
        }
        self.assertTrue(Grok2APIClient.is_configured(config))
        client = Grok2APIClient.from_config(config, session=FakeSession([]))
        self.assertEqual(client.base_url, "https://example.test")
        self.assertEqual(client.username, "admin")

    def test_login_caches_access_token_on_instance(self):
        session = FakeSession(
            [FakeResponse(payload={"data": {"tokens": {"accessToken": "fresh-token"}}})]
        )
        client = Grok2APIClient(
            "https://example.test/", "admin", "secret", session=session
        )
        self.assertEqual(client.login(), "fresh-token")
        self.assertEqual(client.login(), "fresh-token")
        self.assertEqual(client.access_token, "fresh-token")
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(
            session.calls[0][0], "https://example.test/api/admin/v1/auth/login"
        )

    def test_import_logs_in_uses_multipart_and_parses_complete_event(self):
        import_response = FakeResponse(
            lines=[
                b": connected",
                b"",
                b"event: progress",
                b'data: {"completed":1,"total":1}',
                b"",
                b"event: complete",
                b'data: {"created":1,"updated":0,"synced":1}',
                b"",
            ]
        )
        session = FakeSession(
            [
                FakeResponse(payload={"data": {"tokens": {"accessToken": "fresh-token"}}}),
                import_response,
            ]
        )
        client = Grok2APIClient(
            "https://example.test", "admin", "secret", session=session
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "g2a-fixture.json"
            path.write_text(json.dumps({"provider": "grok_build"}), encoding="utf-8")
            result = client.import_auth_file(path)
        self.assertEqual(result["created"], 1)
        self.assertIn("multipart", session.calls[1][1])
        self.assertEqual(
            session.calls[1][1]["headers"]["Authorization"], "Bearer fresh-token"
        )
        self.assertTrue(import_response.closed)

    def test_import_surfaces_sse_error(self):
        session = FakeSession(
            [
                FakeResponse(payload={"data": {"tokens": {"accessToken": "fresh-token"}}}),
                FakeResponse(
                    lines=[
                        b"event: error",
                        b'data: {"message":"fixture failed"}',
                        b"",
                    ]
                ),
            ]
        )
        client = Grok2APIClient(
            "https://example.test", "admin", "secret", session=session
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "g2a-fixture.json"
            path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(Grok2APIImportError, "fixture failed"):
                client.import_auth_file(path)

    def test_context_manager_closes_owned_session_only(self):
        external = FakeSession([])
        client = Grok2APIClient(
            "https://example.test", "admin", "secret", session=external
        )
        client.close()
        self.assertFalse(external.closed)


if __name__ == "__main__":
    unittest.main()
