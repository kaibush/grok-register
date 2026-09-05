import unittest
from unittest import mock

from backend.integrations.proxy import (
    expand_session_placeholder,
    parse_http_proxy_url,
    redact_proxy_text,
    redact_proxy_url,
    resolve_proxy_url,
    validate_http_proxy_url,
)


class DockerProxyResolutionTests(unittest.TestCase):
    def test_localhost_proxy_maps_to_docker_host(self):
        with mock.patch.dict(
            "os.environ", {"GROK_DOCKER_PROXY_HOST": "host.docker.internal"}, clear=False
        ):
            self.assertEqual(
                resolve_proxy_url("http://127.0.0.1:7897"),
                "http://host.docker.internal:7897",
            )

    def test_credentials_are_preserved(self):
        with mock.patch.dict(
            "os.environ", {"GROK_DOCKER_PROXY_HOST": "host.docker.internal"}, clear=False
        ):
            self.assertEqual(
                resolve_proxy_url("socks5://user:pass@localhost:7897"),
                "socks5://user:pass@host.docker.internal:7897",
            )

    def test_encoded_http_credentials_are_preserved_during_host_rewrite(self):
        with mock.patch.dict(
            "os.environ", {"GROK_DOCKER_PROXY_HOST": "host.docker.internal"}, clear=False
        ):
            self.assertEqual(
                resolve_proxy_url("http://user%40mail:p%40ss%3Aword@localhost:7897"),
                "http://user%40mail:p%40ss%3Aword@host.docker.internal:7897",
            )

    def test_regular_proxy_is_unchanged(self):
        with mock.patch.dict(
            "os.environ", {"GROK_DOCKER_PROXY_HOST": "host.docker.internal"}, clear=False
        ):
            self.assertEqual(
                resolve_proxy_url("http://proxy.example.com:7897"),
                "http://proxy.example.com:7897",
            )


class HttpProxyParsingTests(unittest.TestCase):
    def test_authenticated_http_proxy_is_split_for_camoufox(self):
        self.assertEqual(
            parse_http_proxy_url("http://user:password@proxy.example.com:8080"),
            {
                "server": "http://proxy.example.com:8080",
                "username": "user",
                "password": "password",
            },
        )

    def test_percent_encoded_credentials_are_decoded(self):
        self.assertEqual(
            parse_http_proxy_url(
                "https://user%40mail.example:p%40ss%3Aword@proxy.example.com:8443"
            ),
            {
                "server": "https://proxy.example.com:8443",
                "username": "user@mail.example",
                "password": "p@ss:word",
            },
        )

    def test_original_encoded_url_is_retained_for_http_clients(self):
        proxy = "http://user%40mail:p%40ss@proxy.example.com:8080"
        self.assertEqual(validate_http_proxy_url(proxy), proxy)

    def test_invalid_percent_encoding_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "百分号编码"):
            validate_http_proxy_url("http://user:bad%ZZ@proxy.example.com:8080")

    def test_unencoded_path_character_in_credentials_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "百分号编码"):
            validate_http_proxy_url("http://user:bad/word@proxy.example.com:8080")

    def test_proxy_credentials_are_redacted_for_display_and_log_text(self):
        proxy = "http://user%40mail:p%40ss@proxy.example.com:8080"
        self.assertEqual(
            redact_proxy_url(proxy),
            "http://***:***@proxy.example.com:8080",
        )
        message = redact_proxy_text(f"request failed via {proxy}")
        self.assertNotIn("user%40mail", message)
        self.assertNotIn("p%40ss", message)
        self.assertIn("http://***:***@proxy.example.com:8080", message)

        malformed = redact_proxy_text(
            "failed via http://user:raw/secret@proxy.example.com:8080"
        )
        self.assertNotIn("raw/secret", malformed)


class ExpandSessionPlaceholderTests(unittest.TestCase):
    def test_placeholder_replaced_with_fresh_token(self):
        first = expand_session_placeholder("http://register.{session}:t@h:1")
        second = expand_session_placeholder("http://register.{session}:t@h:1")
        self.assertNotIn("{session}", first)
        self.assertNotEqual(first, second)

    def test_no_placeholder_unchanged(self):
        proxy = "http://register.fixed:t@h:1"
        self.assertEqual(expand_session_placeholder(proxy), proxy)
        self.assertEqual(expand_session_placeholder(""), "")


class ProxySessionPlaceholderTests(unittest.TestCase):
    """get_proxies 的 {session} 占位符：每次调用生成新标识，无占位符时保持不变。"""

    def _get(self, proxy):
        from backend.registration import engine

        with mock.patch.dict(engine.config, {"proxy": proxy}):
            return engine.get_proxies()

    def test_session_placeholder_replaced_per_call(self):
        first = self._get("http://register.{session}:token@proxy.example.com:2260")
        second = self._get("http://register.{session}:token@proxy.example.com:2260")
        self.assertNotIn("{session}", first["http"])
        self.assertNotIn("{session}", second["http"])
        self.assertNotEqual(first["http"], second["http"])
        self.assertTrue(
            first["http"].startswith("http://register.") , first["http"]
        )
        self.assertIn(":token@proxy.example.com:2260", first["http"])
        self.assertEqual(first["http"], first["https"])

    def test_proxy_without_placeholder_unchanged(self):
        proxy = "http://register.fixed:token@proxy.example.com:2260"
        self.assertEqual(self._get(proxy)["http"], proxy)
        self.assertEqual(self._get(proxy)["http"], proxy)


if __name__ == "__main__":
    unittest.main()
