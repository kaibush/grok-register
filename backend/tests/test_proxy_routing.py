import unittest
from unittest import mock

from backend.automation import session as browser_session
from backend.integrations import auth_exchange
from backend.integrations import network_checks
from backend.registration import engine as gr


class ProxyRoutingTests(unittest.TestCase):
    def setUp(self):
        self.original_config = dict(gr.config)

    def tearDown(self):
        gr.config.clear()
        gr.config.update(self.original_config)
        browser_session.configure(
            get_proxies=lambda: {},
            is_debug=lambda: False,
            is_headless=lambda: False,
            get_locale=lambda: "en-US",
        )

    def test_camoufox_registration_keeps_configured_proxy(self):
        browser_session.configure(
            get_proxies=lambda: {
                "http": "http://127.0.0.1:7897",
                "https": "http://127.0.0.1:7897",
            },
            is_debug=lambda: False,
            is_headless=lambda: False,
            get_locale=lambda: "en-US",
        )
        options = browser_session.create_browser_options(unique_profile=False)
        self.assertEqual(options["proxy"], {"server": "http://127.0.0.1:7897"})

    def test_actual_http_route_log_deduplicates_query_variants(self):
        logs = []
        with mock.patch.object(gr, "registration_log", side_effect=logs.append):
            gr.reset_network_route_logs()
            gr._log_actual_http_route(
                "get",
                "https://accounts.x.ai/sign-up?step=1",
                proxies={"https": "http://127.0.0.1:7897"},
            )
            gr._log_actual_http_route(
                "GET",
                "https://accounts.x.ai/sign-up?step=2",
                proxies={"https": "http://127.0.0.1:7897"},
            )
            gr._log_actual_http_route("GET", "http://mail.test/api/emails", proxies={})

        self.assertEqual(len(logs), 2)
        self.assertIn("GET https://accounts.x.ai/sign-up -> 代理 http://127.0.0.1:7897", logs[0])
        self.assertIn("GET http://mail.test/api/emails -> 直连（不使用代理）", logs[1])

    def test_outlook_acquire_and_code_polling_use_direct_default_http(self):
        with mock.patch.object(
            gr.outlookemail_provider,
            "acquire_email",
            return_value=("fixture@outlook.com", "fixture-token"),
        ) as acquire:
            gr.outlookemail_get_email_and_token()
        self.assertIs(acquire.call_args.args[0], gr.http_get)
        self.assertIs(acquire.call_args.args[1], gr.direct_http_session)
        self.assertEqual(acquire.call_args.kwargs["proxies"], {})

        with mock.patch.object(
            gr.outlookemail_provider,
            "wait_for_code",
            return_value="ABC-123",
        ) as wait:
            gr.outlookemail_get_oai_code("fixture@outlook.com")
        self.assertIs(wait.call_args.args[0], gr.http_get)
        self.assertIs(wait.call_args.args[1], gr.direct_http_session)
        self.assertEqual(wait.call_args.kwargs["proxies"], {})

    def test_default_http_wrappers_disable_environment_and_project_proxy(self):
        gr.config["proxy"] = "http://127.0.0.1:7897"
        for method, request_fn in (
            ("GET", gr.http_get),
            ("POST", gr.http_post),
            ("DELETE", gr.http_delete),
        ):
            with self.subTest(method=method):
                response = mock.Mock()
                session = mock.MagicMock()
                session.__enter__.return_value = session
                session.__exit__.return_value = False
                session.request.return_value = response
                raw_request = session.request
                with mock.patch.object(
                    gr.requests, "Session", return_value=session
                ) as factory:
                    result = request_fn("http://mail-service.test/api")
                self.assertIs(result, response)
                factory.assert_called_once_with(trust_env=False)
                raw_request.assert_called_once_with(
                    method,
                    "http://mail-service.test/api",
                    proxies={},
                    timeout=15,
                )

    def test_xai_connectivity_check_explicitly_uses_configured_proxy(self):
        response = mock.Mock(status_code=200, text="<!doctype html>", headers={})
        http_get = mock.Mock(return_value=response)
        proxy = "http://127.0.0.1:7897"
        _, ok, detail = network_checks.check_xai_signup(proxy, http_get)
        self.assertTrue(ok, detail)
        self.assertEqual(
            http_get.call_args.kwargs["proxies"],
            {"http": proxy, "https": proxy},
        )

    def test_outlook_connectivity_check_uses_direct_default_http(self):
        response = mock.Mock(status_code=200)
        response.json.return_value = {"success": True, "accounts": []}
        direct_get = mock.Mock(return_value=response)
        name, ok, detail = network_checks.check_email_api(
            "outlookemail",
            {
                "outlookemail_api_base": "http://mail-pool.test",
                "outlookemail_source": "accounts",
                "outlookemail_api_key": "api-key",
                "outlookemail_group_id": "",
            },
            direct_get,
            mock.Mock(),
        )
        self.assertEqual(name, "邮箱API")
        self.assertTrue(ok, detail)
        self.assertEqual(direct_get.call_args.kwargs["proxies"], {})

    def test_outlook_disable_is_forced_direct(self):
        gr.config.update(
            {
                "email_provider": "outlookemail",
                "outlookemail_source": "accounts",
                "outlookemail_disable_after_cpa_success": True,
            }
        )
        with mock.patch.object(
            gr.outlookemail_provider,
            "account_for_email",
            return_value={"id": 1, "email": "fixture@outlook.com"},
        ) as lookup, mock.patch.object(
            gr.outlookemail_provider,
            "disable_account",
            return_value={"success": True, "account_id": 1},
        ) as disable:
            detail = gr.disable_outlookemail_after_cpa_success(
                "fixture@outlook.com", {"status": "success"}
            )
        self.assertEqual(detail["status"], "success")
        self.assertIs(lookup.call_args.args[0], gr.http_get)
        self.assertIs(disable.call_args.args[0], gr.http_get)
        self.assertIs(disable.call_args.args[1], gr.direct_http_session)
        self.assertEqual(disable.call_args.kwargs["proxies"], {})

    def test_sso_token_exchange_uses_proxy_but_cpa_remote_upload_is_direct(self):
        gr.config.update(
            {
                "proxy": "http://127.0.0.1:7897",
                "cpa_auto_add": True,
                "cpa_token_mode": "device_protocol",
                "cpa_auth_dir": "",
                "cpa_remote_url": "http://cpa.internal:8317",
                "cpa_management_key": "management-key",
                "grok2api_auth_dir": "",
                "grok2api_remote_url": "",
                "grok2api_remote_username": "",
                "grok2api_remote_password": "",
            }
        )
        with mock.patch.object(
            gr._s2cpa,
            "sso_to_token",
            return_value={"access_token": "access", "refresh_token": "refresh"},
        ) as exchange, mock.patch.object(
            gr._s2cpa,
            "token_to_cpa_record",
            return_value={"access_token": "access", "email": "fixture@example.com"},
        ), mock.patch.object(
            gr._s2cpa,
            "decode_jwt_payload",
            return_value={},
        ), mock.patch.object(
            gr._s2cpa,
            "upload_cpa_auth_remote",
            return_value="xai-fixture.json",
        ) as upload:
            self.assertTrue(gr.add_sso_to_cpa("sso-value", email="fixture@example.com"))

        self.assertEqual(exchange.call_args.kwargs["proxy"], "http://127.0.0.1:7897")
        self.assertEqual(upload.call_args.kwargs["proxy"], "")

    def test_cpa_remote_http_session_does_not_inherit_environment_proxy(self):
        response = mock.Mock(status_code=200, reason="OK", text="")
        session = mock.MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = False
        session.post.return_value = response
        with mock.patch.object(auth_exchange.requests, "Session", return_value=session) as factory:
            name = auth_exchange.upload_cpa_auth_remote(
                "http://cpa.internal:8317",
                "management-key",
                {"email": "fixture@example.com"},
                proxy="",
            )
        self.assertEqual(name, "xai-fixture@example.com.json")
        factory.assert_called_once_with(trust_env=False)
        self.assertIsNone(session.post.call_args.kwargs["proxies"])


if __name__ == "__main__":
    unittest.main()
