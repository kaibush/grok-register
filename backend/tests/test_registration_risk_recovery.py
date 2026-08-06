import unittest
from unittest import mock

from backend.registration import engine


class RegistrationRiskRecoveryTests(unittest.TestCase):
    def setUp(self):
        self._config = engine.config
        engine.config = {
            "cpa_auto_add": True,
            "cpa_auth_dir": "data/cpa_auth",
            "cpa_remote_url": "",
            "grok2api_auth_dir": "",
        }

    def tearDown(self):
        engine.config = self._config

    def test_registration_risk_marker_is_recoverable(self):
        logs = []
        state = {
            "denied": True,
            "found": True,
            "bot_flag_source": 7,
            "bot_flag_details": "policy=deny,event=$registration",
        }
        with (
            mock.patch.object(engine._s2cpa, "inspect_sso_account_state", return_value=state),
            mock.patch.object(engine, "_append_sso_risk_rejected") as save_rejected,
        ):
            result = engine.ensure_sso_oauth_eligible(
                "initial-sso", email="new@example.com", log_callback=logs.append
            )

        self.assertIs(result, state)
        save_rejected.assert_not_called()
        self.assertTrue(any("重新登录刷新 SSO" in message for message in logs))

    def test_refreshes_sso_with_the_registered_credentials(self):
        logs = []
        with mock.patch(
            "backend.registration.login_flow.login_with_password",
            return_value="refreshed-sso",
        ) as login:
            result = engine.refresh_sso_after_registration_risk(
                "initial-sso",
                email="new@example.com",
                password="secret",
                log_callback=logs.append,
            )

        self.assertEqual(result, "refreshed-sso")
        login.assert_called_once_with(
            "new@example.com", "secret", timeout=100, log_callback=logs.append
        )
        self.assertTrue(any("已通过重新登录刷新 SSO" in message for message in logs))


if __name__ == "__main__":
    unittest.main()
