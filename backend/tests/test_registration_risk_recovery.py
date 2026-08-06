import unittest
from unittest import mock

from backend.registration import engine
from backend.registration import login_flow


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

    def test_sso_wait_failure_reuses_current_browser_sso(self):
        logs = []
        with (
            mock.patch.object(engine, "wait_for_sso_cookie", side_effect=RuntimeError("sso_timeout")),
            mock.patch.object(engine._rf, "current_sso_cookie", return_value="existing-sso"),
            mock.patch.object(engine, "refresh_sso_with_password") as refresh,
        ):
            result = engine.wait_for_registration_sso(
                "new@example.com", {"password": "secret"}, log_callback=logs.append
            )

        self.assertEqual(result, "existing-sso")
        refresh.assert_not_called()
        self.assertTrue(any("复用现有 SSO" in message for message in logs))

    def test_sso_wait_failure_relogs_only_when_no_current_sso_exists(self):
        with (
            mock.patch.object(engine, "wait_for_sso_cookie", side_effect=RuntimeError("sso_timeout")),
            mock.patch.object(engine._rf, "current_sso_cookie", return_value=""),
            mock.patch.object(engine, "refresh_sso_with_password", return_value="fresh-sso") as refresh,
        ):
            result = engine.wait_for_registration_sso(
                "new@example.com", {"password": "secret"}
            )

        self.assertEqual(result, "fresh-sso")
        refresh.assert_called_once()

    def test_login_reuses_sso_when_the_browser_is_already_logged_in(self):
        logs = []
        with (
            mock.patch.object(login_flow, "_navigate_signin"),
            mock.patch.object(login_flow, "_read_sso_cookie", return_value="existing-sso"),
            mock.patch.object(login_flow, "_dismiss_cookie_consent") as dismiss,
            mock.patch.object(login_flow, "_native_click_action") as click_login,
        ):
            result = login_flow.login_with_password(
                "new@example.com", "secret", log_callback=logs.append
            )

        self.assertEqual(result, "existing-sso")
        dismiss.assert_not_called()
        click_login.assert_not_called()
        self.assertTrue(any("当前浏览器已登录" in message for message in logs))

    def test_login_rechecks_sso_when_the_email_button_is_missing(self):
        with (
            mock.patch.object(login_flow, "_navigate_signin"),
            mock.patch.object(login_flow, "_dismiss_cookie_consent"),
            mock.patch.object(login_flow, "_read_sso_cookie", side_effect=("", "existing-sso")),
            mock.patch.object(login_flow, "_native_click_action", return_value=False),
        ):
            result = login_flow.login_with_password("new@example.com", "secret")

        self.assertEqual(result, "existing-sso")


if __name__ == "__main__":
    unittest.main()
