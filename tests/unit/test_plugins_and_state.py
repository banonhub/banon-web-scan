import unittest

from core.config import parse_args
from core.plugins.plugin_manager import PluginManager
from core.runtime.entities import (
    ControlTarget,
    FormTarget,
    PageInventory,
)
from core.workflows.state_detector import BrowserState, StateDetector


class FakeDriver:
    def get_cookies(self):
        return []


class PluginAndStateTests(unittest.TestCase):
    def setUp(self):
        self.settings = parse_args(["--target", "https://target.test"])

    def test_installed_plugins_are_discovered_without_registration(self):
        library = PluginManager(self.settings).discover()
        self.assertEqual(
            set(library),
            {
                "back_cache",
                "browser_storage",
                "console_errors",
                "cookie_flags",
                "cross_user_access",
                "csrf_presence",
                "csrf_uniqueness",
                "form_validation",
                "csp_strength",
                "headers",
                "https",
                "info_headers",
                "input_robustness",
                "insecure_form_action",
                "login_errors",
                "login_rate_limit",
                "logout_invalidation",
                "mixed_content",
                "page_health",
                "password_policy",
                "protected_routes",
                "reset_enum",
                "role_ui",
                "session_rotation",
                "url_secrets",
            },
        )

    def test_select_all_returns_every_plugin(self):
        manager = PluginManager(self.settings)
        manager.discover()
        self.assertEqual(len(manager.select(["all"])), 25)

    def test_select_single_plugin_by_name(self):
        manager = PluginManager(self.settings)
        manager.discover()
        selected = manager.select(["headers"])
        self.assertEqual([plugin.NAME for plugin in selected], ["headers"])

    def test_generic_inventory_recognizes_login_form(self):
        identity = ControlTarget(
            element_id="identity",
            frame_path=(),
            tag="input",
            control_type="email",
            label="Account email",
            form_id="form",
        )
        password = ControlTarget(
            element_id="secret",
            frame_path=(),
            tag="input",
            control_type="password",
            label="Secret",
            form_id="form",
        )
        form = FormTarget(
            element_id="form",
            frame_path=(),
            action="https://target.test/session",
            method="post",
            text="Continue",
            control_ids=("identity", "secret"),
            has_password=True,
        )
        inventory = PageInventory(
            url="https://target.test/session",
            title="Session",
            body_text="",
            controls=[identity, password],
            forms=[form],
        )
        detector = StateDetector(FakeDriver(), self.settings)
        self.assertTrue(detector.is_login_form(form, inventory))

    def test_registration_form_is_not_treated_as_login(self):
        identity = ControlTarget(
            element_id="identity",
            frame_path=(),
            tag="input",
            control_type="email",
            label="Account email",
            form_id="form",
        )
        password = ControlTarget(
            element_id="secret",
            frame_path=(),
            tag="input",
            control_type="password",
            label="Create password",
            form_id="form",
        )
        form = FormTarget(
            element_id="form",
            frame_path=(),
            action="https://target.test/register",
            method="post",
            text="Create account",
            control_ids=("identity", "secret"),
            has_password=True,
        )
        inventory = PageInventory(
            url="https://target.test/register",
            title="Register",
            body_text="",
            controls=[identity, password],
            forms=[form],
        )
        detector = StateDetector(FakeDriver(), self.settings)
        self.assertTrue(detector.is_registration_form(form, inventory))
        self.assertFalse(detector.is_login_form(form, inventory))

    def test_login_form_with_signup_link_remains_login(self):
        identity = ControlTarget(
            element_id="identity",
            frame_path=(),
            tag="input",
            control_type="text",
            label="Username",
            form_id="form",
        )
        password = ControlTarget(
            element_id="secret",
            frame_path=(),
            tag="input",
            control_type="password",
            label="Password",
            form_id="form",
        )
        submit = ControlTarget(
            element_id="submit",
            frame_path=(),
            tag="button",
            control_type="submit",
            text="Log in",
            form_id="form",
        )
        form = FormTarget(
            element_id="form",
            frame_path=(),
            action="https://target.test/session",
            method="post",
            text="Log in or visit Sign up",
            control_ids=("identity", "secret", "submit"),
            has_password=True,
        )
        inventory = PageInventory(
            url="https://target.test/session",
            title="Session",
            body_text="",
            controls=[identity, password, submit],
            forms=[form],
        )
        detector = StateDetector(FakeDriver(), self.settings)
        self.assertFalse(detector.is_registration_form(form, inventory))
        self.assertTrue(detector.is_login_form(form, inventory))

    def test_authentication_requires_configured_signal_count(self):
        detector = StateDetector(FakeDriver(), self.settings)
        before = BrowserState(
            url="https://target.test/session",
            fingerprint="one",
            cookie_names=frozenset(),
            login_form_present=True,
            authenticated_control_present=False,
        )
        after = BrowserState(
            url="https://target.test/account",
            fingerprint="two",
            cookie_names=frozenset({"session"}),
            login_form_present=False,
            authenticated_control_present=True,
        )
        self.assertTrue(detector.authentication_changed(before, after))

    def test_failed_login_still_showing_form_is_not_authentication(self):
        # A failed login that redirects to an error page and sets a flash
        # cookie must not be read as a successful authentication.
        detector = StateDetector(FakeDriver(), self.settings)
        before = BrowserState(
            url="https://target.test/login",
            fingerprint="one",
            cookie_names=frozenset(),
            login_form_present=True,
            authenticated_control_present=False,
        )
        after = BrowserState(
            url="https://target.test/login?error=1",
            fingerprint="two",
            cookie_names=frozenset({"flash"}),
            login_form_present=True,
            authenticated_control_present=False,
        )
        self.assertFalse(detector.authentication_changed(before, after))


if __name__ == "__main__":
    unittest.main()
