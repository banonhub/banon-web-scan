import unittest
from contextlib import redirect_stderr
from copy import deepcopy
from io import StringIO

from core.config import parse_args
from core.config.loader import normalize_target
from core.config.validator import validate_defaults


class ConfigurationTests(unittest.TestCase):
    def test_no_target_leaves_target_unset(self):
        settings = parse_args([])
        self.assertIsNone(settings.target)

    def test_target_is_normalized(self):
        settings = parse_args(["--target", "target.test/"])
        self.assertEqual(settings.target, "http://target.test")

    def test_target_normalization(self):
        self.assertEqual(
            normalize_target("target.test/"),
            "http://target.test",
        )
        self.assertEqual(
            normalize_target("https://target.test/app/"),
            "https://target.test/app",
        )

    def test_watch_mode_is_enabled_by_flag(self):
        settings = parse_args(["--watch"])
        self.assertTrue(settings.watch)
        self.assertFalse(settings.headless)

    def test_headless_mode_hides_browser(self):
        settings = parse_args(["--headless"])
        self.assertFalse(settings.watch)
        self.assertTrue(settings.headless)

    def test_secondary_credentials_are_supported_for_cross_user_checks(self):
        settings = parse_args(
            [
                "--secondary-username",
                "user2",
                "--secondary-password",
                "password2",
            ]
        )
        self.assertEqual(settings.secondary_username, "user2")
        self.assertEqual(settings.secondary_password, "password2")

    def test_watch_and_headless_cannot_be_combined(self):
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                parse_args(["--headless", "--watch"])

    def test_defaults_have_no_route_specific_login_assumption(self):
        settings = parse_args([])
        serialized = str(settings.defaults).lower()
        self.assertNotIn("/login", serialized)
        self.assertNotIn("/dashboard", serialized)
        self.assertNotIn("safe_control_terms", settings.defaults["workflows"])
        self.assertNotIn("ai fallback", serialized)

    def test_missing_required_default_is_rejected_at_startup(self):
        settings = parse_args([])
        invalid = deepcopy(settings.defaults)
        del invalid["inspection"]["control_selector"]
        with self.assertRaises(ValueError):
            validate_defaults(invalid)


if __name__ == "__main__":
    unittest.main()
