import unittest

from core.config import parse_args
from core.runtime.entities import FormTarget, PageInventory
from core.runtime.scan_context import ScanContext
from plugins.insecure_form_action import InsecureFormActionPlugin


def _form(action, *, has_password=False, method="post"):
    return FormTarget(
        element_id=f"form-{action}",
        frame_path=(),
        action=action,
        method=method,
        text="",
        control_ids=(),
        has_password=has_password,
    )


def _inventory(url, forms):
    return PageInventory(url=url, title="Test", body_text="", forms=forms)


class InsecureFormActionTests(unittest.TestCase):
    def setUp(self):
        self.settings = parse_args(["--target", "https://target.test"])
        self.context = ScanContext(self.settings)
        self.plugin = InsecureFormActionPlugin(self.context, None, None, None)

    def test_supports_requires_forms(self):
        self.assertFalse(self.plugin.supports(_inventory("http://t.test", [])))
        self.assertTrue(
            self.plugin.supports(
                _inventory("http://t.test", [_form("http://t.test/x")])
            )
        )

    def test_http_password_form_is_high_severity(self):
        inventory = _inventory(
            "https://t.test/login",
            [_form("http://t.test/login", has_password=True)],
        )
        result = self.plugin.scan(page=None, inventory=inventory)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "HIGH")
        self.assertEqual(
            result.findings[0].evidence["form_action"],
            "http://t.test/login",
        )

    def test_http_non_password_form_is_default_severity(self):
        inventory = _inventory(
            "http://t.test/search",
            [_form("http://t.test/search", has_password=False)],
        )
        result = self.plugin.scan(page=None, inventory=inventory)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "MEDIUM")

    def test_https_form_produces_no_finding(self):
        inventory = _inventory(
            "https://t.test/login",
            [_form("https://t.test/login", has_password=True)],
        )
        result = self.plugin.scan(page=None, inventory=inventory)
        self.assertEqual(result.findings, [])

    def test_same_action_is_reported_once(self):
        inventory = _inventory(
            "https://t.test/a",
            [_form("http://t.test/login", has_password=True)],
        )
        first = self.plugin.scan(page=None, inventory=inventory)
        second = self.plugin.scan(page=None, inventory=inventory)
        self.assertEqual(len(first.findings), 1)
        self.assertEqual(second.findings, [])


if __name__ == "__main__":
    unittest.main()
