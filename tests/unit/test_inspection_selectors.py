import tempfile
import unittest
from pathlib import Path

from core.browser.page_inspector import PageInspector
from core.config import parse_args


class ExtraSelectorTests(unittest.TestCase):
    def _inspector(self, argv):
        settings = parse_args(argv)
        return PageInspector(driver=None, settings=settings), settings

    def test_no_extra_selectors_returns_base_config_unchanged(self):
        inspector, settings = self._inspector(["--target", "https://target.test"])
        base = settings.get("inspection")["control_selector"]
        effective = inspector._effective_inspection()
        self.assertEqual(effective["control_selector"], base)

    def test_extra_selectors_are_appended_to_control_selector(self):
        inspector, settings = self._inspector(
            [
                "--target",
                "https://target.test",
                "--extra-selectors",
                ".widget",
                "my-custom-element",
            ]
        )
        base = settings.get("inspection")["control_selector"]
        effective = inspector._effective_inspection()
        self.assertEqual(
            effective["control_selector"],
            f"{base}, .widget, my-custom-element",
        )
        # The shared defaults document must stay untouched.
        self.assertEqual(settings.get("inspection")["control_selector"], base)

    def test_extra_selectors_file_is_loaded_and_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            selector_file = Path(tmp) / "selectors.txt"
            selector_file.write_text(
                "# custom controls\n"
                ".card-button\n"
                "\n"
                "[data-widget]\n",
                encoding="utf-8",
            )
            settings = parse_args(
                [
                    "--target",
                    "https://target.test",
                    "--extra-selectors",
                    ".widget",
                    "--extra-selectors-file",
                    str(selector_file),
                ]
            )
        self.assertEqual(
            settings.extra_selectors,
            [".widget", ".card-button", "[data-widget]"],
        )


if __name__ == "__main__":
    unittest.main()
