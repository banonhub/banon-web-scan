import unittest

from core.runtime.entities import (
    ControlTarget,
    FormTarget,
    PageInventory,
)
from core.runtime.results import Finding


class RuntimeEntityTests(unittest.TestCase):
    def test_form_controls_are_resolved_from_inventory(self):
        control = ControlTarget(
            element_id="one",
            frame_path=(0,),
            tag="input",
            control_type="text",
            label="Search",
            form_id="form",
        )
        form = FormTarget(
            element_id="form",
            frame_path=(0,),
            action="/search",
            method="get",
            text="",
            control_ids=("one",),
            has_password=False,
        )
        inventory = PageInventory(
            url="https://target.test",
            title="",
            body_text="",
            controls=[control],
            forms=[form],
        )
        self.assertEqual(inventory.controls_for_form(form), [control])
        self.assertIn("search", control.semantic_text)

    def test_finding_rejects_unknown_severity(self):
        with self.assertRaises(ValueError):
            Finding("Title", "Description", "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
