from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select

from core.runtime.entities import ControlTarget


class ControlAdapterRegistry:
    """Normalize interaction with native and custom web controls."""

    def __init__(self, driver):
        self.driver = driver

    def fill(self, element, target: ControlTarget, value: str) -> None:
        if target.tag == "select":
            select = Select(element)
            try:
                select.select_by_visible_text(value)
            except Exception:
                option = next(
                    (
                        item
                        for item in select.options
                        if item.is_enabled()
                        and item.get_attribute("value") not in {"", None}
                    ),
                    None,
                )
                if option is None:
                    raise
                option.click()
            return
        if target.control_type in {"checkbox", "radio"}:
            desired = str(value).lower() in {"1", "true", "yes", "on"}
            if element.is_selected() != desired:
                element.click()
            return
        if target.control_type == "range":
            self.driver.execute_script(
                """
                const element = arguments[0];
                element.value = arguments[1];
                element.dispatchEvent(new Event("input", {bubbles: true}));
                element.dispatchEvent(new Event("change", {bubbles: true}));
                """,
                element,
                value,
            )
            return
        if target.attributes.get("contenteditable"):
            element.click()
            element.send_keys(Keys.CONTROL, "a")
            element.send_keys(value)
            return
        if target.role in {"combobox", "textbox"} and target.tag not in {
            "input",
            "textarea",
        }:
            self.driver.execute_script(
                """
                const element = arguments[0];
                const value = arguments[1];
                element.focus();
                element.textContent = value;
                element.dispatchEvent(new InputEvent(
                  "input", {bubbles: true, data: value}
                ));
                element.dispatchEvent(new Event("change", {bubbles: true}));
                """,
                element,
                value,
            )
            return

        try:
            element.clear()
        except Exception:
            element.click()
            element.send_keys(Keys.CONTROL, "a")
        element.send_keys(value)
