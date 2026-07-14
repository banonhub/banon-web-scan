from __future__ import annotations

from core.browser.interaction_engine import InteractionEngine
from core.browser.page_inspector import PageInspector
from core.config.settings import ScannerSettings
from core.runtime.entities import ControlTarget, FormTarget, PageInventory


class BasePage:
    """Generic browser facade: inventory first, then semantic interaction."""

    def __init__(self, driver, settings: ScannerSettings):
        self.driver = driver
        self.settings = settings
        self.inspector = PageInspector(driver, settings)
        self.actions = InteractionEngine(driver, settings)

    def open(self, url: str) -> PageInventory:
        self.actions.navigate(url)
        return self.inspector.inspect_current()

    def inspect(self) -> PageInventory:
        return self.inspector.inspect_current()

    def fill(self, control: ControlTarget, value: str) -> None:
        self.actions.fill(control, value)

    def submit(self, form: FormTarget) -> None:
        self.actions.submit(form)
