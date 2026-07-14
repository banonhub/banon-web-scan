"""Generic browser inspection and interaction capabilities."""

from core.browser.base_page import BasePage
from core.browser.driver_factory import create_driver
from core.browser.interaction_engine import InteractionEngine
from core.browser.page_inspector import PageInspector

__all__ = ["BasePage", "InteractionEngine", "PageInspector", "create_driver"]
