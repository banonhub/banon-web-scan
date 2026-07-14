from __future__ import annotations

import time

from selenium.common.exceptions import (
    NoAlertPresentException,
    UnexpectedAlertPresentException,
)

from core.browser.browsing_context import BrowsingContext
from core.browser.control_adapters import ControlAdapterRegistry
from core.browser.wait_strategy import WaitStrategy
from core.config.settings import ScannerSettings
from core.runtime.entities import ControlTarget, FormTarget


class InteractionEngine:
    """Operate on normalized targets regardless of document/frame/shadow origin."""

    def __init__(self, driver, settings: ScannerSettings):
        self.driver = driver
        self.settings = settings
        self.contexts = BrowsingContext(driver, settings)
        self.wait = WaitStrategy(driver, settings)
        self.adapters = ControlAdapterRegistry(driver)

    def navigate(self, url: str) -> None:
        self.contexts.reset()
        try:
            self.driver.get(url)
        except UnexpectedAlertPresentException:
            self._accept_alert()
        try:
            self.wait.page_ready()
        except UnexpectedAlertPresentException:
            self._accept_alert()
            self.wait.page_ready()
        self.watch_note("Inspecting page", url, pause_key="page_pause")

    def locate(self, target: ControlTarget | FormTarget):
        self.contexts.activate(target.frame_path)
        marker = self.settings.get("inspection", "marker_attribute")
        element = self.driver.execute_script(
            """
            const marker = arguments[0];
            const value = arguments[1];
            const find = root => {
              for (const element of root.querySelectorAll("*")) {
                if (element.getAttribute(marker) === value) return element;
                if (element.shadowRoot) {
                  const nested = find(element.shadowRoot);
                  if (nested) return nested;
                }
              }
              return null;
            };
            return find(document);
            """,
            marker,
            target.element_id,
        )
        if element is None:
            raise LookupError(f"Element is no longer available: {target.element_id}")
        return element

    def fill(self, target: ControlTarget, value: str) -> None:
        element = self.locate(target)
        self._show_target(element, f"Fill {self._target_name(target)}")
        self.adapters.fill(element, target, value)
        self.watch_pause("action_pause")

    def click(self, target: ControlTarget) -> None:
        element = self.locate(target)
        self._show_target(element, f"Click {self._target_name(target)}")
        try:
            element.click()
        except Exception:
            self.driver.execute_script("arguments[0].click();", element)
        self.wait.after_action()
        self.watch_pause("action_pause")

    def submit(self, form: FormTarget) -> None:
        element = self.locate(form)
        self._show_target(element, "Submit form")
        self.driver.execute_script(
            """
            const form = arguments[0];
            if (form.requestSubmit) form.requestSubmit();
            else form.submit();
            """,
            element,
        )
        self.wait.after_action()
        self.watch_pause("action_pause")

    def watch_note(
        self,
        title: str,
        detail: str = "",
        *,
        pause_key: str = "plugin_pause",
    ) -> None:
        if not self._watch_enabled():
            return
        try:
            self.driver.execute_script(
                """
                const title = arguments[0];
                const detail = arguments[1];
                const bannerId = "__banon_watch_banner";
                let banner = document.getElementById(bannerId);
                if (!banner) {
                  banner = document.createElement("div");
                  banner.id = bannerId;
                  Object.assign(banner.style, {
                    position: "fixed",
                    top: "12px",
                    right: "12px",
                    zIndex: "2147483647",
                    maxWidth: "420px",
                    padding: "10px 12px",
                    border: "1px solid rgba(0, 170, 255, 0.7)",
                    borderRadius: "6px",
                    background: "rgba(5, 18, 32, 0.92)",
                    color: "#f7fbff",
                    font: "13px/1.35 system-ui, -apple-system, Segoe UI, sans-serif",
                    boxShadow: "0 10px 30px rgba(0, 0, 0, 0.28)",
                    pointerEvents: "none"
                  });
                  document.documentElement.appendChild(banner);
                }
                banner.textContent = detail ? `${title}: ${detail}` : title;
                """,
                title,
                detail,
            )
        except Exception:
            return
        self.watch_pause(pause_key)

    def watch_pause(self, key: str) -> None:
        if not self._watch_enabled():
            return
        delay = float(self.settings.get("browser", "watch").get(key, 0))
        if delay > 0:
            time.sleep(delay)

    def _show_target(self, element, label: str) -> None:
        if not self._watch_enabled():
            return
        config = self.settings.get("browser", "watch")
        restore_ms = int(
            max(
                float(config["highlight_duration"])
                + float(config["action_pause"]),
                0.5,
            )
            * 1000
        )
        try:
            self.driver.execute_script(
                """
                const element = arguments[0];
                const label = arguments[1];
                const outline = arguments[2];
                const background = arguments[3];
                const block = arguments[4];
                const restoreMs = arguments[5];
                element.scrollIntoView({
                  block: block || "center",
                  inline: "center",
                  behavior: "auto"
                });
                const previous = {
                  outline: element.style.outline,
                  backgroundColor: element.style.backgroundColor,
                  boxShadow: element.style.boxShadow
                };
                const token = `${Date.now()}-${Math.random()}`;
                element.dataset.banonWatchToken = token;
                element.style.outline = outline;
                element.style.backgroundColor = background;
                element.style.boxShadow = "0 0 0 4px rgba(0, 170, 255, 0.24)";
                const tag = document.createElement("div");
                tag.textContent = label;
                Object.assign(tag.style, {
                  position: "fixed",
                  left: "12px",
                  bottom: "12px",
                  zIndex: "2147483647",
                  padding: "8px 10px",
                  borderRadius: "6px",
                  background: "rgba(5, 18, 32, 0.92)",
                  color: "#f7fbff",
                  font: "13px/1.35 system-ui, -apple-system, Segoe UI, sans-serif",
                  pointerEvents: "none"
                });
                document.documentElement.appendChild(tag);
                setTimeout(() => {
                  if (element.dataset.banonWatchToken === token) {
                    element.style.outline = previous.outline;
                    element.style.backgroundColor = previous.backgroundColor;
                    element.style.boxShadow = previous.boxShadow;
                    delete element.dataset.banonWatchToken;
                  }
                  tag.remove();
                }, restoreMs);
                """,
                element,
                label,
                config["highlight_outline"],
                config["highlight_background"],
                config["scroll_block"],
                restore_ms,
            )
        except Exception:
            return
        self.watch_pause("highlight_duration")

    def _watch_enabled(self) -> bool:
        return bool(self.settings.watch) and not self.settings.headless

    def _accept_alert(self) -> str:
        try:
            alert = self.driver.switch_to.alert
            text = alert.text
            alert.accept()
            return text
        except NoAlertPresentException:
            return ""

    @staticmethod
    def _target_name(target: ControlTarget | FormTarget) -> str:
        if isinstance(target, FormTarget):
            return target.action or target.element_id
        for value in (
            target.label,
            target.placeholder,
            target.name,
            target.html_id,
            target.text,
            target.role,
        ):
            if value:
                return value
        return target.element_id
