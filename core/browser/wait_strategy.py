import time

from selenium.webdriver.support.ui import WebDriverWait

from core.config.settings import ScannerSettings


class WaitStrategy:
    """Wait for document readiness and a configurable period of DOM stability."""

    def __init__(self, driver, settings: ScannerSettings):
        self.driver = driver
        self.settings = settings

    def page_ready(self) -> None:
        timeout = self.settings.timeout
        readiness = self.settings.get("interaction", "ready_state")
        WebDriverWait(self.driver, timeout).until(
            lambda current: current.execute_script(
                "return document.readyState"
            )
            in readiness
        )
        self.dom_stable()

    def dom_stable(self) -> None:
        config = self.settings.get("interaction", "dom_stability")
        interval = float(config["poll_interval"])
        required = int(config["stable_polls"])
        maximum = float(config["maximum_wait"])
        deadline = time.monotonic() + maximum
        stable = 0
        previous = None

        while time.monotonic() < deadline and stable < required:
            try:
                signature = self.driver.execute_script(
                    """
                    return [
                      document.readyState,
                      document.documentElement.innerHTML.length,
                      document.querySelectorAll("*").length
                    ].join(":");
                    """
                )
            except Exception:
                return
            if signature == previous:
                stable += 1
            else:
                stable = 0
                previous = signature
            time.sleep(interval)

    def after_action(self) -> None:
        delay = float(self.settings.get("interaction", "post_action_delay"))
        if delay:
            time.sleep(delay)
        try:
            self.page_ready()
        except Exception:
            self.dom_stable()
