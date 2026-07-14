from selenium.webdriver.common.by import By

from core.config.settings import ScannerSettings


class BrowsingContext:
    """Switch safely between the main document and nested iframe contexts."""

    def __init__(self, driver, settings: ScannerSettings):
        self.driver = driver
        self.settings = settings

    def activate(self, frame_path: tuple[int, ...]) -> None:
        selector = self.settings.get("inspection", "frame_selector")
        self.driver.switch_to.default_content()
        for frame_index in frame_path:
            frames = self.driver.find_elements(By.CSS_SELECTOR, selector)
            if frame_index >= len(frames):
                raise LookupError(f"Frame path no longer exists: {frame_path}")
            self.driver.switch_to.frame(frames[frame_index])

    def reset(self) -> None:
        self.driver.switch_to.default_content()
