from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from core.config.settings import ScannerSettings


def _position_browser(driver, settings: ScannerSettings) -> None:
    layout = settings.get("browser", "window")
    if layout["layout"] != "split":
        return
    try:
        screen = driver.execute_script(
            "return {width: screen.availWidth, height: screen.availHeight};"
        )
        width = int(screen["width"])
        height = int(screen["height"])
        ratio = float(layout["split_ratio"])
        left = int(width * ratio)
        driver.set_window_rect(
            x=left,
            y=0,
            width=width - left,
            height=height,
        )
    except Exception:
        return


def create_driver(settings: ScannerSettings):
    """Create the one shared browser used by the complete scan context."""
    browser = settings.get("browser")
    options = webdriver.ChromeOptions()
    arguments = (
        browser["headless_arguments"]
        if settings.headless
        else browser["visible_arguments"]
    )
    for argument in [*arguments, *browser["common_arguments"]]:
        options.add_argument(argument)

    if browser.get("capture_browser_logs"):
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_page_load_timeout(settings.timeout)
    if not settings.headless:
        _position_browser(driver, settings)
    return driver
