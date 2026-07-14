from __future__ import annotations

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult


class PageHealthPlugin(BasePlugin):
    """Detect blank pages, server errors, and crash/error screens."""

    NAME = "page_health"
    DESCRIPTION = "Detects blank pages, server errors, and crash/error screens"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)

        status = self._status_code(page.url, float(settings["request_timeout"]))
        if status is not None and status in settings["server_error_status_codes"]:
            result.findings.append(
                self.finding(
                    title="Server error response",
                    description=f"The page returned HTTP {status}.",
                    severity=settings["server_error_severity"],
                    evidence={"url": page.url, "status_code": status},
                )
            )
            return result

        body = (inventory.body_text or "").strip()
        signatures = [
            signature
            for signature in settings["error_content_signatures"]
            if signature.lower() in body.lower()
        ]
        if signatures:
            result.findings.append(
                self.finding(
                    title="Error or crash screen content",
                    description=(
                        "The page body contained text associated with an error "
                        "or crash screen."
                    ),
                    severity=settings["error_screen_severity"],
                    evidence={"url": page.url, "matched_signatures": signatures},
                )
            )
            return result

        looks_blank = (
            len(body) < int(settings["minimum_body_length"])
            and not inventory.forms
            and not inventory.controls
            and not inventory.links
        )
        if looks_blank:
            result.findings.append(
                self.finding(
                    title="Blank or empty page",
                    description=(
                        "The page rendered with almost no visible content, "
                        "controls, or links."
                    ),
                    severity=settings["blank_page_severity"],
                    evidence={"url": page.url, "body_length": len(body)},
                )
            )
        return result

    def _status_code(self, url: str, timeout: float) -> int | None:
        try:
            with client_from_driver(
                self.context.driver,
                self.context.settings,
                timeout=timeout,
            ) as client:
                return client.get(url).status_code
        except Exception:
            return None
