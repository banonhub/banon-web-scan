from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult


class ConsoleErrorsPlugin(BasePlugin):
    """Capture severe JavaScript console errors reported after page load."""

    NAME = "console_errors"
    DESCRIPTION = "Captures severe JavaScript console errors after page load"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)

        try:
            entries = self.context.driver.get_log("browser")
        except Exception:
            # Browser log capture is unavailable (driver not configured for it).
            return result

        levels = set(settings["report_levels"])
        ignore = [term.lower() for term in settings["ignore_substrings"]]
        messages: list[str] = []
        for entry in entries:
            if entry.get("level") not in levels:
                continue
            message = str(entry.get("message", ""))
            if any(term in message.lower() for term in ignore):
                continue
            messages.append(message)

        messages = messages[: int(settings["maximum_messages"])]
        if messages:
            result.findings.append(
                self.finding(
                    title="JavaScript console errors detected",
                    description=(
                        "The browser reported severe console errors after the "
                        "page loaded."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "count": len(messages),
                        "messages": messages,
                    },
                )
            )
        return result
