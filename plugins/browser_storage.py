from __future__ import annotations

import re

from core.plugins import BasePlugin
from core.runtime import PluginResult


class BrowserStoragePlugin(BasePlugin):
    """Check browser storage for secret-looking values."""

    NAME = "browser_storage"
    DESCRIPTION = "Checks localStorage/sessionStorage for secrets"

    def supports(self, inventory) -> bool:
        return True

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        try:
            storage = self.context.driver.execute_script(
                """
                const dump = store => {
                  const values = {};
                  for (let index = 0; index < store.length; index += 1) {
                    const key = store.key(index);
                    values[key] = store.getItem(key);
                  }
                  return values;
                };
                return {
                  localStorage: dump(window.localStorage),
                  sessionStorage: dump(window.sessionStorage)
                };
                """
            )
        except Exception:
            return result

        patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in settings["secret_patterns"]
        ]
        matches = []
        for store_name, values in (storage or {}).items():
            for key, value in (values or {}).items():
                text = f"{key} {value}"
                if any(pattern.search(text) for pattern in patterns):
                    matches.append(
                        {
                            "store": store_name,
                            "key": key,
                            "value_preview": self._preview(value),
                        }
                    )

        if matches:
            result.findings.append(
                self.finding(
                    title="Browser storage contains secret-looking data",
                    description=(
                        "localStorage or sessionStorage contained keys or "
                        "values that look like tokens, passwords, or API keys."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "matches": matches[: int(settings["maximum_matches"])],
                    },
                )
            )
        return result

    @staticmethod
    def _preview(value: object) -> str:
        text = str(value or "")
        if len(text) <= 12:
            return "*" * len(text)
        return f"{text[:4]}...{text[-4:]}"
