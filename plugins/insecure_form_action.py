from __future__ import annotations

from urllib.parse import urlsplit

from core.plugins import BasePlugin
from core.runtime import PluginResult


class InsecureFormActionPlugin(BasePlugin):
    """Flag forms that submit over cleartext HTTP instead of HTTPS."""

    NAME = "insecure_form_action"
    DESCRIPTION = (
        "Flags forms that submit over cleartext HTTP, especially password forms"
    )

    def supports(self, inventory) -> bool:
        return bool(inventory.forms)

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        reported = self.context.inputs.setdefault(
            "insecure_form_action_reported", set()
        )

        for form in inventory.forms:
            action = form.action or inventory.url
            if urlsplit(action).scheme.lower() != "http":
                continue
            key = self._action_key(action)
            if key in reported:
                continue
            reported.add(key)

            severity = (
                settings["password_form_severity"]
                if form.has_password
                else settings["default_severity"]
            )
            carries = "a password field" if form.has_password else "form data"
            result.findings.append(
                self.finding(
                    title="Form submits over cleartext HTTP",
                    description=(
                        f"A form on this page submits {carries} to an http:// "
                        "URL, so its contents travel unencrypted and can be "
                        "read or altered by anyone on the network path."
                    ),
                    severity=severity,
                    evidence={
                        "page": inventory.url,
                        "form_action": action,
                        "method": form.method,
                        "has_password": form.has_password,
                    },
                )
            )
        return result

    @staticmethod
    def _action_key(action: str) -> str:
        parts = urlsplit(action)
        return f"{parts.scheme.lower()}://{parts.netloc.lower()}{parts.path}"
