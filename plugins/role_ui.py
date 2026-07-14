from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import contains_any


class RoleUiPlugin(BasePlugin):
    """Detect admin-only affordances visible to the current normal user."""

    NAME = "role_ui"
    DESCRIPTION = "Checks normal users cannot see admin-only UI controls"
    REQUIRES_AUTH = True

    def supports(self, inventory) -> bool:
        return bool(self.context.authenticated)

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        matches = []
        for control in inventory.controls:
            text = control.semantic_text
            href = str(control.attributes.get("href", ""))
            if control.visible and contains_any(f"{text} {href}", settings["admin_terms"]):
                matches.append(
                    {
                        "tag": control.tag,
                        "type": control.control_type,
                        "text": text[:80],
                        "href": href[:160],
                    }
                )
        for link in inventory.links:
            if contains_any(link, settings["admin_terms"]):
                matches.append({"tag": "a", "type": "link", "href": link[:160]})

        if matches:
            result.findings.append(
                self.finding(
                    title="Admin UI visible to normal user",
                    description=(
                        "The authenticated page exposed controls or links that "
                        "look admin-only to the current user."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "matches": matches[: int(settings["maximum_matches"])],
                    },
                )
            )
        return result
