from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import csrf_like_controls, form_semantics, state_changing_forms


class CsrfPresencePlugin(BasePlugin):
    """Check state-changing forms for CSRF-like hidden tokens."""

    NAME = "csrf_presence"
    DESCRIPTION = "Checks state-changing forms for CSRF-like hidden tokens"

    def supports(self, inventory) -> bool:
        return bool(
            state_changing_forms(
                inventory,
                skip_terms=self.context.settings.get(
                    "plugins",
                    "settings",
                    self.NAME,
                )["skip_terms"],
            )
        )

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        for form in state_changing_forms(inventory, skip_terms=settings["skip_terms"]):
            controls = inventory.controls_for_form(form)
            if csrf_like_controls(controls, settings["token_terms"]):
                continue
            result.findings.append(
                self.finding(
                    title="State-changing form has no CSRF token",
                    description=(
                        "A non-GET form did not expose a hidden field that "
                        "looks like a CSRF token."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "form_action": form.action,
                        "form_method": form.method,
                        "form": form_semantics(form, inventory)[:120],
                    },
                )
            )
        return result

