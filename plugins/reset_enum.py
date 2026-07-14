from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import (
    contains_any,
    fillable_controls,
    form_semantics,
    identity_control,
    redact_identity,
    visible_messages,
)


class PasswordResetEnumerationPlugin(BasePlugin):
    """Compare reset responses for valid-looking and invalid identities."""

    NAME = "reset_enum"
    DESCRIPTION = "Checks password reset responses for account enumeration"

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done:{inventory.url}"):
            return False
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        return any(self._candidate_form(form, inventory, settings) for form in inventory.forms)

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        self.context.inputs[f"{self.NAME}_done:{inventory.url}"] = True
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        valid_identity = self.context.settings.username or settings["valid_identity"]
        invalid_identity = settings["invalid_identity"]

        valid = self._attempt(page.url, settings, valid_identity)
        invalid = self._attempt(page.url, settings, invalid_identity)
        if valid is None or invalid is None:
            return result

        signals: list[str] = []
        if set(valid["messages"]) != set(invalid["messages"]):
            signals.append("visible_messages")
        base_length = max(invalid["body_length"], 1)
        delta = abs(valid["body_length"] - base_length) / base_length
        if delta >= float(settings["minimum_body_length_ratio"]):
            signals.append("body_length")

        if signals:
            result.findings.append(
                self.finding(
                    title="Password reset may reveal account existence",
                    description=(
                        "The reset flow produced different responses for a "
                        "valid-looking identity and an invalid identity."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "signals": signals,
                        "valid_messages": [
                            redact_identity(message, self.context.settings.username)
                            for message in valid["messages"]
                        ],
                        "invalid_messages": invalid["messages"],
                    },
                )
            )
        return result

    def _candidate_form(self, form, inventory, settings) -> bool:
        if form.has_password:
            return False
        return contains_any(form_semantics(form, inventory), settings["form_terms"])

    def _attempt(self, url: str, settings: dict, identity: str):
        try:
            inventory = self.browser.open(url)
        except Exception:
            return None
        form = next(
            (
                form
                for form in inventory.forms
                if self._candidate_form(form, inventory, settings)
            ),
            None,
        )
        if form is None:
            return None
        controls = inventory.controls_for_form(form)
        identity_field = identity_control(
            controls,
            self.context.settings.get("authentication", "identity_control_types"),
            self.context.settings.get("authentication", "identity_semantic_terms"),
        )
        if identity_field is None:
            fillable = fillable_controls(
                controls,
                self.context.settings.get("workflows", "fillable_control_types"),
            )
            identity_field = fillable[0] if fillable else None
        if identity_field is None:
            return None
        try:
            self.browser.fill(identity_field, identity)
            self.browser.submit(form)
            after = self.browser.inspect()
        except Exception:
            return None
        return {
            "messages": [message.lower() for message in visible_messages(after)],
            "body_length": len((after.body_text or "").strip()),
        }

