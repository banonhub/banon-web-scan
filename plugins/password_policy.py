from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import (
    contains_any,
    fillable_controls,
    form_semantics,
    generic_value,
    identity_control,
    password_controls,
    visible_messages,
)


class PasswordPolicyPlugin(BasePlugin):
    """Check whether weak passwords are clearly rejected."""

    NAME = "password_policy"
    DESCRIPTION = "Checks signup/change-password forms reject weak passwords"

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done:{inventory.url}"):
            return False
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        return any(self._candidate_form(form, inventory, settings) for form in inventory.forms)

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        self.context.inputs[f"{self.NAME}_done:{inventory.url}"] = True
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        form = next(
            (
                form
                for form in inventory.forms
                if self._candidate_form(form, inventory, settings)
            ),
            None,
        )
        if form is None:
            return result

        try:
            self.browser.open(page.url)
            current = self.browser.inspect()
            refreshed = next(
                (
                    item
                    for item in current.forms
                    if item.action == form.action and item.method == form.method
                ),
                current.forms[0] if current.forms else None,
            )
            if refreshed is None:
                return result
            controls = current.controls_for_form(refreshed)
            self._fill_form(controls, settings)
            before = self.detector.capture(current)
            self.browser.submit(refreshed)
            after = self.browser.inspect()
            changed = self.detector.authentication_changed(
                before,
                self.detector.capture(after),
            )
        except Exception:
            return result

        text = " ".join([after.body_text, *after.messages]).lower()
        rejected = contains_any(text, settings["rejection_terms"])
        if not rejected and (changed or after.url != page.url or not after.messages):
            result.findings.append(
                self.finding(
                    title="Weak password was not clearly rejected",
                    description=(
                        "A weak password submission on a password-setting form "
                        "did not produce a clear rejection message."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "form_action": form.action,
                        "messages": visible_messages(after),
                    },
                )
            )
        return result

    def _candidate_form(self, form, inventory, settings) -> bool:
        if not form.has_password:
            return False
        semantics = form_semantics(form, inventory)
        if contains_any(semantics, settings["skip_terms"]):
            return False
        return self.detector.is_registration_form(form, inventory) or contains_any(
            semantics,
            settings["form_terms"],
        )

    def _fill_form(self, controls, settings) -> None:
        identity = identity_control(
            controls,
            self.context.settings.get("authentication", "identity_control_types"),
            self.context.settings.get("authentication", "identity_semantic_terms"),
        )
        if identity is not None:
            self.browser.fill(identity, settings["test_email"])
        for control in password_controls(controls):
            self.browser.fill(control, settings["weak_password"])
        for control in fillable_controls(
            controls,
            self.context.settings.get("workflows", "fillable_control_types"),
        ):
            if control.control_type == "password" or control is identity:
                continue
            if control.required:
                self.browser.fill(control, generic_value(control, settings))

