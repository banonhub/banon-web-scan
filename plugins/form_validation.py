from __future__ import annotations

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import (
    contains_any,
    fillable_controls,
    form_semantics,
    state_changing_forms,
    visible_messages,
)


class FormValidationPlugin(BasePlugin):
    """Submit invalid values and check for clean validation handling."""

    NAME = "form_validation"
    DESCRIPTION = "Checks invalid form submissions get clean validation messages"

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done:{inventory.url}"):
            return False
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        forms = self._candidate_forms(inventory, settings)
        return bool(forms)

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        self.context.inputs[f"{self.NAME}_done:{inventory.url}"] = True
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        form = next(iter(self._candidate_forms(inventory, settings)), None)
        if form is None:
            return result

        try:
            self.browser.open(page.url)
            current = self.browser.inspect()
            refreshed = current.forms[min(inventory.forms.index(form), len(current.forms) - 1)]
            controls = current.controls_for_form(refreshed)
            for control in fillable_controls(controls, settings["control_types"]):
                if control.required:
                    self.browser.fill(control, settings["invalid_value"])
            self.browser.submit(refreshed)
            after = self.browser.inspect()
        except Exception:
            return result

        status = self._status(after.url, float(settings["request_timeout"]))
        text = " ".join([after.body_text, *after.messages]).lower()
        crashed = (
            status in settings["server_error_status_codes"]
            if status is not None
            else False
        ) or contains_any(text, settings["error_terms"])
        has_validation = contains_any(text, settings["validation_terms"])
        if crashed or not has_validation:
            result.findings.append(
                self.finding(
                    title="Form validation is missing or unstable",
                    description=(
                        "Submitting invalid form values did not produce a clear "
                        "validation response, or it produced an error state."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "form_action": form.action,
                        "status_code": status,
                        "messages": visible_messages(after),
                        "crashed": crashed,
                    },
                )
            )
        return result

    def _candidate_forms(self, inventory, settings):
        forms = state_changing_forms(inventory, skip_terms=settings["skip_terms"])
        if not forms:
            forms = [
                form
                for form in inventory.forms
                if not contains_any(form_semantics(form, inventory), settings["skip_terms"])
            ]
        return forms[: int(settings["maximum_forms"])]

    def _status(self, url: str, timeout: float) -> int | None:
        try:
            with client_from_driver(
                self.context.driver,
                self.context.settings,
                timeout=timeout,
            ) as client:
                return client.get(url).status_code
        except Exception:
            return None

