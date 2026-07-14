from __future__ import annotations

from core.net import client_from_driver
from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import contains_any, fillable_controls, form_semantics, visible_messages


class InputRobustnessPlugin(BasePlugin):
    """Send harmless edge-case input and look for crashes."""

    NAME = "input_robustness"
    DESCRIPTION = "Checks harmless special input does not crash pages"

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done:{inventory.url}"):
            return False
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        return any(self._candidate_forms(inventory, settings))

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        self.context.inputs[f"{self.NAME}_done:{inventory.url}"] = True
        settings = self.context.settings.get("plugins", "settings", self.NAME)
        forms = self._candidate_forms(inventory, settings)
        if not forms:
            return result
        form = forms[0]
        payload = settings["payload"]

        try:
            self.browser.open(page.url)
            current = self.browser.inspect()
            refreshed = current.forms[min(inventory.forms.index(form), len(current.forms) - 1)]
            controls = current.controls_for_form(refreshed)
            for control in fillable_controls(controls, settings["control_types"]):
                self.browser.fill(control, payload)
            self.browser.submit(refreshed)
            after = self.browser.inspect()
        except Exception as exc:
            result.findings.append(
                self.finding(
                    title="Input caused browser interaction failure",
                    description=(
                        "Submitting harmless edge-case input caused the browser "
                        "workflow to fail."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "form_action": form.action,
                        "error": str(exc),
                    },
                )
            )
            return result

        status = self._status(after.url, float(settings["request_timeout"]))
        body = " ".join([after.body_text, *after.messages]).lower()
        if (
            status in settings["server_error_status_codes"]
            if status is not None
            else False
        ) or contains_any(body, settings["error_terms"]):
            result.findings.append(
                self.finding(
                    title="Input caused an error state",
                    description=(
                        "Harmless special characters or long input produced a "
                        "server error or crash-like page."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "form_action": form.action,
                        "status_code": status,
                        "messages": visible_messages(after),
                    },
                )
            )
        return result

    def _candidate_forms(self, inventory, settings):
        return [
            form
            for form in inventory.forms
            if not form.has_password
            and not contains_any(form_semantics(form, inventory), settings["skip_terms"])
            and fillable_controls(
                inventory.controls_for_form(form),
                settings["control_types"],
            )
        ][: int(settings["maximum_forms"])]

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

