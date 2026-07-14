from __future__ import annotations

from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import mask_identity, redact_identity


class LoginErrorsPlugin(BasePlugin):
    """Check failed-login responses for username-enumeration differences."""

    NAME = "login_errors"
    DESCRIPTION = "Checks failed-login messages for username enumeration"

    def supports(self, inventory) -> bool:
        if self.context.inputs.get(f"{self.NAME}_done"):
            return False
        return any(
            self.detector.is_login_form(form, inventory)
            for form in inventory.forms
        )

    def scan(self, page, inventory) -> PluginResult:
        result = PluginResult()
        self.context.inputs[f"{self.NAME}_done"] = True
        settings = self.context.settings.get("plugins", "settings", self.NAME)

        candidates = list(settings["candidate_usernames"])
        if self.context.settings.username:
            candidates.insert(0, self.context.settings.username)

        baseline = self._attempt(
            page.url,
            settings["nonexistent_username"],
            settings["wrong_password"],
        )
        if baseline is None:
            return result

        for username in candidates:
            attempt = self._attempt(
                page.url, username, settings["wrong_password"]
            )
            if attempt is None:
                continue
            signals = self._differences(
                baseline, attempt, settings["enumeration_signals"]
            )
            if signals:
                result.findings.append(
                    self.finding(
                        title="Login errors may allow username enumeration",
                        description=(
                            "A failed login for a candidate username produced a "
                            "different response than a clearly nonexistent one."
                        ),
                        severity=settings["severity"],
                        evidence={
                            "url": page.url,
                            "candidate_username": mask_identity(username),
                            "difference_signals": signals,
                            "candidate_messages": [
                                redact_identity(message, self.context.settings.username)
                                for message in attempt["messages"]
                            ],
                            "nonexistent_messages": [
                                redact_identity(message, self.context.settings.username)
                                for message in baseline["messages"]
                            ],
                        },
                    )
                )
                break
        return result

    def _attempt(self, url: str, username: str, password: str):
        try:
            inventory = self.browser.open(url)
        except Exception:
            return None
        form = next(
            (
                form
                for form in inventory.forms
                if self.detector.is_login_form(form, inventory)
            ),
            None,
        )
        if form is None:
            return None
        controls = inventory.controls_for_form(form)
        identity = self._identity(controls)
        secret = self._secret(controls)
        if identity is None or secret is None:
            return None
        try:
            self.browser.fill(identity, username)
            self.browser.fill(secret, password)
            self.browser.submit(form)
            after = self.browser.inspect()
        except Exception:
            return None
        return {
            "messages": [
                message.strip().lower()
                for message in after.messages
                if message
            ],
            "body_length": len(after.body_text.strip()),
        }

    def _identity(self, controls):
        types = self.context.settings.get(
            "authentication", "identity_control_types"
        )
        terms = self.context.settings.get(
            "authentication", "identity_semantic_terms"
        )
        match = next(
            (
                control
                for control in controls
                if control.control_type in types
                and any(term.lower() in control.semantic_text for term in terms)
            ),
            None,
        )
        return match or next(
            (control for control in controls if control.control_type in types),
            None,
        )

    def _secret(self, controls):
        types = self.context.settings.get(
            "inspection", "secret_control_types"
        )
        return next(
            (
                control
                for control in controls
                if control.control_type in types and control.enabled
            ),
            None,
        )

    @staticmethod
    def _differences(baseline, other, config) -> list[str]:
        signals: list[str] = []
        if (
            config.get("messages")
            and (baseline["messages"] or other["messages"])
            and set(baseline["messages"]) != set(other["messages"])
        ):
            signals.append("visible_messages")
        if config.get("body_length"):
            base_length = max(baseline["body_length"], 1)
            delta = abs(other["body_length"] - base_length) / base_length
            if delta >= float(config["minimum_body_length_ratio"]):
                signals.append("body_length")
        return signals
