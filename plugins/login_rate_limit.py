from __future__ import annotations

import time

from core.plugins import BasePlugin
from core.runtime import PluginResult

from plugins._helpers import contains_any, identity_control, password_controls, redact_identity, visible_messages


class LoginRateLimitPlugin(BasePlugin):
    """Check whether repeated failed logins trigger a throttle signal."""

    NAME = "login_rate_limit"
    DESCRIPTION = "Checks failed logins for delay, warning, CAPTCHA, or lockout"

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
        username = (
            self.context.settings.username
            or settings["username"]
            or self.context.settings.get("authentication", "default_username")
        )
        protected_signals: list[str] = []
        durations: list[float] = []
        messages: list[str] = []

        for attempt in range(int(settings["attempts"])):
            started = time.monotonic()
            after = self._attempt(
                page.url,
                username,
                f"{settings['wrong_password']}_{attempt}",
            )
            durations.append(round(time.monotonic() - started, 3))
            if after is None:
                break
            messages.extend(visible_messages(after))
            body = " ".join([after.body_text, *after.messages]).lower()
            if after.captcha_detected:
                protected_signals.append("captcha")
            if contains_any(body, settings["lockout_terms"]):
                protected_signals.append("lockout_or_warning")
            if durations[-1] >= float(settings["minimum_delay_seconds"]):
                protected_signals.append("response_delay")

        if not protected_signals and len(durations) >= int(settings["attempts"]):
            result.findings.append(
                self.finding(
                    title="Login may lack rate limiting",
                    description=(
                        "Several failed login attempts did not produce a clear "
                        "delay, warning, CAPTCHA, or lockout signal."
                    ),
                    severity=settings["severity"],
                    evidence={
                        "url": page.url,
                        "attempts": len(durations),
                        "durations": durations,
                        "messages": [
                            redact_identity(message, self.context.settings.username)
                            for message in messages[: int(settings["maximum_messages"])]
                        ],
                    },
                )
            )
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
        identity = identity_control(
            controls,
            self.context.settings.get("authentication", "identity_control_types"),
            self.context.settings.get("authentication", "identity_semantic_terms"),
        )
        secrets = password_controls(controls)
        if identity is None or not secrets:
            return None
        try:
            self.browser.fill(identity, username)
            self.browser.fill(secrets[0], password)
            self.browser.submit(form)
            return self.browser.inspect()
        except Exception:
            return None
