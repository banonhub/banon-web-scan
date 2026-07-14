import hashlib
import re
from dataclasses import dataclass

from core.config.settings import ScannerSettings
from core.runtime.entities import FormTarget, PageInventory


@dataclass(slots=True, frozen=True)
class BrowserState:
    url: str
    fingerprint: str
    cookie_names: frozenset[str]
    login_form_present: bool
    authenticated_control_present: bool


class StateDetector:
    """Infer navigation and authentication without assuming route names."""

    def __init__(self, driver, settings: ScannerSettings):
        self.driver = driver
        self.settings = settings

    def capture(self, inventory: PageInventory) -> BrowserState:
        cookie_names = frozenset(
            cookie.get("name", "") for cookie in self.driver.get_cookies()
        )
        terms = self.settings.get("authentication", "logout_semantic_terms")
        authenticated_control = any(
            any(term.lower() in control.semantic_text for term in terms)
            for control in inventory.controls
        )
        return BrowserState(
            url=inventory.url,
            fingerprint=self.fingerprint(inventory),
            cookie_names=cookie_names,
            login_form_present=any(
                self.is_login_form(form, inventory)
                for form in inventory.forms
            ),
            authenticated_control_present=authenticated_control,
        )

    def is_login_form(
        self,
        form: FormTarget,
        inventory: PageInventory,
    ) -> bool:
        if not form.has_password:
            return False
        if self.is_registration_form(form, inventory):
            return False
        terms = self.settings.get("authentication", "identity_semantic_terms")
        identity_types = self.settings.get(
            "authentication", "identity_control_types"
        )
        controls = inventory.controls_for_form(form)
        return any(
            control.control_type in identity_types
            and any(term.lower() in control.semantic_text for term in terms)
            for control in controls
        )

    def is_registration_form(
        self,
        form: FormTarget,
        inventory: PageInventory,
    ) -> bool:
        terms = self.settings.get(
            "authentication", "registration_semantic_terms"
        )
        controls = inventory.controls_for_form(form)
        location = f"{inventory.url} {form.action}".lower()
        if any(term.lower() in location for term in terms):
            return True

        action_types = self.settings.get(
            "authentication", "form_action_control_types"
        )
        action_text = " ".join(
            control.semantic_text
            for control in controls
            if control.control_type in action_types
            or control.tag in action_types
        )
        if any(term.lower() in action_text for term in terms):
            return True

        secret_types = self.settings.get(
            "inspection", "secret_control_types"
        )
        secret_count = sum(
            control.control_type in secret_types for control in controls
        )
        return secret_count > 1 and any(
            term.lower() in form.text.lower() for term in terms
        )

    def authentication_changed(
        self,
        before: BrowserState,
        after: BrowserState,
    ) -> bool:
        config = self.settings.get("authentication", "transition_signals")
        login_cleared = (
            before.login_form_present and not after.login_form_present
        )
        # A redirect plus a fresh cookie is common on a *failed* login (error
        # page + flash/CSRF cookie). Require a strong signal — the login form
        # disappeared, or an authenticated control (logout) is now present —
        # before treating a transition as a real authentication.
        strong = login_cleared or after.authenticated_control_present
        if after.login_form_present and not after.authenticated_control_present:
            return False
        signals = 0
        if login_cleared:
            signals += 1
        if before.url != after.url:
            signals += 1
        if after.authenticated_control_present:
            signals += 1
        if after.cookie_names.difference(before.cookie_names):
            signals += 1
        return strong and signals >= int(config["minimum_signal_count"])

    @staticmethod
    def fingerprint(inventory: PageInventory) -> str:
        normalized = re.sub(r"\s+", " ", inventory.body_text).strip().lower()
        structure = "|".join(
            f"{control.tag}:{control.control_type}:{control.semantic_text}"
            for control in inventory.controls
        )
        return hashlib.sha256(
            f"{inventory.url}|{normalized}|{structure}".encode("utf-8")
        ).hexdigest()
