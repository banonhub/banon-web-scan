from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from core.runtime.entities import ControlTarget, FormTarget, PageInventory


def compact_text(*values: object) -> str:
    return " ".join(str(value or "").strip() for value in values).lower()


def form_semantics(form: FormTarget, inventory: PageInventory) -> str:
    controls = inventory.controls_for_form(form)
    return compact_text(
        inventory.url,
        form.action,
        form.method,
        form.text,
        *(control.semantic_text for control in controls),
    )


def contains_any(value: str, terms: Iterable[str]) -> bool:
    lowered = value.lower()
    return any(term.lower() in lowered for term in terms)


def mask_identity(value: object) -> str:
    """Mask a username/email for report evidence.

    Keeps the first character (and, for emails, the domain) so a finding stays
    readable without recording the full account: ``test@test.com`` becomes
    ``t***@test.com`` and ``admin`` becomes ``a***``. Empty input returns "".
    """
    text = str(value or "")
    if not text:
        return ""
    if "@" in text:
        local, _, domain = text.partition("@")
        masked = f"{local[0]}***" if local else "***"
        return f"{masked}@{domain}"
    return f"{text[0]}***"


def redact_identity(value: object, identity: str | None) -> str:
    """Replace any occurrence of ``identity`` in ``value`` with its masked form.

    Used to scrub a real test account out of captured page messages before they
    are stored as evidence, in case the target reflects the submitted identity
    back in its response. Case-insensitive; a falsy ``identity`` is a no-op.
    """
    text = str(value or "")
    if not identity:
        return text
    return re.sub(re.escape(identity), mask_identity(identity), text, flags=re.IGNORECASE)


def visible_messages(inventory: PageInventory) -> list[str]:
    return [
        message.strip()
        for message in inventory.messages
        if message and message.strip()
    ]


def identity_control(
    controls: list[ControlTarget],
    identity_types: Iterable[str],
    identity_terms: Iterable[str],
) -> ControlTarget | None:
    types = set(identity_types)
    terms = [term.lower() for term in identity_terms]
    match = next(
        (
            control
            for control in controls
            if control.control_type in types
            and any(term in control.semantic_text for term in terms)
        ),
        None,
    )
    if match is not None:
        return match
    return next(
        (
            control
            for control in controls
            if control.control_type in types
            and control.visible
            and control.enabled
        ),
        None,
    )


def password_controls(controls: list[ControlTarget]) -> list[ControlTarget]:
    return [
        control
        for control in controls
        if control.control_type == "password"
        and control.visible
        and control.enabled
    ]


def fillable_controls(
    controls: list[ControlTarget],
    types: Iterable[str],
) -> list[ControlTarget]:
    allowed = set(types)
    return [
        control
        for control in controls
        if control.control_type in allowed
        and control.visible
        and control.enabled
        and not control.attributes.get("readonly")
    ]


def csrf_like_controls(
    controls: list[ControlTarget],
    token_terms: Iterable[str],
) -> list[ControlTarget]:
    terms = [term.lower() for term in token_terms]
    return [
        control
        for control in controls
        if control.control_type == "hidden"
        and any(term in control.semantic_text for term in terms)
        and (control.text or control.name or control.html_id)
    ]


def state_changing_forms(
    inventory: PageInventory,
    *,
    skip_terms: Iterable[str] = (),
) -> list[FormTarget]:
    skipped = [term.lower() for term in skip_terms]
    forms = []
    for form in inventory.forms:
        if form.method == "get":
            continue
        semantics = form_semantics(form, inventory)
        if any(term in semantics for term in skipped):
            continue
        forms.append(form)
    return forms


def generic_value(control: ControlTarget, settings: dict) -> str:
    values = settings.get("safe_values", {})
    return str(values.get(control.control_type, values.get("default", "banon")))


def resource_like_url(url: str, patterns: Iterable[str]) -> bool:
    parts = urlsplit(url)
    target = f"{parts.path}?{parts.query}".rstrip("?")
    return any(re.search(pattern, target, re.IGNORECASE) for pattern in patterns)


def hidden_token_values(html: str, token_terms: Iterable[str]) -> dict[str, str]:
    terms = [re.escape(term) for term in token_terms]
    term_pattern = "|".join(terms)
    values: dict[str, str] = {}
    input_pattern = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
    attr_pattern = re.compile(
        r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(['\"])(.*?)\2",
        re.DOTALL,
    )
    for tag_match in input_pattern.finditer(html or ""):
        tag = tag_match.group(0)
        attrs = {
            key.lower(): value
            for key, _quote, value in attr_pattern.findall(tag)
        }
        if attrs.get("type", "").lower() != "hidden":
            continue
        name = compact_text(attrs.get("name"), attrs.get("id"))
        if not re.search(term_pattern, name, re.IGNORECASE):
            continue
        value = attrs.get("value", "")
        if value:
            values[name or f"token_{len(values) + 1}"] = value
    return values
