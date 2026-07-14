from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class ControlTarget:
    element_id: str
    frame_path: tuple[int, ...]
    tag: str
    control_type: str
    name: str = ""
    html_id: str = ""
    role: str = ""
    label: str = ""
    placeholder: str = ""
    autocomplete: str = ""
    text: str = ""
    required: bool = False
    visible: bool = True
    enabled: bool = True
    form_id: str | None = None
    shadow_depth: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def semantic_text(self) -> str:
        return " ".join(
            value
            for value in (
                self.label,
                self.role,
                self.placeholder,
                self.name,
                self.html_id,
                self.text,
                self.autocomplete,
            )
            if value
        ).lower()


@dataclass(slots=True, frozen=True)
class FormTarget:
    element_id: str
    frame_path: tuple[int, ...]
    action: str
    method: str
    text: str
    control_ids: tuple[str, ...]
    has_password: bool
    shadow_depth: int = 0
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PageInventory:
    url: str
    title: str
    body_text: str
    controls: list[ControlTarget] = field(default_factory=list)
    forms: list[FormTarget] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    captcha_detected: bool = False
    frame_count: int = 0
    shadow_root_count: int = 0

    def controls_for_form(self, form: FormTarget) -> list[ControlTarget]:
        identifiers = set(form.control_ids)
        return [
            control for control in self.controls if control.element_id in identifiers
        ]


@dataclass(slots=True)
class PageRecord:
    url: str
    path: str
    source: str
    authenticated: bool = False
    depth: int = 0
    title: str = ""
    status: str = "pending"
    status_code: int | None = None
    final_url: str | None = None
    page_type: str = "page"
    scan_count: int = 0


@dataclass(slots=True, frozen=True)
class PluginSuggestion:
    name: str
    description: str


@dataclass(slots=True)
class PageAnalysis:
    page: PageRecord
    inventory: PageInventory
    suggestions: list[PluginSuggestion] = field(default_factory=list)
    barriers: list["Barrier"] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class Barrier:
    kind: str
    url: str
    detail: str
