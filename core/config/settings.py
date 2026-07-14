from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ScannerSettings:
    """Validated command-line settings plus the complete defaults document."""

    target: str | None
    scan: list[str]
    headless: bool
    watch: bool
    timeout: int
    output: str
    defaults: dict[str, Any] = field(repr=False)
    project_root: Path = field(repr=False)
    allow_destructive: bool = False
    allow_destructive_terms: list[str] = field(default_factory=list)
    extra_selectors: list[str] = field(default_factory=list)
    captcha_pause: bool = False
    verbose: bool = False
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    login_url: str | None = None
    secondary_username: str | None = None
    secondary_password: str | None = field(default=None, repr=False)

    def get(self, *keys: str) -> Any:
        """Read a required nested default without silently inventing a fallback."""
        value: Any = self.defaults
        for key in keys:
            if not isinstance(value, dict) or key not in value:
                dotted = ".".join(keys)
                raise KeyError(f"Missing required setting: {dotted}")
            value = value[key]
        return value

    def resolve_path(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = self.project_root / path
        return path.resolve()
