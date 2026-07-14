from pathlib import Path

from core.config.settings import ScannerSettings


class ListProvider:
    """Load and validate every configurable scanner list in one place."""

    def __init__(self, settings: ScannerSettings):
        self.settings = settings

    def resolve(self, value: str | Path) -> Path:
        return self.settings.resolve_path(value)

    def load(self, value: str | Path, *, lowercase: bool = False) -> list[str]:
        path = self.resolve(value)
        try:
            with path.open("r", encoding="utf-8") as file:
                entries = [
                    line.strip()
                    for line in file
                    if line.strip() and not line.lstrip().startswith("#")
                ]
        except OSError as exc:
            raise ValueError(f"Could not read list file '{path}': {exc}") from exc

        if lowercase:
            return [entry.lower() for entry in entries]
        return entries
