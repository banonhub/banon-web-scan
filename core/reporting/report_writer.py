import json
from datetime import datetime, timezone
from pathlib import Path

from core.config.settings import ScannerSettings


class ReportWriter:
    """Persist the engine's serializable result without coupling reporting to it."""

    def __init__(self, settings: ScannerSettings):
        self.settings = settings

    def write(self, result: dict, *, timestamp: str | None = None) -> str:
        # Reports are user output, so a relative --output is resolved against
        # the current working directory rather than the install location. This
        # keeps reports out of site-packages when the tool is pip/pipx installed.
        output = Path(self.settings.output).expanduser()
        directory = output if output.is_absolute() else Path.cwd() / output
        directory.mkdir(parents=True, exist_ok=True)
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        template = self.settings.get("evidence", "report_filename")
        path = directory / template.format(timestamp=timestamp)
        with path.open("w", encoding="utf-8") as file:
            json.dump(result, file, indent=2, ensure_ascii=False)
            file.write("\n")
        return str(path)
