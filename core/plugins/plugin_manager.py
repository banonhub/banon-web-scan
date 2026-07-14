import importlib
import inspect
from pathlib import Path

from core.config.settings import ScannerSettings
from core.plugins.base_plugin import BasePlugin


class PluginManager:
    """Discover, validate, alias, and select the drop-in plugin library."""

    def __init__(self, settings: ScannerSettings):
        self.settings = settings
        self.library: dict[str, type[BasePlugin]] = {}

    def discover(self) -> dict[str, type[BasePlugin]]:
        config = self.settings.get("plugins")
        directory = self.settings.resolve_path(config["directory"])
        package = config["package"]
        self.library.clear()

        for path in sorted(Path(directory).glob(config["file_pattern"])):
            if path.name.startswith(config["ignored_filename_prefix"]):
                continue
            module_name = f"{package}.{path.stem}"
            module = importlib.import_module(module_name)
            for _, candidate in inspect.getmembers(module, inspect.isclass):
                if candidate is BasePlugin:
                    continue
                if not issubclass(candidate, BasePlugin):
                    continue
                if candidate.__module__ != module.__name__:
                    continue
                if not candidate.NAME or candidate.NAME == BasePlugin.NAME:
                    raise ValueError(
                        f"Plugin class {candidate.__name__} has no unique NAME"
                    )
                if candidate.NAME in self.library:
                    raise ValueError(f"Duplicate plugin name: {candidate.NAME}")
                self.library[candidate.NAME] = candidate
        return dict(self.library)

    def select(self, requested: list[str]) -> list[type[BasePlugin]]:
        if not self.library:
            self.discover()
        config = self.settings.get("plugins")
        all_token = config["all_token"]
        aliases = config["aliases"]
        if all_token in requested:
            return list(self.library.values())

        selected: list[type[BasePlugin]] = []
        unknown: list[str] = []
        for name in requested:
            resolved = aliases.get(name, name)
            plugin = self.library.get(resolved)
            if plugin is None:
                unknown.append(name)
            elif plugin not in selected:
                selected.append(plugin)
        if unknown:
            available = ", ".join(sorted(self.library))
            raise ValueError(
                f"Unknown plugins: {', '.join(unknown)}. Available: {available}"
            )
        return selected
