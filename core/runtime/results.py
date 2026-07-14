from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.runtime.entities import Barrier


@dataclass(slots=True)
class Finding:
    title: str
    description: str
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)
    plugin: str = "unknown"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def __post_init__(self):
        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {self.severity}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "plugin": self.plugin,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        return f"[{self.severity}] {self.title}"


@dataclass(slots=True)
class PluginResult:
    findings: list[Finding] = field(default_factory=list)
    barriers: list[Barrier] = field(default_factory=list)
    authenticated: bool = False
    authentication_evidence: dict[str, Any] = field(default_factory=dict)
