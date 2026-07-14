"""Generic same-origin discovery and scope enforcement."""

from core.discovery.crawler import DiscoveryEngine
from core.discovery.scope_policy import ScopePolicy

__all__ = ["DiscoveryEngine", "ScopePolicy"]
