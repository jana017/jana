"""Plugin package. Importing this module registers all built-in plugins."""
from . import decoders  # noqa: F401 - side-effect import: registers plugins
from .base import Plugin, register, get, all_plugins, auto_candidates

__all__ = ["Plugin", "register", "get", "all_plugins", "auto_candidates"]
