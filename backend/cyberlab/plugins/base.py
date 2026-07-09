"""Plugin base class + registry for CyberLab.

Every decoder / transformer / analyzer is a Plugin. Plugins are hot-registered
in a module-level dict. The engine looks them up by `id` when executing a
recipe step.

Design decisions
----------------
* Plugins operate on bytes-in / bytes-out where possible. This lets us chain
  binary operations (gzip → xor → base64) without lossy re-encoding.
* Text plugins receive `.decode('utf-8', 'replace')` and return str. The
  engine handles the conversion.
* `detect(payload: bytes) -> float` returns a heuristic confidence [0.0, 1.0]
  used by the auto-decode engine to pick the best next step.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Dict, Any, List, Optional


@dataclass
class Plugin:
    id: str
    name: str
    category: str
    description: str
    run: Callable[[bytes, Dict[str, Any]], bytes]
    detect: Optional[Callable[[bytes], float]] = None
    params: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    # If True, the auto-decoder will consider this plugin.
    auto: bool = True


_REGISTRY: Dict[str, Plugin] = {}


def register(plugin: Plugin) -> None:
    _REGISTRY[plugin.id] = plugin


def get(plugin_id: str) -> Plugin:
    if plugin_id not in _REGISTRY:
        raise KeyError(f"Unknown plugin: {plugin_id}")
    return _REGISTRY[plugin_id]


def all_plugins() -> List[Plugin]:
    return sorted(_REGISTRY.values(), key=lambda p: (p.category, p.name))


def auto_candidates() -> List[Plugin]:
    return [p for p in _REGISTRY.values() if p.auto and p.detect is not None]
