"""Python hook loading — v0.1: TRUSTED LOCAL ONLY.

A hook is user Python: `def fn(data, ctx)` for transform hooks, or `def fn(ctx)`
for lifecycle/variable hooks. v0.1 runs local/private hooks with the user's own
trust. A real sandbox (restricted imports, no net/fs, timeout) is a later
roadmap item — building one badly is worse than not having it, so we don't fake
it. Community/untrusted profiles must be declarative-only (enforced by the
loader when ``allow_python_hooks`` is false).
"""
from __future__ import annotations

import importlib.util
import os
from typing import Callable

from .errors import ProfileError

_cache: dict = {}


def load_hook(path: str, func_name: str, base_dir: str = ".") -> Callable:
    full = os.path.join(base_dir, path)
    key = (os.path.abspath(full), func_name)
    if key in _cache:
        return _cache[key]
    if not os.path.exists(full):
        raise ProfileError(f"hook file not found: {full}")
    spec = importlib.util.spec_from_file_location(f"tatar_hook_{abs(hash(key))}", full)
    if spec is None or spec.loader is None:
        raise ProfileError(f"cannot load hook module: {full}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # trusted local execution
    fn = getattr(module, func_name, None)
    if not callable(fn):
        raise ProfileError(f"hook '{func_name}' not found in {full}")
    _cache[key] = fn
    return fn
