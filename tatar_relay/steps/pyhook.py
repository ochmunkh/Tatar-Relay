"""User Python hook as a transform step (trusted local only in v0.1)."""
from __future__ import annotations

import os

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..hooks import load_hook
from .base import Step, register


@register("python")
class PythonStep(Step):
    in_type = DataType.ANY
    out_type = DataType.ANY

    def configure(self) -> None:
        self.file = self.params.get("file")
        self.fwd_name = self.params.get("forward")
        self.bwd_name = self.params.get("backward")
        self.base_dir = self.params.get("_base_dir", os.getcwd())
        if not self.file or not self.fwd_name:
            raise DecryptError(category="config_error",
                               message="python step needs 'file' and 'forward'")

    def _call(self, name, data, ctx):
        if not name:
            raise DecryptError(category="config_error",
                               message=f"python step '{self.file}' missing direction handler")
        fn = load_hook(self.file, name, self.base_dir)
        try:
            return fn(data, ctx)
        except DecryptError:
            raise
        except Exception as e:  # noqa: BLE001
            raise DecryptError(category="hook_error",
                               message=f"{self.file}:{name} raised {type(e).__name__}: {e}")

    def forward(self, data, ctx: Context):
        return self._call(self.fwd_name, data, ctx)

    def backward(self, data, ctx: Context):
        return self._call(self.bwd_name, data, ctx)
