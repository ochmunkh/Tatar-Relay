"""Authentication / integrity steps.

``hmac_verify`` — forward: computes HMAC and compares with the expected value,
raising ``signature_mismatch`` on failure.  backward: pass-through (re-signing
is the job of the reseal ``sign`` step).

YAML spec
---------
.. code-block:: yaml

    transform:
      - hmac_verify:
          algo: sha256              # sha256 (default) | sha512 | sha1
          key: "${session_key}"     # hex-encoded key or raw bytes var
          input: "${payload}"       # what to MAC over (template)
          field: "signature"        # read expected MAC from this JSON field
          # OR
          expected: "${mac_header}" # read expected MAC from a header / var
          encoding: hex             # hex (default) | base64
          # Optional: remove the signature field from payload before MACing.
          # Useful when the MAC covers the body *without* its own field.
          strip_field: false

Either ``field`` or ``expected`` must be present (not both).

The step passes the payload through unchanged so subsequent steps see the
same bytes/dict that arrived.  Any field removal is internal and the payload
is NOT modified — use a dedicated ``set`` reseal step if you need to strip it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from ..context import Context
from ..datatypes import DataType
from ..errors import DecryptError
from ..variables import Renderer
from .base import Step, register

_ALGOS = {
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha1":   hashlib.sha1,
}


def _to_bytes(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        try:
            return bytes.fromhex(v)
        except ValueError:
            return v.encode("utf-8")
    raise DecryptError(category="config_error",
                       message=f"hmac_verify: cannot convert {type(v).__name__} to bytes")


def _decode_mac(value: str, encoding: str) -> bytes:
    """Decode a MAC value from its on-wire encoding."""
    try:
        if encoding == "base64":
            pad = (4 - len(value) % 4) % 4
            return base64.b64decode(value + "=" * pad)
        # default: hex
        return bytes.fromhex(value.strip())
    except Exception as exc:
        raise DecryptError(
            category="config_error",
            message=f"hmac_verify: cannot decode MAC ({encoding}): {exc}",
        ) from exc


@register("hmac_verify")
class HmacVerify(Step):
    """Forward: verify HMAC.  Backward: pass-through."""

    in_type  = DataType.ANY
    out_type = DataType.ANY

    def configure(self) -> None:
        algo_name = self.params.get("algo", "sha256").lower().replace("-", "")
        if algo_name not in _ALGOS:
            raise DecryptError(
                category="config_error",
                message=f"hmac_verify: unsupported algo '{algo_name}'. "
                        f"Supported: {sorted(_ALGOS)}",
            )
        self.algo      = _ALGOS[algo_name]
        self.algo_name = algo_name
        self.encoding  = self.params.get("encoding", "hex")
        self.strip     = bool(self.params.get("strip_field", False))

        has_field    = "field"    in self.params
        has_expected = "expected" in self.params
        if has_field == has_expected:   # both or neither
            raise DecryptError(
                category="config_error",
                message="hmac_verify: exactly one of 'field' or 'expected' must be set",
            )

    # ── forward: verify ───────────────────────────────────────────────────

    def forward(self, data: Any, ctx: Context) -> Any:
        # Build extras so ${payload} and ${payload_b64} resolve to the current step's data,
        # mirroring the convention used by the reseal phase.
        data_bytes = data if isinstance(data, (bytes, bytearray)) else (
            json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if isinstance(data, (dict, list)) else str(data).encode("utf-8")
        )
        extras = {
            "payload":     data_bytes.decode("latin-1"),
            "payload_b64": base64.b64encode(data_bytes).decode("ascii"),
        }
        rnd = Renderer(ctx.vars, extras)

        # -- resolve key
        raw_key = rnd.render(self.params["key"])
        key = _to_bytes(raw_key)

        # -- resolve what to MAC
        input_tmpl = self.params.get("input", "${payload}")
        mac_input  = rnd.render_bytes(input_tmpl)

        # -- if strip_field: remove the sig field from JSON before MACing
        if self.strip and "field" in self.params:
            mac_input = self._strip_field(mac_input, self.params["field"])

        # -- resolve expected MAC
        if "field" in self.params:
            expected_raw = self._read_field(data, self.params["field"])
        else:
            expected_raw = str(rnd.render(self.params["expected"]))
        expected = _decode_mac(expected_raw, self.encoding)

        # -- compute & compare (constant time)
        computed = hmac.new(key, mac_input, self.algo).digest()
        if not hmac.compare_digest(computed, expected):
            raise DecryptError(
                category="signature_invalid",
                message=(
                    f"hmac_verify ({self.algo_name}): signature does not match. "
                    f"Expected {expected.hex()[:16]}… — "
                    f"the key, encoding, or input template may be wrong."
                ),
                step=self.name,
                direction="forward",
            )

        # pass payload through unchanged
        return data

    # ── backward: pass-through ────────────────────────────────────────────

    def backward(self, data: Any, ctx: Context) -> Any:
        # Re-signing is done by the reseal ``sign`` step.
        return data

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _read_field(data: Any, field: str) -> str:
        """Extract a field value from JSON bytes or a dict."""
        if isinstance(data, (bytes, bytearray)):
            try:
                data = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise DecryptError(
                    category="config_error",
                    message=f"hmac_verify: payload is not JSON; cannot read field '{field}'",
                ) from exc
        if not isinstance(data, dict):
            raise DecryptError(
                category="config_error",
                message=f"hmac_verify: payload is not a JSON object; cannot read field '{field}'",
            )
        if field not in data:
            raise DecryptError(
                category="config_error",
                message=f"hmac_verify: field '{field}' not found in payload "
                        f"(available: {sorted(data.keys())})",
            )
        return str(data[field])

    @staticmethod
    def _strip_field(raw: bytes, field: str) -> bytes:
        """Return JSON bytes with *field* removed (for MACs over field-less body)."""
        try:
            obj = json.loads(raw.decode("utf-8"))
            obj.pop(field, None)
            return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        except Exception:
            return raw   # silently fall back; the verify will likely fail anyway
