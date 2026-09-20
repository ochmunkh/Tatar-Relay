"""Heuristic blob inspection — suggestions with CONFIDENCE, never a verdict.

Given a captured encrypted blob (and, optionally, crypto observations from the
JS observer hook), this proposes:

  * where the payload lives + how it is wrapped (base64 / hex / gzip),
  * the likely cipher family (from structure, or exactly from observations),
  * a *draft profile YAML* the human reviews and saves.

It never claims certainty and never auto-decrypts. Observations (ground truth
from the app's own crypto calls) override the structural heuristics when present.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_B64_STD = re.compile(rb"^[A-Za-z0-9+/=\r\n]+$")
_B64_URL = re.compile(rb"^[A-Za-z0-9_\-=\r\n]+$")
_HEX_RE = re.compile(rb"^[0-9a-fA-F\r\n]+$")

# JSON field-name hints -> role
_FIELD_HINTS = {
    "payload": "cipher", "data": "cipher", "body": "cipher", "enc": "cipher",
    "encrypted": "cipher", "ciphertext": "cipher", "ct": "cipher", "cipher": "cipher",
    "iv": "iv", "nonce": "iv",
    "tag": "tag", "mac": "sig", "sig": "sig", "signature": "sig", "hmac": "sig",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _looks_random(data: bytes) -> bool:
    """Robust 'looks encrypted' check that also works for short blobs.

    Absolute Shannon entropy can't reach 8 bits on a short sample (max is
    log2(len)), so we normalise by that ceiling and additionally require a
    healthy fraction of non-printable bytes — text with many distinct chars
    would otherwise look 'random'.
    """
    n = len(data)
    if n < 8:
        return False
    ent = _entropy(data)
    if ent > 7.2:
        return True
    ceil = math.log2(n)
    norm = ent / ceil if ceil else 0.0
    nonprint = sum(1 for b in data if b < 9 or b > 126) / n
    return norm >= 0.9 and nonprint > 0.2


def _ecb_repeats(data: bytes, block: int = 16) -> bool:
    """A repeated 16-byte block strongly suggests AES-ECB (or CBC w/ repeats)."""
    if len(data) < block * 2:
        return False
    seen, blocks = set(), 0
    for i in range(0, len(data) - block + 1, block):
        b = data[i:i + block]
        if b in seen:
            return True
        seen.add(b); blocks += 1
    return False


@dataclass
class Guess:
    name: str
    confidence: int  # 0..100


@dataclass
class Fingerprint:
    outer_encoding: str = "raw"          # base64 | hex | raw
    b64_variant: Optional[str] = None    # standard | urlsafe
    gzip: bool = False
    is_json: bool = False
    json_fields: Dict[str, str] = field(default_factory=dict)  # name -> role
    cipher_field: Optional[str] = None
    entropy: float = 0.0
    decoded_len: int = 0
    len_mod16: int = 0
    ecb: bool = False
    cipher_guess: str = "unknown"        # aes-ecb | aes-cbc | aead | unknown
    notes: List[str] = field(default_factory=list)


def _looks_b64(s: bytes) -> Optional[str]:
    t = s.strip()
    if len(t) < 8 or len(t) % 4 != 0:
        return None
    if _B64_STD.match(t):
        return "standard"
    if _B64_URL.match(t):
        return "urlsafe"
    return None


def _decode_outer(data: bytes, fp: Fingerprint) -> bytes:
    variant = _looks_b64(data)
    if variant:
        try:
            raw = data.strip()
            if variant == "urlsafe":
                out = base64.urlsafe_b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4))
            else:
                out = base64.b64decode(raw)
            fp.outer_encoding = "base64"; fp.b64_variant = variant
            return out
        except (binascii.Error, ValueError):
            pass
    t = data.strip()
    if _HEX_RE.match(t) and len(t) % 2 == 0:
        try:
            out = bytes.fromhex(t.decode("ascii"))
            fp.outer_encoding = "hex"
            return out
        except ValueError:
            pass
    return data


def fingerprint(data: bytes) -> Fingerprint:
    fp = Fingerprint()

    # JSON envelope? (before treating the whole thing as one blob)
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        try:
            obj = json.loads(data.decode("utf-8"))
            fp.is_json = True
            if isinstance(obj, dict):
                best_len = -1
                for k, v in obj.items():
                    role = _FIELD_HINTS.get(k.lower())
                    if role:
                        fp.json_fields[k] = role
                    if isinstance(v, str) and len(v) > best_len and len(v) >= 16:
                        # the longest opaque-looking string is the likely ciphertext
                        if _looks_b64(v.encode()) or _HEX_RE.match(v.encode()):
                            best_len = len(v); fp.cipher_field = k
                if fp.cipher_field and fp.cipher_field not in fp.json_fields:
                    fp.json_fields[fp.cipher_field] = "cipher"
            fp.notes.append("JSON envelope — locate the ciphertext field, not the whole body")
            return fp
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # Binary / opaque blob path
    decoded = _decode_outer(data, fp)
    if decoded[:2] == b"\x1f\x8b":
        fp.gzip = True
        try:
            decoded = gzip.decompress(decoded)
        except OSError:
            pass

    fp.decoded_len = len(decoded)
    fp.len_mod16 = len(decoded) % 16
    fp.entropy = round(_entropy(decoded), 2)
    fp.ecb = _ecb_repeats(decoded)

    # After a valid JSON decode we would have returned; here it is opaque bytes.
    high = _looks_random(decoded)
    if fp.ecb:
        fp.cipher_guess = "aes-ecb"
        fp.notes.append("repeated 16-byte block → ECB mode (or CBC with repeats)")
    elif high and fp.len_mod16 == 0:
        fp.cipher_guess = "aes-cbc"
        fp.notes.append("high entropy + length multiple of 16 → block cipher (CBC likely)")
    elif high and fp.len_mod16 != 0:
        fp.cipher_guess = "aead"
        fp.notes.append("high entropy + non-block length → AEAD (AES-GCM / ChaCha20): "
                        "nonce prefix + ciphertext + 16-byte tag")
    else:
        fp.notes.append("entropy not conclusive — may be plaintext, or another encoding first")
    return fp


def analyze(data: bytes) -> Tuple[List[Guess], List[str]]:
    """Back-compatible summary: ranked guesses + a suggested step list."""
    fp = fingerprint(data)
    guesses: List[Guess] = []
    pipeline: List[str] = []

    if fp.is_json:
        guesses.append(Guess("json envelope", 96))
        if fp.cipher_field:
            pipeline.append(f"envelope.json_field: {fp.cipher_field}")
        pipeline.append("base64_decode / hex_decode  # depends on field encoding")
        pipeline.append("aes_decrypt / chacha20_decrypt  # key required")
        pipeline.append("as_json")
        return guesses, pipeline

    guesses.append(Guess("base64", 92 if fp.outer_encoding == "base64" else 8))
    if fp.outer_encoding == "base64":
        pipeline.append("base64_decode")
    elif fp.outer_encoding == "hex":
        guesses.append(Guess("hex", 90)); pipeline.append("hex_decode")
    guesses.append(Guess("gzip", 96 if fp.gzip else 6))
    if fp.gzip:
        pipeline.append("gunzip")

    conf = {"aes-ecb": 70, "aes-cbc": 62, "aead": 60, "unknown": 15}[fp.cipher_guess]
    guesses.append(Guess(fp.cipher_guess, conf))
    if fp.cipher_guess == "aead":
        pipeline.append("aes_decrypt {mode: gcm} / chacha20_decrypt  # key required")
    elif fp.cipher_guess in ("aes-cbc", "aes-ecb"):
        pipeline.append(f"aes_decrypt {{mode: {fp.cipher_guess.split('-')[1]}}}  # key required")
    pipeline.append("as_json")
    return guesses, pipeline


# ---------------------------------------------------------------------------
# Observations (ground truth from the JS observer hook)
# ---------------------------------------------------------------------------

def load_observations(path: str) -> List[dict]:
    out: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return out


def _pick_observation(obs: List[dict]) -> Optional[dict]:
    """Prefer a symmetric cipher observation (AES/ChaCha) over key-exchange."""
    ciphers = [o for o in obs if str(o.get("algorithm", "")).upper().startswith(("AES", "CHACHA"))]
    return (ciphers or obs)[-1] if (ciphers or obs) else None


def _cipher_step_from_obs(o: dict) -> Optional[str]:
    algo = str(o.get("algorithm", "")).upper()
    iv = int(o.get("ivLen") or 0)
    if "GCM" in algo or o.get("mode") == "GCM":
        return f"    - aes_decrypt: {{ mode: gcm, key: \"${{session_key}}\", iv: {{ source: prefix, length: {iv or 12} }} }}"
    if "CBC" in algo or o.get("mode") == "CBC":
        return f"    - aes_decrypt: {{ mode: cbc, key: \"${{session_key}}\", iv: {{ source: prefix, length: {iv or 16} }} }}"
    if "CHACHA" in algo:
        return f"    - chacha20_decrypt: {{ key: \"${{session_key}}\", nonce_length: {iv or 12} }}"
    return None


def draft_profile(data: bytes, name: str = "target",
                  observations: Optional[List[dict]] = None) -> str:
    """Emit a draft profile YAML for review. Merges observations when given."""
    fp = fingerprint(data)
    lines: List[str] = []
    lines.append(f"# {name}.yaml — DRAFT from `relay inspect` — REVIEW before use")
    lines.append("# Confidence is heuristic; verify with `relay validate --sample`.")
    lines.append(f'name: "{name}"')
    lines.append("scope:")
    lines.append('  hosts: [ "REPLACE\\\\.example\\\\.com" ]   # REQUIRED (fail-closed)')
    lines.append("")
    lines.append("request:")

    # envelope
    if fp.is_json and fp.cipher_field:
        lines.append("  envelope:")
        lines.append(f'    locate: [ {{ in: json_field, field: "{fp.cipher_field}" }} ]')
    else:
        lines.append("  envelope: { locate: [ { in: raw } ] }   # REVIEW: where is the payload?")

    # transforms
    lines.append("  transform:")
    if fp.outer_encoding == "base64":
        lines.append("    - base64_decode")
    elif fp.outer_encoding == "hex":
        lines.append("    - hex_decode")
    if fp.gzip:
        lines.append("    - gunzip")

    obs = observations or []
    picked = _pick_observation(obs)
    cipher_line = _cipher_step_from_obs(picked) if picked else None
    if cipher_line:
        summary = f"{picked.get('algorithm')} {picked.get('ivLen')}B nonce (from observation)"
        lines.append(f"    # cipher from JS observation: {summary}")
        lines.append(cipher_line)
    else:
        if fp.cipher_guess == "aead":
            lines.append('    # REVIEW: AES-GCM or ChaCha20? (observation would confirm)')
            lines.append('    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }')
        elif fp.cipher_guess in ("aes-cbc", "aes-ecb"):
            mode = fp.cipher_guess.split("-")[1]
            lines.append(f'    - aes_decrypt: {{ mode: {mode}, key: "${{session_key}}", iv: {{ source: prefix, length: 16 }} }}')
        else:
            lines.append('    # REVIEW: cipher not determined — capture a JS observation or set manually')
            lines.append('    - aes_decrypt: { mode: gcm, key: "${session_key}", iv: { source: prefix, length: 12 } }')
    lines.append("    - as_json")

    # reseal
    lines.append("  reseal:")
    sig_field = next((k for k, r in fp.json_fields.items() if r == "sig"), None)
    if sig_field:
        lines.append(f'    # a "{sig_field}" field looks like a signature — re-sign after edit (set key/input):')
        lines.append(f'    - sign: {{ algo: hmac_sha256, key: "${{session_key}}", input: "${{payload_b64}}", into: {sig_field} }}')
    lines.append("    - serialize: { mode: compact }   # REVIEW: preserve / canonical / compact")
    lines.append("")
    lines.append("# NOTES:")
    for n in fp.notes:
        lines.append(f"#  - {n}")
    if picked:
        lines.append(f"#  - observation used: {json.dumps(picked, ensure_ascii=False)}")
    lines.append("security: { allow_python_hooks: false }")
    return "\n".join(lines) + "\n"
