"""Heuristic blob inspection — suggestions with CONFIDENCE, never a verdict.

Deliberately does not claim certainty and never auto-decrypts. It proposes a
pipeline the human can accept.
"""
from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass
from typing import List, Tuple

_B64 = re.compile(rb"^[A-Za-z0-9+/=\r\n]+$")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


@dataclass
class Guess:
    name: str
    confidence: int  # 0..100


def analyze(data: bytes) -> Tuple[List[Guess], List[str]]:
    guesses: List[Guess] = []
    pipeline: List[str] = []

    looks_b64 = bool(_B64.match(data.strip())) and len(data.strip()) % 4 == 0
    guesses.append(Guess("base64", 93 if looks_b64 else 10))

    decoded = data
    if looks_b64:
        try:
            decoded = base64.b64decode(data.strip())
            pipeline.append("base64_decode")
        except Exception:  # noqa: BLE001
            looks_b64 = False

    is_gzip = decoded[:2] == b"\x1f\x8b"
    guesses.append(Guess("gzip", 96 if is_gzip else 8))
    if is_gzip:
        pipeline.append("gunzip")
        import gzip
        try:
            decoded = gzip.decompress(decoded)
        except Exception:  # noqa: BLE001
            pass

    stripped = decoded.lstrip()
    is_json = stripped[:1] in (b"{", b"[")
    guesses.append(Guess("json", 99 if is_json else 5))

    ent = _entropy(decoded)
    # high entropy on not-yet-json data suggests an encryption layer
    aes_conf = 61 if (not is_json and ent > 7.3) else (15 if not is_json else 3)
    guesses.append(Guess("aes", aes_conf))
    if aes_conf >= 50:
        pipeline.append("aes_decrypt  # key required")

    if is_json:
        pipeline.append("as_json")

    return guesses, pipeline
