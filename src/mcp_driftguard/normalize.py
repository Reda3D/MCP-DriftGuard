"""Canonicalisation helpers.

Everything here exists to make output byte-identical across runs, platforms and
Python versions. Without this, a "drift" report becomes noise: the same two
snapshots would produce different reports depending on dict ordering or on
whether a string was NFC- or NFD-encoded.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any, List

#: Collapse runs of whitespace (including newlines) into a single space.
_WS_RE = re.compile(r"\s+")


def nfc(value: str) -> str:
    """Unicode-normalise a string.

    MCP tool names are attacker-controlled. ``"ｃｒｅａｔｅ"`` (fullwidth) and
    ``"create"`` are different byte strings but visually identical, which is
    exactly how a tool gets shadowed. NFC removes the easy wins; the policy
    layer flags what is left (see ``heuristics.non_ascii_name``).
    """
    return unicodedata.normalize("NFC", value)


def clean_text(value: str) -> str:
    """Normalise a human-readable string for comparison.

    Whitespace is collapsed so that re-indenting a description does not raise a
    finding, while any real change in wording still does.
    """
    return _WS_RE.sub(" ", nfc(value)).strip()


def canonical_json(value: Any) -> str:
    """Serialise deterministically: sorted keys, no insignificant spacing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(value: Any) -> str:
    """Hash a JSON-compatible value canonically."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_file(path: str, *, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def json_pointer(*parts: Any) -> str:
    """Build an RFC 6901 JSON pointer from path segments."""
    if not parts:
        return ""
    out: List[str] = []
    for part in parts:
        token = str(part).replace("~", "~0").replace("/", "~1")
        out.append(token)
    return "/" + "/".join(out)


def stable_sort_key(text: str) -> str:
    """Sort key that does not depend on locale or Unicode collation."""
    return nfc(text)
