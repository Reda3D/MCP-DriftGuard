"""Deterministic heuristics for tool-poisoning signals.

These are *pattern matches*, not a model and not an opinion. Every rule is a
literal regular expression with a stable code, listed in the documentation, so
a finding can always be reproduced and argued with. Nothing here can block a
build on its own — the policy decides, and the shipped default policy keeps
these at a non-blocking level.
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Tuple

#: (code, human description, compiled pattern)
_PATTERNS: Tuple[Tuple[str, str, "re.Pattern[str]"], ...] = (
    (
        "DG-H001",
        "instruction-override phrasing in description",
        re.compile(
            r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system)\b"
            r"[^.\n]{0,20}\b(instruction|prompt|rule|direction)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DG-H002",
        "description instructs the agent to conceal its actions",
        re.compile(
            r"\b(do\s+not|don'?t|never)\b[^.\n]{0,30}\b(tell|inform|notify|mention|reveal)\b"
            r"[^.\n]{0,30}\b(user|human|operator)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DG-H003",
        "description references the system prompt or hidden context",
        re.compile(r"\bsystem\s+(prompt|message|instruction)s?\b", re.IGNORECASE),
    ),
    (
        "DG-H004",
        "description contains an embedded URL",
        re.compile(r"https?://[^\s\)\]\"'>]+", re.IGNORECASE),
    ),
    (
        "DG-H005",
        "description references credentials or secrets",
        re.compile(
            r"\b(api[_\s-]?key|secret|token|password|credential|private\s+key)s?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DG-H006",
        "description instructs the agent to act before or without confirmation",
        re.compile(
            r"\b(before|without)\b[^.\n]{0,30}\b(asking|confirming|confirmation|consent|telling)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "DG-H007",
        "long base64-like blob in description",
        re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
    ),
)

#: Zero-width and bidirectional control characters. Their only legitimate use in
#: a tool description is roughly none, and they let text render differently from
#: what is actually stored.
_INVISIBLE = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\ufeff": "zero-width no-break space",
    "\u202a": "left-to-right embedding",
    "\u202b": "right-to-left embedding",
    "\u202d": "left-to-right override",
    "\u202e": "right-to-left override",
    "\u2066": "left-to-right isolate",
    "\u2067": "right-to-left isolate",
    "\u2069": "pop directional isolate",
}


def find_suspicious_patterns(description: str) -> List[Tuple[str, str]]:
    """Return ``(code, description)`` for each heuristic that fires."""
    hits: List[Tuple[str, str]] = []
    if not description:
        return hits
    for code, label, pattern in _PATTERNS:
        if pattern.search(description):
            hits.append((code, label))
    for char, label in _INVISIBLE.items():
        if char in description:
            hits.append(("DG-H010", "invisible control character (%s)" % label))
            break
    return hits


def has_invisible_characters(text: str) -> bool:
    return any(char in text for char in _INVISIBLE)


#: Minimal, documented fold table for the homoglyphs that actually get used to
#: shadow tool names. This is deliberately not the full Unicode confusables
#: table: an exhaustive list would create false positives on legitimate
#: non-Latin names while still missing novel substitutions.
_CONFUSABLES = {
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",  # Cyrillic ie
    "\u043e": "o",  # Cyrillic o
    "\u0440": "p",  # Cyrillic er
    "\u0441": "c",  # Cyrillic es
    "\u0443": "y",  # Cyrillic u
    "\u0445": "x",  # Cyrillic ha
    "\u0456": "i",  # Cyrillic dotted i
    "\u0455": "s",  # Cyrillic dze
    "\u0501": "d",  # Cyrillic komi de
    "\u0261": "g",  # Latin script g
    "\u03b1": "a",  # Greek alpha
    "\u03bf": "o",  # Greek omicron
    "\u03c1": "p",  # Greek rho
}


def confusable_fold(name: str) -> str:
    """Best-effort fold of lookalike characters onto their Latin skeleton.

    Deliberately conservative: it normalises compatibility forms (fullwidth,
    mathematical alphanumerics) and folds a short list of common Cyrillic and
    Greek substitutions. It is a signal generator, not a proof.
    """
    folded = unicodedata.normalize("NFKD", name)
    folded = "".join(char for char in folded if not unicodedata.combining(char))
    folded = "".join(_CONFUSABLES.get(char, char) for char in folded)
    return unicodedata.normalize("NFC", folded)
