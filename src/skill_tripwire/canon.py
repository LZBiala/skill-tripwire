"""Canonicalization: the spine of the scanner.

A poisoned file hides its payload from the human and from a naive matcher using the same
tricks: fullwidth or compatibility characters that fold to ASCII only after normalization,
zero-width and tag codepoints that split a word so no regex sees it whole, and base64 or hex
blobs that carry a shell one-liner past a text search. Every one of those is defeated by
canonicalizing first. Nothing else in this project runs before this module.

The output carries three things a downstream rule needs:
  - `text`: NFKC-normalized, with invisible codepoints removed, so a split word reads whole.
  - `invisibles`: an inventory of what was removed. Invisible format characters have no
    legitimate use in a config file, so the inventory is itself evidence, not just cleanup.
  - `decodings` + `scan_text`: nested base64/hex decoded and appended, so a rule can find a
    payload that was hidden inside an encoded blob.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass

# Codepoints with no business in a human-authored config file, grouped by how they attack.
_TAG_LOW, _TAG_HIGH = 0xE0000, 0xE007F
_BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}


@dataclass(frozen=True)
class Invisible:
    codepoint: int
    name: str
    offset: int
    category: str  # "tag" | "bidi" | "zero_width" | "other_invisible"


@dataclass(frozen=True)
class Decoding:
    scheme: str  # "base64" | "hex"
    span: tuple[int, int]
    decoded: str
    depth: int


@dataclass(frozen=True)
class CanonResult:
    original: str
    text: str
    invisibles: tuple[Invisible, ...]
    decodings: tuple[Decoding, ...]
    scan_text: str


def _classify(cp: int) -> str | None:
    """Name the attack class for a codepoint, or None if it is legitimate text/whitespace."""
    if _TAG_LOW <= cp <= _TAG_HIGH:
        return "tag"
    if cp in _BIDI:
        return "bidi"
    if cp in _ZERO_WIDTH:
        return "zero_width"
    ch = chr(cp)
    # Tab, newline, carriage return are control characters but are ordinary in a text file.
    if ch in "\t\n\r":
        return None
    # Format characters (Cf) and unassigned/private-use are invisible smuggle vectors; normal
    # letters, digits, punctuation, and spaces (Zs) are not.
    if unicodedata.category(ch) in {"Cf", "Co", "Cn"}:
        return "other_invisible"
    return None


def _strip_invisibles(text: str) -> tuple[str, tuple[Invisible, ...]]:
    kept: list[str] = []
    found: list[Invisible] = []
    for offset, ch in enumerate(text):
        cat = _classify(ord(ch))
        if cat is None:
            kept.append(ch)
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = f"U+{ord(ch):04X}"
        found.append(Invisible(ord(ch), name, offset, cat))
    return "".join(kept), tuple(found)


_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\t\n\r ")
    return ok / len(s)


def _decode_blobs(text: str, depth: int, max_depth: int) -> list[Decoding]:
    """Find base64/hex runs, decode the ones that yield printable text, recurse once.

    Bounded on purpose: a finite decoder cannot chase infinite nesting, and the README says
    so. Two layers catches the common "base64 inside the file, shell inside the base64" case
    without turning the scanner into a decompression bomb target.
    """
    out: list[Decoding] = []
    if depth > max_depth:
        return out
    for m in _B64_RUN.finditer(text):
        raw = m.group(0)
        if len(raw) % 4:
            continue
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        if _printable_ratio(decoded) >= 0.9 and decoded.strip():
            out.append(Decoding("base64", m.span(), decoded, depth))
            out.extend(_decode_blobs(decoded, depth + 1, max_depth))
    for m in _HEX_RUN.finditer(text):
        raw = m.group(0)
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", "replace")
        except ValueError:
            continue
        if _printable_ratio(decoded) >= 0.9 and decoded.strip():
            out.append(Decoding("hex", m.span(), decoded, depth))
            out.extend(_decode_blobs(decoded, depth + 1, max_depth))
    return out


def canonicalize(text: str, *, max_decode_depth: int = 2) -> CanonResult:
    """Fold, strip, and decode, in that order, and report what each step exposed."""
    # A single leading U+FEFF is a byte-order mark: encoding metadata many editors and shells
    # write, not a hidden instruction. Drop it before classification so a benign BOM does not
    # read as an attack. The same codepoint anywhere else stays suspicious and is inventoried.
    if text[:1] == chr(0xFEFF):
        text = text[1:]
    normalized = unicodedata.normalize("NFKC", text)
    cleaned, invisibles = _strip_invisibles(normalized)
    decodings = tuple(_decode_blobs(cleaned, 1, max_decode_depth))
    if decodings:
        scan_text = cleaned + "\n" + "\n".join(d.decoded for d in decodings)
    else:
        scan_text = cleaned
    return CanonResult(
        original=text,
        text=cleaned,
        invisibles=invisibles,
        decodings=decodings,
        scan_text=scan_text,
    )
