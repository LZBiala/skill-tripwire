"""G6 (BLOCKS): the corpus of poisoned samples is defanged, and this proves it.

A repository that publishes attack samples must be safe to clone. Every URL points at
non-resolving reserved space, no sample carries a real secret, and the source file materializes
invisible codepoints from numbers rather than storing raw hidden bytes. If any of this fails,
nothing gets committed until it is fixed.
"""
from __future__ import annotations

import re
from pathlib import Path

import samples

ROOT = Path(__file__).resolve().parents[1]

# Reserved, non-resolving space only (RFC 2606 / RFC 5737 / RFC 3849).
_RESERVED_HOST = re.compile(
    r"""(?ix)
    (?: \.invalid | \.example | (?:^|//|\.)example\.(?:com|net|org)
      | 192\.0\.2\.\d+ | 198\.51\.100\.\d+ | 203\.0\.113\.\d+ | 2001:db8: )
    """,
)
_URL = re.compile(r"https?://[^\s`)>\"']+")
_CRED = re.compile(r"(?i)(sk-ant-|ghp_|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
_DANGEROUS_CP = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
                 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def test_every_url_points_at_reserved_non_resolving_space() -> None:
    offenders = []
    for s in samples.build():
        for url in _URL.findall(s["text"]):
            if not _RESERVED_HOST.search(url):
                offenders.append(f"{s['id']}: {url}")
    assert not offenders, "sample URLs that could resolve: " + "; ".join(offenders)


def test_no_sample_carries_a_real_credential() -> None:
    hits = [s["id"] for s in samples.build() if _CRED.search(s["text"])]
    assert not hits, "credential-shaped strings in samples: " + ", ".join(hits)


def test_the_corpus_source_ships_no_raw_invisible_bytes() -> None:
    # Invisible/bidi/tag codepoints must be built with chr(), never stored literally, so
    # cloning the repo cannot carry a hidden instruction into an editor or an agent.
    src = (ROOT / "corpus" / "samples.py").read_text(encoding="utf-8")
    found = sorted({hex(ord(c)) for c in src if ord(c) in _DANGEROUS_CP
                    or 0xE0000 <= ord(c) <= 0xE007F})
    assert not found, f"raw dangerous codepoints in corpus source: {found}"


def test_the_builder_actually_produces_paired_samples() -> None:
    rows = samples.build()
    mal = [s for s in rows if s["malicious"]]
    ben = [s for s in rows if not s["malicious"]]
    assert len(mal) >= 8 and len(ben) >= 8, "corpus needs both poisons and benign twins"
    assert any(s["held_out"] for s in rows), "there must be a held-out arm"
