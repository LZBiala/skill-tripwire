# The evaluation corpus - read before you touch it

This directory holds seeded examples of poisoned skill and config files. They exist so the
scanner's detection and false-positive rates can be measured against something real. They are
**defanged and inert**, and a test (`tests/test_corpus_safety.py`) blocks the build if that
ever stops being true.

## Safety invariants (enforced, not promised)

- **Every URL points at reserved, non-resolving space** - `.invalid`, `.example`,
  `example.com`, TEST-NET (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and
  `2001:db8::/32`. Nothing here resolves.
- **No working payload.** The shell one-liners are data inside a file that a scanner reads;
  nothing in this repo executes them. There is no `curl | bash` that runs, only text that
  looks like one so the scanner can be tested against it.
- **No real secret, key, credential, or live path.** Only placeholders and fictional paths.
- **No raw invisible bytes on disk.** Invisible, bidi, and tag codepoints are built with
  `chr()` from numbers at runtime, so cloning this repo cannot carry a hidden instruction into
  your editor or your agent. The whole repo is checked for this.

## Not auto-loaded

The corpus is deliberately not part of the installable package and is never loaded by the
scanner at runtime. It is imported only by the eval harness and the tests.

## Provenance

Attack *shapes* are drawn from public research - Invariant Labs tool poisoning, Snyk
ToxicSkills categories, Rehberger's invisible-character work, Datadog's pre-execution gap, and
the OWASP Agentic Skills Top 10. No sample reproduces a real attacker's payload, targets a real
person or organization, or contains working attacker infrastructure. This corpus is for
defensive evaluation only.
