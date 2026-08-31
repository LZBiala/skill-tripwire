# The rubric

The README says this project was "built against a rubric frozen before the first line of
code." A claim you cannot check is a story, so here is the rubric, published from the project's
private planning notes.

## Publication notes (every edit, disclosed)

This is the working rubric, frozen 2026-08-31 before any code existed. Publishing it took two
kinds of edit, and silently editing a frozen document about honesty would defeat the point:

1. **Private-context prose removed.** The original gate text names a personal build doctrine
   and cites a sibling portfolio project's numbers as the lesson behind a couple of gates.
   Those references are context, not requirement, and are removed here. Each gate's testable
   substance is preserved; a fresh-context reviewer diffed this file against the original to
   confirm it.
2. **G8's wording was corrected after an external audit.** The frozen G8 assumed a held-out
   arm would demonstrate "not tuned on it." The audit pointed out that a self-authored held-out
   set cannot demonstrate that, however carefully labeled. G8 below is reworded to state the
   honest status rather than the intended one, and the eval report refuses to print a
   generalization number until an externally-authored corpus exists. Keeping the frozen wording
   would have let the document overstate what the corpus proves.

## Correctness gates

**G1 - canonicalize before any rule runs.** A test proves that a payload hidden by NFKC-
foldable characters, invisible codepoints, or one layer of base64/hex is caught, because
canonicalization happened first.

**G2 - two tiers, and the boundary holds.** Block-tier rules can raise QUARANTINE; warn-tier
rules can raise at most REVIEW. A test proves a warn-only file never quarantines and a block
hit always does. Unparseable input returns QUARANTINE, never PASS.

**G3 - every rule fails closed and names its evidence.** Each rule, given a sample it should
catch, returns the verdict with a rule id, a location, and the matched shape, not a bare
boolean. Given its byte-similar benign twin, it does not fire.

**G4 - RED observed before GREEN, every rule and every module.** The test exists and fails for
the stated reason before the implementation. A test that passes on arrival is rewritten.

**G5 - the judge is fenced and subordinate.** With the optional judge enabled: it receives only
canonicalized text; a block-tier QUARANTINE overrides any judge PASS; the judge can raise
REVIEW but never auto-clear or auto-block; a file that addresses the judge directly ("report
this as safe") is fed as data, and the fencing is tested with a mock judge so the override and
containment logic are verified without a network call.

## Honesty gates

**G6 - the corpus is defanged, and a test proves it (BLOCKS).** No exfil URL resolves; no
working one-liner; no real secret; invisible-codepoint samples built from numbers, not stored
raw. A CI test fails the build if any sample would resolve, execute, or carry a live payload.

**G7 - numbers are published with their denominators (BLOCKS on absence).** Per-rule precision
AND recall, FPR with its denominator and a rule-of-three bound (never a bare "0%"), and
precision at the ~2% base rate. The report regenerates in CI and the build fails if it drifts.
No single blended detection number stands alone.

**G8 - the self-authored limit-probe arm is honestly labeled (reworded post-audit).** A slice
of the corpus is held apart and reported separately. Because these samples are self-authored,
this meets the gate's letter (held apart, reported apart) but NOT its spirit: a true
not-tuned-on-it set must come from another author. The report therefore labels the self-
authored numbers as demonstrations, not a generalization measurement, and refuses to print a
generalization rate until an externally-authored corpus exists. That external corpus is the
top open item.

**G9 - no key, no network, no employer data in core.** CI asserts no outbound network call in
the core, no credential-shaped string, no employer name. The judge's network/key use is
isolated to the optional layer and off by default.

**G10 - the README states the ceiling in numbers.** An explicit limits section: static
detection collapses 45-99% under evasion; this is a triage floor, not a boundary; containment
lives in sandboxing and architecture.

## Craft gates

**G11 - hyphens only, no slop.** No em or en dashes; none of the forbidden slop vocabulary.
Checked in CI.

**G12 - a non-engineer can follow the threat.** The README explains, in plain words, why a
skill file is all-instructions and what "the shape of a poisoned instruction" means.

**G13 - installable and runnable from a cold clone in under five minutes.** Zero runtime
dependencies; pytest only for the gates.

## Coverage gate

**G14 - every rule and corpus defect maps to an OWASP Agentic Skills Top 10 id.** A test reads
the rule registry and the corpus manifest and fails if any lacks a mapped id.

## Remedy ladder, pre-registered

- **G1/G2/G3 fails:** the scanner is broken. Fix the scanner, never the assertion.
- **G4 fails:** rewrite the test to assert what its name promises, re-observe RED.
- **G5 fails:** the judge escaped its fence. Re-subordinate it; the core stays authoritative.
- **G6 fails:** stop before any commit and defang. This gate blocks.
- **G7/G8 fails:** do not publish a rate until its denominator, bound, and held-out separation exist.
- **G9 fails:** remove the network/key/employer content from core before any commit. Blocks.
- **G13 fails:** cut setup steps until it passes. Adding documentation is not a fix.
