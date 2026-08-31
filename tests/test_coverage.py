"""G14: every rule and every corpus defect maps to a known OWASP Agentic Skills id.

Coverage you cannot enumerate is coverage you are guessing at. This reads the rule registry
and the corpus manifest and fails if anything claims a category the framework does not name.
"""
from __future__ import annotations

import samples

from skill_tripwire.owasp import is_known
from skill_tripwire.rules import RULE_REGISTRY


def test_every_rule_maps_to_a_known_owasp_id() -> None:
    bad = [rid for rid, (_tier, owasp) in RULE_REGISTRY.items() if not is_known(owasp)]
    assert not bad, "rules with an unknown owasp id: " + ", ".join(bad)


def test_every_corpus_sample_maps_to_a_known_owasp_id() -> None:
    bad = [s["id"] for s in samples.build() if not is_known(s["owasp"])]
    assert not bad, "samples with an unknown owasp id: " + ", ".join(bad)


def test_every_targeted_rule_in_the_corpus_exists() -> None:
    bad = [s["id"] for s in samples.build()
           if s["expect_rule"] is not None and s["expect_rule"] not in RULE_REGISTRY]
    assert not bad, "samples naming a rule that does not exist: " + ", ".join(bad)


def test_finding_tier_and_owasp_match_the_registry() -> None:
    # Binds the two copies of each rule's (tier, owasp): the one in the Finding a rule emits and
    # the one in RULE_REGISTRY. Without this, editing a Finding's tier could silently change a
    # verdict while every other gate stays green - the drift the constitution warns about.
    from skill_tripwire.scan import scan
    mismatches = []
    for s in samples.build():
        for f in scan(s["text"]).findings:
            if f.rule_id in RULE_REGISTRY and (f.tier, f.owasp) != RULE_REGISTRY[f.rule_id]:
                mismatches.append(f"{f.rule_id}: finding=({f.tier},{f.owasp}) registry={RULE_REGISTRY[f.rule_id]}")
    assert not mismatches, "; ".join(sorted(set(mismatches)))
