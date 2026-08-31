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
