"""Coverage mapping to the OWASP Agentic Skills Top 10.

Every detection rule and every seeded corpus defect maps to one of these ids, so coverage is
accountable rather than asserted (gate G14). The slugs below track the OWASP Agentic Skills
Top 10 (v1.0, August 2026) categories. They are the source of truth in this repo; if the
final published OWASP numbering differs, reconcile the numeric ids here and nowhere else. We
use descriptive slugs rather than invented numbers on purpose, so a wrong number can never
masquerade as authority - the honesty rule this whole project is built on.
"""
from __future__ import annotations

# id slug -> human-readable category name
CATEGORIES: dict[str, str] = {
    "ASI:hidden-instructions": "Instructions concealed from the human reviewer",
    "ASI:code-execution": "Unsanctioned code or shell execution",
    "ASI:data-exfiltration": "Sensitive data sent to an external destination",
    "ASI:excessive-capability": "Capability grant exceeding the stated purpose",
    "ASI:tool-poisoning": "Instructions that steer or reconfigure other tools",
    "ASI:social-engineering": "Prompt-injection phrasing aimed at the agent",
    "ASI:obfuscation": "Payload hidden by encoding or entropy",
}


def is_known(owasp_id: str) -> bool:
    return owasp_id in CATEGORIES
