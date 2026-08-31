"""Make the quarantined corpus and the eval harness importable by tests, without shipping
them as part of the installable package. The corpus is deliberately not on the package path -
it is data for evaluation, never something the scanner auto-loads."""
import sys
from pathlib import Path

ROOT = Path(__file__).parent
for sub in ("corpus", "eval"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)
