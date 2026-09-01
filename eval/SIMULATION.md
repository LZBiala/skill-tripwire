# skill-tripwire simulation

A seeded randomized run. Reproduce with: `python tools/simulate.py --n 1000000 --seed 1`

## Robustness (crash and hang resistance on small crafted inputs)

- inputs scanned: 1000000 (benign 450360, attack-variant 399474, adversarial-junk 150166)
- crashes: 0 (must be 0)
- scans slower than 0.25s: 0 (a hang would be a DoS)
- slowest single scan: 6.1 ms

## False positives on randomly generated benign text (a real signal)

- spuriously flagged: 0/450360 = 0.000%
The benign text is generated from a config vocabulary, not curated, so this is not a
cherry-picked FPR - it is what random honest-looking files do.

## Detection on obfuscated attack variants (AN UPPER BOUND)

- caught: 399474/399474 = 100.000%
These are payload-preserving obfuscations of self-authored templates, so the rate
measures the author's imagination, not the world. It is an upper bound. A real
generalization number still needs a corpus authored by someone else - the standing
top open item. This run demonstrates crash/hang resistance and a low benign
false-positive rate on small crafted inputs; it does not prove reach.

(run took 125.3s)
