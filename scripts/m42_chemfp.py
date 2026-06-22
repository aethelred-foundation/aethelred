#!/usr/bin/env python3
"""A real, dependency-free molecular fingerprint for ligand-based virtual
screening on real ChEMBL structures.

This is a path-based (Daylight-style) fingerprint over a chemically-aware SMILES
tokenization: it hashes linear substructure fragments of the molecule into a bit
set and compares molecules by Tanimoto similarity. It is intentionally a
*baseline* — not RDKit Morgan — to keep the M42 stack dependency-free. The point
of the real-data benchmark is that the **data and labels are real** (wet-lab
IC50), so the screen is no longer circular; the fingerprint just has to capture
real shared substructure, which scaffold-sharing inhibitors do.
"""

from __future__ import annotations

import re
from functools import lru_cache

# Chemically-aware SMILES tokenizer: two-letter elements, bracketed atoms,
# aromatic lowercase, bonds, branches, and ring closures each become one token.
_SMILES_TOKEN = re.compile(
    r"(\[[^\]]+\]|Br|Cl|Si|Se|@@|@|=|#|\$|:|/|\\|\(|\)|\.|%\d{2}|[BCNOPSFIbcnopsi]|\d)"
)


def tokenize_smiles(smiles: str) -> list[str]:
    """Split a SMILES string into chemically meaningful tokens."""
    return _SMILES_TOKEN.findall(smiles)


def _hash_fragment(fragment: str, nbits: int) -> int:
    # Deterministic, stable across processes (unlike Python's salted hash()).
    h = 1469598103934665603  # FNV-1a 64-bit offset basis
    for ch in fragment:
        h ^= ord(ch)
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h % nbits


@lru_cache(maxsize=4096)
def fingerprint(smiles: str, nbits: int = 4096, max_path: int = 7) -> frozenset[int]:
    """Path-based structural fingerprint: the set of on-bits produced by hashing
    every linear token sub-path of length 1..max_path. Empty for an empty string.
    """
    tokens = tokenize_smiles(smiles)
    bits: set[int] = set()
    n = len(tokens)
    for start in range(n):
        frag = ""
        for length in range(1, max_path + 1):
            if start + length > n:
                break
            frag = "".join(tokens[start:start + length])
            bits.add(_hash_fragment(frag, nbits))
    return frozenset(bits)


def tanimoto(fp_a: frozenset[int], fp_b: frozenset[int]) -> float:
    """Tanimoto (Jaccard) similarity between two fingerprint bit sets."""
    if not fp_a and not fp_b:
        return 0.0
    inter = len(fp_a & fp_b)
    union = len(fp_a) + len(fp_b) - inter
    return inter / union if union else 0.0
