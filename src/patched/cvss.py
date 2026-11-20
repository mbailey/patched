"""Severity: the advisory's own word first, else a CVSS v3 base score."""
from __future__ import annotations

import math

ORDER = ["unknown", "low", "medium", "high", "critical"]
WORDS = {"low": "low", "moderate": "medium", "medium": "medium", "high": "high",
         "important": "high", "critical": "critical"}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def v3_score(vector: str) -> float | None:
    """CVSS v3.0/3.1 base score from a vector string; None if it doesn't parse."""
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        s = m["S"]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * _PR[s][m["PR"]] * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = impact + expl if s == "U" else 1.08 * (impact + expl)
    return _roundup(min(total, 10))


def rating(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "unknown"


def severity(rec: dict) -> str:
    """One of ORDER for an OSV record."""
    word = (rec.get("database_specific") or {}).get("severity")
    if isinstance(word, str) and word.lower() in WORDS:
        return WORDS[word.lower()]
    for a in rec.get("affected", []):
        w = (a.get("ecosystem_specific") or {}).get("severity")
        if isinstance(w, str) and w.lower() in WORDS:
            return WORDS[w.lower()]
    for s in rec.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score = v3_score(s.get("score", ""))
            if score is not None:
                return rating(score)
    return "unknown"


def worst(*levels: str) -> str:
    return max(levels, key=ORDER.index) if levels else "unknown"
