from dataclasses import dataclass

from depscope.models import Finding

SEVERITY_POINTS = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}
UNKNOWN_SEVERITY_POINTS = 2
NEW_POINTS = 2
FIX_POINTS = 1


@dataclass(frozen=True)
class Priority:
    finding: Finding
    score: int
    level: str
    reasons: tuple[str, ...]


def level_for(score: int) -> str:
    if score >= 5:
        return "P1"
    if score == 4:
        return "P2"
    if score == 3:
        return "P3"
    return "P4"


def prioritize(finding: Finding, is_new: bool = False) -> Priority:
    """DepScope's own ranking. Not CVSS, and not an industry standard."""
    reasons = []
    label = (finding.advisory_severity or "").upper()

    if label in SEVERITY_POINTS:
        score = SEVERITY_POINTS[label]
        reasons.append(f"+{score} advisory severity label is {label}")
    else:
        score = UNKNOWN_SEVERITY_POINTS
        reasons.append(
            f"+{score} severity not available, treated as MODERATE for ranking (not a real rating)"
        )

    if is_new:
        score += NEW_POINTS
        reasons.append(f"+{NEW_POINTS} newly introduced by this change")

    if finding.has_fix:
        score += FIX_POINTS
        reasons.append(f"+{FIX_POINTS} a fixed version is listed")

    return Priority(finding, score, level_for(score), tuple(reasons))


def prioritize_all(findings, new_keys=frozenset()) -> list[Priority]:
    """Rank findings, highest score first, ties broken by finding key."""
    ranked = [prioritize(f, is_new=f.key in new_keys) for f in findings]
    return sorted(ranked, key=lambda p: (-p.score, p.finding.key))
