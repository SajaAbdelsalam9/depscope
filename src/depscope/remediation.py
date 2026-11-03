from dataclasses import dataclass

from depscope.models import Dependency, Finding
from depscope.scanner import scan
from depscope.version import lowest_fix_above, parse_version


@dataclass(frozen=True)
class Recommendation:
    dependency: Dependency
    target_version: str | None
    unfixed_keys: tuple[str, ...] = ()


def recommend(dependency: Dependency, findings: list[Finding]) -> Recommendation:
    """Suggest the lowest version that has a listed fix for every fixable finding."""
    own = [f for f in findings if f.dependency == dependency]
    targets = []
    unfixed = []
    for finding in own:
        target = lowest_fix_above(dependency.version, finding.fixed_versions)
        if target is None:
            unfixed.append(finding.key)
        else:
            targets.append(target)

    highest = max(targets, key=parse_version) if targets else None
    return Recommendation(dependency, highest, tuple(sorted(unfixed)))


def verify(recommendation: Recommendation):
    """Ask OSV about the suggested version. Returns (findings, errors) like scan()."""
    if recommendation.target_version is None:
        return [], []
    dependency = recommendation.dependency
    candidate = Dependency(dependency.name, recommendation.target_version, dependency.ecosystem)
    return scan([candidate])


def print_recommendations(dependencies: list[Dependency], findings: list[Finding]) -> None:
    affected = [d for d in dependencies if any(f.dependency == d for f in findings)]
    if not affected:
        return

    print("\nSUGGESTED UPGRADES")
    for dependency in affected:
        rec = recommend(dependency, findings)
        label = f"{dependency.name}=={dependency.version}"

        if rec.target_version is None:
            print(f"  {label}: no fixed version above the installed one is listed")
        else:
            remaining, errors = verify(rec)
            if errors:
                status = "could not be checked against OSV"
            elif remaining:
                keys = ", ".join(f.key for f in remaining)
                status = f"OSV still reports {len(remaining)} vulnerability(ies) at that version: {keys}"
            else:
                status = "OSV reports no known vulnerabilities at that version"
            print(f"  {label}: upgrade to {rec.target_version} - {status}")

        if rec.unfixed_keys:
            print(f"      no fix listed for: {', '.join(rec.unfixed_keys)}")

    print("  (Based on OSV data only. Test your application before upgrading.)")
