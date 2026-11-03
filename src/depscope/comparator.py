import re
from dataclasses import dataclass

from depscope.models import Dependency, Finding


def package_key(dependency: Dependency) -> tuple[str, str]:
    """Stable identity for a package: ecosystem plus normalized name."""
    return (dependency.ecosystem, re.sub(r"[-_.]+", "-", dependency.name).lower())


@dataclass(frozen=True)
class DependencyChange:
    name: str
    before: str
    after: str


@dataclass(frozen=True)
class FindingChange:
    finding: Finding
    reason: str


@dataclass(frozen=True)
class Comparison:
    added: tuple[Dependency, ...]
    removed: tuple[Dependency, ...]
    updated: tuple[DependencyChange, ...]
    unchanged: tuple[Dependency, ...]
    new_findings: tuple[FindingChange, ...]
    resolved_findings: tuple[FindingChange, ...]
    persistent_findings: tuple[Finding, ...]


def _same_finding(a: Finding, b: Finding) -> bool:
    same_package = package_key(a.dependency) == package_key(b.dependency)
    return same_package and bool(set(a.ids) & set(b.ids))


def _has_match(finding: Finding, candidates: list[Finding]) -> bool:
    return any(_same_finding(finding, c) for c in candidates)


def compare(
    before_deps: list[Dependency],
    before_findings: list[Finding],
    after_deps: list[Dependency],
    after_findings: list[Finding],
) -> Comparison:
    before_map = {package_key(d): d for d in before_deps}
    after_map = {package_key(d): d for d in after_deps}

    added = [d for k, d in after_map.items() if k not in before_map]
    removed = [d for k, d in before_map.items() if k not in after_map]
    updated = []
    unchanged = []
    for key, after_dep in after_map.items():
        before_dep = before_map.get(key)
        if before_dep is None:
            continue
        if before_dep.version != after_dep.version:
            updated.append(DependencyChange(after_dep.name, before_dep.version, after_dep.version))
        else:
            unchanged.append(after_dep)

    new_findings = []
    persistent = []
    for finding in after_findings:
        if _has_match(finding, before_findings):
            persistent.append(finding)
            continue
        key = package_key(finding.dependency)
        if key not in before_map:
            reason = "dependency is new"
        elif before_map[key].version != finding.dependency.version:
            reason = "dependency version changed"
        else:
            reason = "not in earlier results for the same version (newly disclosed, or earlier data incomplete)"
        new_findings.append(FindingChange(finding, reason))

    resolved = []
    for finding in before_findings:
        if _has_match(finding, after_findings):
            continue
        key = package_key(finding.dependency)
        if key not in after_map:
            reason = "dependency was removed"
        elif after_map[key].version != finding.dependency.version:
            reason = "dependency version changed"
        else:
            reason = "no longer reported for the same version (advisory withdrawn, or data changed)"
        resolved.append(FindingChange(finding, reason))

    return Comparison(
        added=tuple(sorted(added, key=lambda d: d.name.lower())),
        removed=tuple(sorted(removed, key=lambda d: d.name.lower())),
        updated=tuple(sorted(updated, key=lambda u: u.name.lower())),
        unchanged=tuple(sorted(unchanged, key=lambda d: d.name.lower())),
        new_findings=tuple(sorted(new_findings, key=lambda c: c.finding.key)),
        resolved_findings=tuple(sorted(resolved, key=lambda c: c.finding.key)),
        persistent_findings=tuple(sorted(persistent, key=lambda f: f.key)),
    )
