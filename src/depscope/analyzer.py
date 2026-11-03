from depscope.models import Dependency, Finding, Vulnerability
from depscope.version import sort_versions

NO_SUMMARY = "(no summary provided)"


def _canonical_key(ids: set[str]) -> str:
    """Pick one stable ID for a finding: prefer CVE, then GHSA, then any."""
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(i for i in ids if i.startswith(prefix))
        if matches:
            return matches[0]
    return sorted(ids)[0]


def merge_vulnerabilities(
    dependency: Dependency, vulns: list[Vulnerability]
) -> list[Finding]:
    """Group records that share any ID into one Finding per real vulnerability."""
    groups = []  # each group: {"ids": set of IDs, "vulns": list of records}

    for vuln in vulns:
        ids = {vuln.id, *vuln.aliases}
        merged = {"ids": set(ids), "vulns": [vuln]}

        overlapping = [g for g in groups if g["ids"] & ids]
        for group in overlapping:
            merged["ids"] |= group["ids"]
            merged["vulns"] += group["vulns"]
            groups.remove(group)

        groups.append(merged)

    findings = []
    for group in groups:
        records = sorted(group["vulns"], key=lambda v: v.id)

        summary = next((v.summary for v in records if v.summary != NO_SUMMARY), NO_SUMMARY)
        severity = next((v.advisory_severity for v in records if v.advisory_severity), None)

        findings.append(
            Finding(
                dependency=dependency,
                key=_canonical_key(group["ids"]),
                ids=tuple(sorted(group["ids"])),
                summary=summary,
                cvss_vectors=tuple(sorted({c for v in records for c in v.cvss_vectors})),
                advisory_severity=severity,
                fixed_versions=sort_versions({f for v in records for f in v.fixed_versions}),
            )
        )

    return sorted(findings, key=lambda f: f.key)
