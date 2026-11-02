from depscope.analyzer import merge_vulnerabilities
from depscope.models import Dependency, Finding
from depscope.osv_client import OSVError, parse_vulnerability, query_dependency


def scan(dependencies: list[Dependency]) -> tuple[list[Finding], list[tuple[Dependency, str]]]:
    """Look up every dependency in OSV.

    Returns (findings, errors). A dependency that could not be checked appears
    in errors; it is never silently treated as clean.
    """
    findings = []
    errors = []

    for dependency in dependencies:
        try:
            raw_records = query_dependency(dependency)
            vulns = [parse_vulnerability(raw, dependency) for raw in raw_records]
        except OSVError as error:
            errors.append((dependency, str(error)))
            continue

        findings.extend(merge_vulnerabilities(dependency, vulns))

    return findings, errors
