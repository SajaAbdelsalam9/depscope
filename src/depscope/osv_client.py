import requests

from depscope.models import Dependency, Vulnerability

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
TIMEOUT_SECONDS = 10


class OSVError(Exception):
    """Raised when OSV cannot be reached or returns an unusable answer."""


def query_dependency(dependency: Dependency) -> list[dict]:
    """Ask OSV for known vulnerabilities affecting one exact dependency version."""
    payload = {
        "package": {"name": dependency.name, "ecosystem": dependency.ecosystem},
        "version": dependency.version,
    }

    try:
        response = requests.post(OSV_QUERY_URL, json=payload, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as error:
        raise OSVError(f"OSV request failed for {dependency.name}: {error}") from error
    except ValueError as error:
        raise OSVError(f"OSV returned invalid JSON for {dependency.name}") from error

    return data.get("vulns", [])


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def parse_vulnerability(raw: dict, dependency: Dependency) -> Vulnerability:
    """Convert one raw OSV record into a Vulnerability."""
    vuln_id = raw.get("id")
    if not vuln_id:
        raise OSVError("OSV record without an id")

    cvss_vectors = tuple(
        item["score"] for item in raw.get("severity", []) if "score" in item
    )
    advisory_severity = raw.get("database_specific", {}).get("severity")

    fixed = set()
    for affected in raw.get("affected", []):
        package = affected.get("package", {})
        if _normalize(package.get("name", "")) != _normalize(dependency.name):
            continue
        for version_range in affected.get("ranges", []):
            if version_range.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in version_range.get("events", []):
                if "fixed" in event:
                    fixed.add(event["fixed"])

    return Vulnerability(
        id=vuln_id,
        summary=raw.get("summary") or "(no summary provided)",
        aliases=tuple(raw.get("aliases", [])),
        cvss_vectors=cvss_vectors,
        advisory_severity=advisory_severity,
        fixed_versions=tuple(sorted(fixed)),
    )
