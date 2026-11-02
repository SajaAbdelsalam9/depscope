import requests

from depscope.models import Dependency

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
