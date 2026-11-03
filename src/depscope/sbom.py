import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from depscope.models import Dependency
from depscope.parser import parse_file

SPEC_VERSION = "1.6"
TOOL_VERSION = "0.1.0"
SERIAL_PATTERN = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def package_url(dependency: Dependency) -> str:
    """Build a package URL (purl) such as pkg:pypi/requests@2.19.0."""
    name = quote(dependency.name.lower().replace("_", "-"), safe="")
    version = quote(dependency.version, safe="")
    return f"pkg:pypi/{name}@{version}"


def build_sbom(dependencies, generated_at=None, serial_number=None) -> dict:
    components = {}
    for dependency in dependencies:
        purl = package_url(dependency)
        components[purl] = {
            "type": "library",
            "bom-ref": purl,
            "name": dependency.name,
            "version": dependency.version,
            "purl": purl,
        }

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at
            or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {"type": "application", "name": "DepScope", "version": TOOL_VERSION}
                ]
            },
        },
        "components": [components[key] for key in sorted(components)],
    }


def check_sbom_structure(bom: dict) -> list[str]:
    """DepScope's own sanity checks. This is NOT the official schema validation."""
    problems = []

    if bom.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be 'CycloneDX'")
    if not isinstance(bom.get("specVersion"), str):
        problems.append("specVersion is missing")

    serial = bom.get("serialNumber")
    if not isinstance(serial, str) or not SERIAL_PATTERN.fullmatch(serial):
        problems.append("serialNumber must look like urn:uuid:<lowercase uuid>")

    version = bom.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        problems.append("version must be an integer of at least 1")

    if not bom.get("metadata", {}).get("timestamp"):
        problems.append("metadata.timestamp is missing")

    seen = set()
    for index, component in enumerate(bom.get("components", [])):
        where = f"components[{index}]"
        for field in ("type", "name", "version", "bom-ref", "purl"):
            if not component.get(field):
                problems.append(f"{where}: missing {field}")

        ref = component.get("bom-ref")
        if ref in seen:
            problems.append(f"{where}: duplicate bom-ref {ref}")
        seen.add(ref)

        purl = component.get("purl") or ""
        if not purl.startswith("pkg:pypi/") or "@" not in purl:
            problems.append(f"{where}: purl is malformed")

    return problems


def write_sbom(bom: dict, path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(bom, file, indent=2, ensure_ascii=False)


def run_sbom(requirements_path: str, output_path: str) -> int:
    dependencies, issues = parse_file(requirements_path)
    bom = build_sbom(dependencies)

    problems = check_sbom_structure(bom)
    if problems:
        print("SBOM failed DepScope's structure check:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    write_sbom(bom, output_path)
    print(f"SBOM with {len(bom['components'])} component(s) written to {output_path}")

    if issues:
        print("\nUnsupported lines (NOT included in the SBOM):")
        for issue in issues:
            print(f"  line {issue.line_number}: {issue.text}")

    return 0
