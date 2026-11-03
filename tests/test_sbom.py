import json

from depscope.models import Dependency
from depscope.sbom import (
    SERIAL_PATTERN,
    build_sbom,
    check_sbom_structure,
    package_url,
    run_sbom,
    write_sbom,
)

FIXED_TIME = "2026-01-01T00:00:00+00:00"


def test_package_url_normalizes_name_and_encodes_version():
    assert package_url(Dependency("requests", "2.19.0")) == "pkg:pypi/requests@2.19.0"
    assert package_url(Dependency("Flask_Login", "0.6.3")) == "pkg:pypi/flask-login@0.6.3"
    assert package_url(Dependency("pkg", "1.0+cpu")) == "pkg:pypi/pkg@1.0%2Bcpu"


def test_sbom_has_required_top_level_fields():
    bom = build_sbom([Dependency("requests", "2.19.0")], generated_at=FIXED_TIME)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["version"] == 1
    assert SERIAL_PATTERN.fullmatch(bom["serialNumber"])
    assert bom["metadata"]["timestamp"] == FIXED_TIME
    assert bom["metadata"]["tools"]["components"][0]["name"] == "DepScope"


def test_components_are_sorted_and_duplicates_collapse():
    deps = [Dependency("zlib", "1.0"), Dependency("alpha", "2.0"), Dependency("alpha", "2.0")]
    bom = build_sbom(deps)
    assert [c["name"] for c in bom["components"]] == ["alpha", "zlib"]


def test_generated_sbom_passes_structure_check():
    bom = build_sbom([Dependency("requests", "2.19.0"), Dependency("flask", "2.0.1")])
    assert check_sbom_structure(bom) == []


def test_structure_check_detects_problems():
    bom = build_sbom([Dependency("a", "1")])
    bom["serialNumber"] = "bad"
    bom["components"][0]["purl"] = "nope"
    del bom["components"][0]["version"]
    bom["components"].append(dict(bom["components"][0]))
    problems = check_sbom_structure(bom)
    assert any("serialNumber" in p for p in problems)
    assert any("purl is malformed" in p for p in problems)
    assert any("missing version" in p for p in problems)
    assert any("duplicate bom-ref" in p for p in problems)


def test_empty_inventory_is_valid():
    bom = build_sbom([])
    assert bom["components"] == []
    assert check_sbom_structure(bom) == []


def test_serial_number_differs_between_runs():
    assert build_sbom([])["serialNumber"] != build_sbom([])["serialNumber"]


def test_run_sbom_writes_file_and_excludes_unsupported_lines(tmp_path, capsys):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.19.0\ndjango>=3.2\n")
    output = tmp_path / "out" / "sbom.json"

    assert run_sbom(str(requirements), str(output)) == 0

    data = json.loads(output.read_text(encoding="utf-8"))
    assert [c["name"] for c in data["components"]] == ["requests"]
    assert "NOT included in the SBOM" in capsys.readouterr().out
