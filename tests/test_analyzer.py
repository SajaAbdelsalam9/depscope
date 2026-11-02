import json
from pathlib import Path

from depscope.analyzer import merge_vulnerabilities
from depscope.models import Dependency, Vulnerability
from depscope.osv_client import parse_vulnerability

DEP = Dependency("requests", "2.19.0")
FIXTURE = Path(__file__).parent / "fixtures" / "osv_requests_2.19.0.json"


def make_vuln(vuln_id, aliases=(), **kwargs):
    return Vulnerability(id=vuln_id, summary="summary", aliases=tuple(aliases), **kwargs)


def test_empty_input_gives_no_findings():
    assert merge_vulnerabilities(DEP, []) == []


def test_same_vulnerability_under_two_ids_is_one_finding():
    vulns = [
        make_vuln("GHSA-1", ["CVE-1", "PYSEC-1"]),
        make_vuln("PYSEC-1", ["CVE-1", "GHSA-1"]),
    ]
    findings = merge_vulnerabilities(DEP, vulns)
    assert len(findings) == 1
    assert findings[0].key == "CVE-1"
    assert findings[0].ids == ("CVE-1", "GHSA-1", "PYSEC-1")


def test_alias_chain_is_merged_transitively():
    vulns = [make_vuln("A", ["B"]), make_vuln("C", ["B"])]
    assert len(merge_vulnerabilities(DEP, vulns)) == 1


def test_unrelated_records_stay_separate():
    vulns = [make_vuln("CVE-1"), make_vuln("CVE-2")]
    assert len(merge_vulnerabilities(DEP, vulns)) == 2


def test_merge_combines_data_and_keeps_missing_values_missing():
    vulns = [
        make_vuln("GHSA-1", ["CVE-1"], advisory_severity="HIGH", fixed_versions=("2.0",)),
        make_vuln("PYSEC-1", ["CVE-1"]),
    ]
    finding = merge_vulnerabilities(DEP, vulns)[0]
    assert finding.advisory_severity == "HIGH"
    assert finding.fixed_versions == ("2.0",)
    assert finding.has_fix is True


def test_finding_without_fixed_version_has_no_fix():
    finding = merge_vulnerabilities(DEP, [make_vuln("CVE-1")])[0]
    assert finding.has_fix is False
    assert finding.advisory_severity is None


def test_real_requests_data_gives_five_findings():
    raw = json.loads(FIXTURE.read_text())["vulns"]
    vulns = [parse_vulnerability(r, DEP) for r in raw]
    findings = merge_vulnerabilities(DEP, vulns)
    assert len(vulns) == 10
    assert len(findings) == 5
    assert all(len(f.ids) >= 3 for f in findings)
