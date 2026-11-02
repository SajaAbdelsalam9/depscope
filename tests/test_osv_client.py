import json
import re
from pathlib import Path

import pytest
import requests

from depscope import osv_client
from depscope.models import Dependency
from depscope.osv_client import OSVError, parse_vulnerability, query_dependency

FIXTURE = Path(__file__).parent / "fixtures" / "osv_requests_2.19.0.json"
DEP = Dependency("requests", "2.19.0")


@pytest.fixture
def raw_records():
    return json.loads(FIXTURE.read_text())["vulns"]


def test_all_fixture_records_parse(raw_records):
    vulns = [parse_vulnerability(raw, DEP) for raw in raw_records]
    assert len(vulns) == 10


def test_fixed_versions_are_versions_not_commit_hashes(raw_records):
    for raw in raw_records:
        vuln = parse_vulnerability(raw, DEP)
        for fixed in vuln.fixed_versions:
            assert re.fullmatch(r"\d+(\.\d+)*", fixed), f"{vuln.id}: {fixed}"


def test_record_without_severity_keeps_none_and_empty(raw_records):
    raw = next(r for r in raw_records if r["id"] == "PYSEC-2018-28")
    vuln = parse_vulnerability(raw, DEP)
    assert vuln.advisory_severity is None
    assert vuln.cvss_vectors == ()


def test_ghsa_record_extracts_label_aliases_and_fix(raw_records):
    raw = next(r for r in raw_records if r["id"] == "GHSA-x84v-xcm2-53pg")
    vuln = parse_vulnerability(raw, DEP)
    assert vuln.advisory_severity == "HIGH"
    assert "CVE-2018-18074" in vuln.aliases
    assert vuln.fixed_versions == ("2.20.0",)


def test_record_without_id_raises():
    with pytest.raises(OSVError):
        parse_vulnerability({"summary": "no id"}, DEP)


def test_network_failure_raises_error_instead_of_empty_list(monkeypatch):
    def fake_post(*args, **kwargs):
        raise requests.ConnectionError("no internet")

    monkeypatch.setattr(osv_client.requests, "post", fake_post)
    with pytest.raises(OSVError):
        query_dependency(DEP)
