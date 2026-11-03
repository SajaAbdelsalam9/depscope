import csv
import json

from depscope.models import Dependency, Finding, ParseIssue
from depscope.report import build_report, write_csv, write_json

REQ = Dependency("requests", "2.19.0")
FLASK = Dependency("flask", "2.0.1")
FIXED_TIME = "2026-01-01T00:00:00+00:00"


def make(dep, key, severity=None, fixed=(), summary="s"):
    return Finding(
        dependency=dep, key=key, ids=(key,), summary=summary,
        advisory_severity=severity, fixed_versions=tuple(fixed),
    )


def test_summary_counts_and_severity_distribution():
    findings = [make(REQ, "A", "HIGH", ["2.20.0"]), make(REQ, "B")]
    report = build_report("req.txt", [REQ, FLASK], [], findings, [], FIXED_TIME)
    summary = report["summary"]
    assert summary["dependencies_analyzed"] == 2
    assert summary["distinct_vulnerabilities"] == 2
    assert summary["severity_distribution_advisory_labels"] == {"HIGH": 1, "not available": 1}
    assert report["generated_at"] == FIXED_TIME


def test_failed_lookup_is_marked_not_counted_as_clean():
    report = build_report("req.txt", [REQ, FLASK], [], [], [(FLASK, "boom")], FIXED_TIME)
    flask = next(d for d in report["dependencies"] if d["name"] == "flask")
    assert flask["status"] == "lookup failed"
    assert flask["findings"] is None
    assert report["summary"]["dependencies_lookup_failed"] == 1
    assert len(report["lookup_errors"]) == 1


def test_unsupported_lines_are_listed():
    issue = ParseIssue(5, "django>=3.2", "Unsupported line")
    report = build_report("req.txt", [REQ], [issue], [], [], FIXED_TIME)
    assert report["summary"]["unsupported_lines"] == 1
    assert report["unsupported_lines"][0]["line"] == 5


def test_limitations_and_method_are_always_included():
    report = build_report("req.txt", [], [], [], [], FIXED_TIME)
    assert len(report["limitations"]) > 0
    assert "not CVSS" in report["priority_method"]


def test_findings_are_ranked_highest_first():
    findings = [make(REQ, "LOW1", "LOW"), make(REQ, "HIGH1", "HIGH")]
    report = build_report("req.txt", [REQ], [], findings, [], FIXED_TIME)
    assert [f["key"] for f in report["findings"]] == ["HIGH1", "LOW1"]


def test_json_round_trip(tmp_path):
    report = build_report("req.txt", [REQ], [], [make(REQ, "A", "HIGH")], [], FIXED_TIME)
    path = tmp_path / "out" / "report.json"
    write_json(report, path)
    assert json.loads(path.read_text(encoding="utf-8")) == report


def test_csv_has_one_row_per_finding(tmp_path):
    findings = [make(REQ, "A", "HIGH", ["2.20.0"]), make(REQ, "B")]
    report = build_report("req.txt", [REQ], [], findings, [], FIXED_TIME)
    path = tmp_path / "report.csv"
    write_csv(report, path)
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert len(rows) == 2
    assert rows[0]["finding_key"] == "A"
    assert rows[1]["advisory_severity"] == "not available"


def test_csv_neutralizes_formula_text(tmp_path):
    findings = [make(REQ, "A", summary="=HYPERLINK(\"http://evil\")")]
    report = build_report("req.txt", [REQ], [], findings, [], FIXED_TIME)
    path = tmp_path / "report.csv"
    write_csv(report, path)
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert rows[0]["summary"].startswith("'=")
