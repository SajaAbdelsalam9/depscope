import json

from depscope.comparator import compare
from depscope.models import Dependency, Finding
from depscope.report import build_compare_report, write_compare_json

REQ_OLD = Dependency("requests", "2.19.0")
REQ_NEW = Dependency("requests", "2.34.2")
JINJA = Dependency("jinja2", "2.10")
FLASK = Dependency("flask", "2.0.1")
FIXED_TIME = "2026-01-01T00:00:00+00:00"


def make(dep, key, severity=None, fixed=()):
    return Finding(
        dependency=dep, key=key, ids=(key,), summary="s",
        advisory_severity=severity, fixed_versions=tuple(fixed),
    )


def sample_result():
    before_findings = [make(REQ_OLD, "OLD", "HIGH", ["2.20.0"]), make(FLASK, "STAY", "LOW")]
    after_findings = [make(JINJA, "NEW", "HIGH", ["2.10.1"]), make(FLASK, "STAY", "LOW")]
    return compare([REQ_OLD, FLASK], before_findings, [REQ_NEW, FLASK, JINJA], after_findings)


def build(errors=()):
    return build_compare_report(
        "before.txt", "after.txt", [], [], [], [], sample_result(), list(errors), FIXED_TIME
    )


def test_summary_counts_and_dependency_lists():
    report = build()
    assert report["summary"] == {
        "dependencies_added": 1,
        "dependencies_removed": 0,
        "dependencies_updated": 1,
        "dependencies_unchanged": 1,
        "new_vulnerabilities": 1,
        "resolved_vulnerabilities": 1,
        "persistent_vulnerabilities": 1,
        "packages_not_compared": 0,
    }
    assert report["dependency_changes"]["updated"] == [
        {"name": "requests", "before": "2.19.0", "after": "2.34.2"}
    ]
    assert report["report_type"] == "comparison"


def test_new_vulnerability_is_ranked_with_new_points_and_reason():
    entry = build()["new_vulnerabilities"][0]
    assert entry["key"] == "NEW"
    assert entry["priority_score"] == 6
    assert entry["priority_level"] == "P1"
    assert entry["reason"] == "dependency is new"
    assert any("newly introduced" in r for r in entry["priority_reasons"])


def test_resolved_vulnerability_has_reason_but_no_priority():
    entry = build()["resolved_vulnerabilities"][0]
    assert entry["key"] == "OLD"
    assert entry["reason"] == "dependency version changed"
    assert "priority_level" not in entry


def test_failed_lookups_are_listed_as_not_compared():
    report = build(errors=[(REQ_NEW, "boom")])
    assert report["summary"]["packages_not_compared"] == 1
    assert report["not_compared"] == [{"package": "requests==2.34.2", "error": "boom"}]
    assert any("excluded from the comparison" in text for text in report["limitations"])


def test_write_compare_json_respects_path(tmp_path):
    args = ("b.txt", "a.txt", [], [], [], [], sample_result(), [])
    write_compare_json(*args, json_path=None)
    assert list(tmp_path.iterdir()) == []

    path = tmp_path / "out" / "compare.json"
    write_compare_json(*args, json_path=str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["report_type"] == "comparison"
    assert data["summary"]["new_vulnerabilities"] == 1
