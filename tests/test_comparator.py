from depscope.comparator import compare
from depscope.models import Dependency, Finding


def dep(name, version):
    return Dependency(name, version)


def finding(name, version, key, *ids):
    return Finding(dependency=dep(name, version), key=key, ids=ids or (key,), summary="summary")


def test_dependency_changes_are_classified():
    before = [dep("requests", "2.19.0"), dep("flask", "2.0.1"), dep("old", "1.0")]
    after = [dep("requests", "2.32.4"), dep("Flask", "2.0.1"), dep("new", "3.0")]
    result = compare(before, [], after, [])
    assert [d.name for d in result.added] == ["new"]
    assert [d.name for d in result.removed] == ["old"]
    assert [(u.name, u.before, u.after) for u in result.updated] == [("requests", "2.19.0", "2.32.4")]
    assert [d.name for d in result.unchanged] == ["Flask"]


def test_same_vulnerability_with_different_keys_is_persistent():
    before = [finding("flask", "2.0.1", "CVE-1", "CVE-1", "GHSA-1")]
    after = [finding("flask", "2.0.2", "GHSA-1", "GHSA-1", "PYSEC-1")]
    result = compare([dep("flask", "2.0.1")], before, [dep("flask", "2.0.2")], after)
    assert len(result.persistent_findings) == 1
    assert result.new_findings == ()
    assert result.resolved_findings == ()


def test_upgrade_that_fixes_vulnerability_is_resolved():
    before = [finding("requests", "2.19.0", "CVE-1")]
    result = compare([dep("requests", "2.19.0")], before, [dep("requests", "2.32.4")], [])
    assert len(result.resolved_findings) == 1
    assert result.resolved_findings[0].reason == "dependency version changed"


def test_vulnerability_in_new_dependency_is_new():
    after = [finding("django", "3.0", "CVE-9")]
    result = compare([], [], [dep("django", "3.0")], after)
    assert [c.finding.key for c in result.new_findings] == ["CVE-9"]
    assert result.new_findings[0].reason == "dependency is new"


def test_equal_counts_do_not_hide_changes():
    before = [finding("a", "1", "CVE-1")]
    after = [finding("a", "2", "CVE-2")]
    result = compare([dep("a", "1")], before, [dep("a", "2")], after)
    assert len(before) == len(after)
    assert [c.finding.key for c in result.new_findings] == ["CVE-2"]
    assert [c.finding.key for c in result.resolved_findings] == ["CVE-1"]
    assert result.persistent_findings == ()


def test_new_finding_on_unchanged_version_is_flagged_as_newly_reported():
    deps = [dep("flask", "2.0.1")]
    result = compare(deps, [], deps, [finding("flask", "2.0.1", "CVE-5")])
    assert "not in earlier results" in result.new_findings[0].reason
