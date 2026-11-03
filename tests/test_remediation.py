from depscope import remediation
from depscope.models import Dependency, Finding
from depscope.remediation import Recommendation, recommend, verify


def make_finding(dependency, key, fixed=()):
    return Finding(dependency=dependency, key=key, ids=(key,), summary="s", fixed_versions=tuple(fixed))


def test_target_is_highest_of_nearest_fixes():
    dep = Dependency("requests", "2.19.0")
    findings = [
        make_finding(dep, "A", ["2.20.0"]),
        make_finding(dep, "B", ["2.31.0"]),
        make_finding(dep, "C", ["2.32.4"]),
    ]
    assert recommend(dep, findings).target_version == "2.32.4"


def test_branch_fixes_use_nearest_above_installed_for_each_finding():
    dep = Dependency("flask", "2.0.1")
    findings = [
        make_finding(dep, "A", ["2.3.2", "2.2.5"]),
        make_finding(dep, "B", ["3.1.3"]),
    ]
    assert recommend(dep, findings).target_version == "3.1.3"


def test_no_findings_means_no_recommendation():
    dep = Dependency("flask", "2.0.1")
    assert recommend(dep, []) == Recommendation(dep, None, ())


def test_only_unfixed_finding_gives_no_target_but_is_listed():
    dep = Dependency("pkg", "1.0")
    rec = recommend(dep, [make_finding(dep, "CVE-X")])
    assert rec.target_version is None
    assert rec.unfixed_keys == ("CVE-X",)


def test_mixed_fixed_and_unfixed():
    dep = Dependency("pkg", "1.0")
    findings = [make_finding(dep, "CVE-A", ["1.5"]), make_finding(dep, "CVE-B")]
    rec = recommend(dep, findings)
    assert rec.target_version == "1.5"
    assert rec.unfixed_keys == ("CVE-B",)


def test_findings_of_other_dependencies_are_ignored():
    mine = Dependency("mine", "1.0")
    other = Dependency("other", "1.0")
    rec = recommend(mine, [make_finding(other, "CVE-O", ["9.9"])])
    assert rec.target_version is None


def test_verify_without_target_does_not_query_osv(monkeypatch):
    def fail_if_called(deps):
        raise AssertionError("scan should not be called")

    monkeypatch.setattr(remediation, "scan", fail_if_called)
    dep = Dependency("pkg", "1.0")
    assert verify(Recommendation(dep, None, ())) == ([], [])


def test_verify_checks_the_target_version_not_the_installed_one(monkeypatch):
    seen = []

    def fake_scan(deps):
        seen.extend(deps)
        return [], []

    monkeypatch.setattr(remediation, "scan", fake_scan)
    dep = Dependency("pkg", "1.0")
    verify(Recommendation(dep, "1.5", ()))
    assert seen == [Dependency("pkg", "1.5")]
