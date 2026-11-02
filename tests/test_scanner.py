from depscope import scanner
from depscope.models import Dependency
from depscope.osv_client import OSVError


def test_failed_lookup_is_reported_not_treated_as_clean(monkeypatch):
    def fake_query(dependency):
        raise OSVError("simulated outage")

    monkeypatch.setattr(scanner, "query_dependency", fake_query)

    findings, errors = scanner.scan([Dependency("requests", "2.19.0")])

    assert findings == []
    assert len(errors) == 1
    assert "simulated outage" in errors[0][1]


def test_one_failure_does_not_stop_other_dependencies(monkeypatch):
    def fake_query(dependency):
        if dependency.name == "bad":
            raise OSVError("boom")
        return []

    monkeypatch.setattr(scanner, "query_dependency", fake_query)

    findings, errors = scanner.scan([Dependency("bad", "1"), Dependency("good", "1")])

    assert len(errors) == 1
    assert errors[0][0].name == "bad"
