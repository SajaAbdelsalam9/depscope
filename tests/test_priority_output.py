from depscope.models import Dependency, Finding
from depscope.prioritizer import print_priorities

DEP = Dependency("pkg", "1.0")


def make(key, severity=None):
    return Finding(dependency=DEP, key=key, ids=(key,), summary="s", advisory_severity=severity)


def test_output_has_disclaimer_and_orders_by_score(capsys):
    print_priorities([make("A-LOW", "LOW"), make("B-HIGH", "HIGH")])
    out = capsys.readouterr().out
    assert "not CVSS" in out
    assert out.index("B-HIGH") < out.index("A-LOW")


def test_new_findings_are_ranked_higher(capsys):
    a = make("AAA", "MODERATE")
    b = make("BBB", "MODERATE")
    print_priorities([a, b], {b})
    out = capsys.readouterr().out
    assert out.index("BBB in") < out.index("AAA in")
    assert "newly introduced" in out


def test_no_findings_prints_nothing(capsys):
    print_priorities([])
    assert capsys.readouterr().out == ""
