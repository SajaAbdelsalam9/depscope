from depscope.models import Dependency, Finding
from depscope.prioritizer import level_for, prioritize, prioritize_all

DEP = Dependency("pkg", "1.0")


def make(key, severity=None, fixed=(), vectors=()):
    return Finding(
        dependency=DEP, key=key, ids=(key,), summary="s",
        advisory_severity=severity, fixed_versions=tuple(fixed), cvss_vectors=tuple(vectors),
    )


def test_high_existing_with_fix_scores_four():
    result = prioritize(make("A", "HIGH", ["2.0"]))
    assert result.score == 4
    assert result.level == "P2"


def test_new_high_with_fix_is_top_priority():
    result = prioritize(make("A", "HIGH", ["2.0"]), is_new=True)
    assert result.score == 6
    assert result.level == "P1"


def test_low_existing_without_fix_is_lowest():
    result = prioritize(make("A", "LOW"))
    assert result.score == 1
    assert result.level == "P4"


def test_missing_severity_is_flagged_not_hidden():
    result = prioritize(make("A"))
    assert result.score == 2
    assert any("not available" in reason for reason in result.reasons)


def test_cvss_vector_alone_does_not_invent_a_rating():
    with_vector = prioritize(make("A", vectors=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]))
    without_vector = prioritize(make("A"))
    assert with_vector.score == without_vector.score


def test_label_is_case_insensitive():
    assert prioritize(make("A", "high")).score == prioritize(make("A", "HIGH")).score


def test_every_point_has_a_reason():
    result = prioritize(make("A", "MODERATE", ["2.0"]), is_new=True)
    assert len(result.reasons) == 3


def test_level_boundaries():
    assert [level_for(s) for s in (0, 2, 3, 4, 5, 7)] == ["P4", "P4", "P3", "P2", "P1", "P1"]


def test_ranking_is_ordered_by_score_then_key():
    findings = [make("B", "LOW"), make("A", "HIGH"), make("C", "HIGH")]
    ranked = prioritize_all(findings)
    assert [p.finding.key for p in ranked] == ["A", "C", "B"]


def test_new_keys_raise_the_score():
    findings = [make("A", "MODERATE"), make("B", "MODERATE")]
    ranked = prioritize_all(findings, new_keys={"B"})
    assert ranked[0].finding.key == "B"
