from depscope.version import lowest_fix_above, sort_versions


def test_versions_sort_numerically_not_as_text():
    assert sort_versions(["2.10", "2.9", "2.2.5"]) == ("2.2.5", "2.9", "2.10")


def test_flask_picks_nearest_fix_above_installed():
    assert lowest_fix_above("2.0.1", ("3.1.3", "2.3.2", "2.2.5")) == "2.2.5"


def test_fix_on_older_branch_is_skipped_when_already_past_it():
    assert lowest_fix_above("1.26.20", ("1.26.17", "2.0.6")) == "2.0.6"
    assert lowest_fix_above("1.24.1", ("1.26.17", "2.0.6")) == "1.26.17"


def test_installed_equal_to_fix_has_nothing_to_upgrade_to():
    assert lowest_fix_above("2.2.5", ("2.2.5",)) is None


def test_installed_newer_than_all_fixes_returns_none():
    assert lowest_fix_above("9.0", ("2.0", "3.0")) is None


def test_unparseable_installed_version_returns_none():
    assert lowest_fix_above("not-a-version", ("1.0",)) is None


def test_unparseable_fixed_version_is_ignored():
    assert lowest_fix_above("1.0", ("abc", "1.1")) == "1.1"
