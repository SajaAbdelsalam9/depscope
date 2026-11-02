import pytest

from depscope.models import Dependency
from depscope.parser import parse_file, parse_line


def test_parses_pinned_line():
    assert parse_line("requests==2.19.0") == Dependency("requests", "2.19.0")


def test_ignores_inline_comment_and_spaces():
    assert parse_line("  flask==2.0.1  # web") == Dependency("flask", "2.0.1")


@pytest.mark.parametrize("line", ["", "   ", "# a comment"])
def test_blank_and_comment_lines_return_none(line):
    assert parse_line(line) is None


@pytest.mark.parametrize(
    "line", ["django>=3.2", "requests", "requests==", "==1.0", "a==1==2"]
)
def test_unsupported_lines_raise_value_error(line):
    with pytest.raises(ValueError):
        parse_line(line)


def test_parse_file_separates_dependencies_and_issues(tmp_path):
    file = tmp_path / "requirements.txt"
    file.write_text("# comment\nrequests==2.19.0\n\ndjango>=3.2\n")

    dependencies, issues = parse_file(str(file))

    assert dependencies == [Dependency("requests", "2.19.0")]
    assert len(issues) == 1
    assert issues[0].line_number == 4
