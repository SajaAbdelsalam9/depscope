import pytest

from depscope.models import Dependency
from depscope.parser import parse_line


@pytest.mark.parametrize(
    "line",
    [
        "flask[async]==3.0.0",
        'requests==2.0; python_version > "3"',
        "requests===2.0",
        "requests==2.19.0 \\",
    ],
)
def test_extras_markers_and_options_are_unsupported(line):
    with pytest.raises(ValueError):
        parse_line(line)


@pytest.mark.parametrize(
    "line,name,version",
    [
        ("Flask_Login==0.6.3", "Flask_Login", "0.6.3"),
        ("pkg==1.0.post1", "pkg", "1.0.post1"),
        ("pkg==1!2.0", "pkg", "1!2.0"),
        ("pkg==1.0+cpu", "pkg", "1.0+cpu"),
    ],
)
def test_valid_pins_still_parse(line, name, version):
    assert parse_line(line) == Dependency(name, version)
