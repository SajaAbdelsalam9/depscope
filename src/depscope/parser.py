import re

from depscope.models import Dependency, ParseIssue

NAME_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._+!-]*[A-Za-z0-9])?$")


def parse_line(line: str) -> Dependency | None:
    """Parse one line of a requirements.txt file.

    Returns a Dependency for a pinned line like 'requests==2.19.0'.
    Returns None for blank lines and comments.
    Raises ValueError for lines we cannot support.
    """
    cleaned = line.split("#")[0].strip()

    if not cleaned:
        return None

    if "==" not in cleaned:
        raise ValueError(f"Unsupported line (not an exact == pin): {line.strip()}")

    parts = cleaned.split("==")
    if len(parts) != 2:
        raise ValueError(f"Malformed line: {line.strip()}")

    name = parts[0].strip()
    version = parts[1].strip()

    if not name or not version:
        raise ValueError(f"Missing package name or version: {line.strip()}")

    if not NAME_PATTERN.fullmatch(name) or not VERSION_PATTERN.fullmatch(version):
        raise ValueError(
            "Unsupported name or version (extras, environment markers and options "
            f"are not supported): {line.strip()}"
        )

    return Dependency(name=name, version=version)


def parse_file(path: str) -> tuple[list[Dependency], list[ParseIssue]]:
    """Parse a requirements.txt file.

    Returns the dependencies found and a list of lines that could not be used.
    """
    dependencies = []
    issues = []

    with open(path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                dependency = parse_line(line)
            except ValueError as error:
                issues.append(ParseIssue(line_number, line.strip(), str(error)))
                continue

            if dependency is not None:
                dependencies.append(dependency)

    return dependencies, issues
