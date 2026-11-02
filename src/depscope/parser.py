from depscope.models import Dependency, ParseIssue


def parse_line(line: str) -> Dependency | None:
    """Parse one line of a requirements.txt file.

    Returns a Dependency for a pinned line like 'requests==2.19.0'.
    Returns None for blank lines and comments.
    Raises ValueError for lines we cannot support.
    """
    # Remove any inline comment, then trim spaces and newlines
    cleaned = line.split("#")[0].strip()

    # Nothing left means a blank line or a full-line comment
    if not cleaned:
        return None

    # We only support exact pins like name==version
    if "==" not in cleaned:
        raise ValueError(f"Unsupported line (not an exact == pin): {line.strip()}")

    parts = cleaned.split("==")
    if len(parts) != 2:
        raise ValueError(f"Malformed line: {line.strip()}")

    name = parts[0].strip()
    version = parts[1].strip()

    if not name or not version:
        raise ValueError(f"Missing package name or version: {line.strip()}")

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
