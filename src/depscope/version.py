from collections.abc import Iterable

from packaging.version import InvalidVersion, Version


def parse_version(text: str) -> Version | None:
    """Parse a version string, or return None if it is not a valid version."""
    try:
        return Version(text)
    except InvalidVersion:
        return None


def sort_versions(versions: Iterable[str]) -> tuple[str, ...]:
    """Sort version strings numerically. Unparseable ones go last, in text order."""
    valid = []
    invalid = []
    for text in versions:
        parsed = parse_version(text)
        if parsed is None:
            invalid.append(text)
        else:
            valid.append((parsed, text))
    return tuple(text for _, text in sorted(valid)) + tuple(sorted(invalid))


def lowest_fix_above(installed: str, fixed_versions: Iterable[str]) -> str | None:
    """Return the lowest fixed version that is newer than the installed one.

    Returns None if the installed version cannot be parsed, or if no known
    fixed version is newer than it.
    """
    current = parse_version(installed)
    if current is None:
        return None

    candidates = []
    for text in fixed_versions:
        parsed = parse_version(text)
        if parsed is not None and parsed > current:
            candidates.append((parsed, text))

    if not candidates:
        return None
    return min(candidates)[1]
