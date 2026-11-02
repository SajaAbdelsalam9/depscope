from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str = "PyPI"


@dataclass(frozen=True)
class ParseIssue:
    line_number: int
    text: str
    reason: str


@dataclass(frozen=True)
class Vulnerability:
    id: str
    summary: str
    aliases: tuple[str, ...] = ()
    cvss_vectors: tuple[str, ...] = ()
    advisory_severity: str | None = None
    fixed_versions: tuple[str, ...] = ()
