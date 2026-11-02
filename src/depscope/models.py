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
