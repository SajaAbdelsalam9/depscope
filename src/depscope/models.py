from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str = "PyPI"
