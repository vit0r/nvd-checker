"""
Base classes and data structures for dependency parsing.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Dependency:
    """Represents a third-party dependency found in a project."""

    name: str
    version: str | None = None
    version_constraint: str | None = None
    ecosystem: str = "unknown"
    source_file: str = ""

    @property
    def display_name(self) -> str:
        """Human-readable name with version."""
        if self.version:
            return f"{self.name}@{self.version}"
        if self.version_constraint:
            return f"{self.name} ({self.version_constraint})"
        return self.name

    def __hash__(self) -> int:
        return hash((self.name.lower(), self.version, self.ecosystem))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Dependency):
            return NotImplemented
        return (
            self.name.lower() == other.name.lower()
            and self.version == other.version
            and self.ecosystem == other.ecosystem
        )


@dataclass
class ScanResult:
    """Result of scanning a repository for dependencies."""

    repo_path: str
    dependencies: list[Dependency] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_dependencies(self) -> int:
        return len(self.dependencies)

    @property
    def ecosystems(self) -> set[str]:
        return {dep.ecosystem for dep in self.dependencies}


class DependencyParser(abc.ABC):
    """Abstract base class for dependency file parsers."""

    @property
    @abc.abstractmethod
    def ecosystem(self) -> str:
        """The ecosystem this parser handles (e.g., 'python', 'nodejs')."""
        ...

    @property
    @abc.abstractmethod
    def supported_files(self) -> list[str]:
        """List of filename patterns this parser can handle."""
        ...

    @abc.abstractmethod
    def parse(self, filepath: Path) -> list[Dependency]:
        """Parse a dependency file and return list of dependencies.

        Args:
            filepath: Path to the dependency file.

        Returns:
            List of Dependency objects found in the file.
        """
        ...

    def can_parse(self, filepath: Path) -> bool:
        """Check if this parser can handle the given file."""
        return filepath.name in self.supported_files
