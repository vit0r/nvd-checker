"""
Auto-detection of project dependencies by scanning the repository
for known dependency files.
"""

from __future__ import annotations

import logging
from pathlib import Path

from nvd_checker.scanner.base import Dependency, DependencyParser, ScanResult
from nvd_checker.scanner.go_parser import GoParser
from nvd_checker.scanner.java_parser import JavaParser
from nvd_checker.scanner.node_parser import NodeParser
from nvd_checker.scanner.python_parser import PythonParser
from nvd_checker.scanner.ruby_parser import RubyParser

logger = logging.getLogger("nvd_checker")

# Directories to skip during scanning
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".tox", ".eggs", "dist", "build", ".mypy_cache",
    ".pytest_cache", "vendor", ".gradle", "target",
}


class DependencyDetector:
    """Scans a repository directory and detects all third-party dependencies."""

    def __init__(self) -> None:
        self._parsers: list[DependencyParser] = [
            PythonParser(),
            NodeParser(),
            GoParser(),
            JavaParser(),
            RubyParser(),
        ]

    def scan(self, repo_path: str | Path) -> ScanResult:
        """Scan a repository and return all detected dependencies."""
        repo_path = Path(repo_path).resolve()
        result = ScanResult(repo_path=str(repo_path))

        if not repo_path.is_dir():
            result.errors.append(f"Path is not a directory: {repo_path}")
            return result

        logger.info(f"Scanning repository: {repo_path}")

        dep_files = self._find_dependency_files(repo_path)
        seen: set[Dependency] = set()

        for filepath in dep_files:
            result.files_scanned.append(str(filepath))
            for parser in self._parsers:
                if parser.can_parse(filepath):
                    try:
                        deps = parser.parse(filepath)
                        for dep in deps:
                            if dep not in seen:
                                seen.add(dep)
                                result.dependencies.append(dep)
                        logger.info(
                            f"  Found {len(deps)} deps in {filepath.name} "
                            f"({parser.ecosystem})"
                        )
                    except Exception as e:
                        msg = f"Error parsing {filepath}: {e}"
                        logger.warning(msg)
                        result.errors.append(msg)

        logger.info(
            f"Scan complete: {result.total_dependencies} unique dependencies "
            f"from {len(result.files_scanned)} files"
        )
        return result

    def _find_dependency_files(self, repo_path: Path) -> list[Path]:
        """Walk the repository and find all supported dependency files."""
        all_supported = set()
        for parser in self._parsers:
            all_supported.update(parser.supported_files)

        found: list[Path] = []
        self._walk_dir(repo_path, all_supported, found)
        return sorted(found)

    def _walk_dir(
        self, directory: Path, supported: set[str], found: list[Path]
    ) -> None:
        """Recursively walk directory, skipping known non-source dirs."""
        try:
            for entry in sorted(directory.iterdir()):
                if entry.is_dir():
                    if entry.name not in SKIP_DIRS:
                        self._walk_dir(entry, supported, found)
                elif entry.is_file() and entry.name in supported:
                    found.append(entry)
        except PermissionError:
            logger.warning(f"Permission denied: {directory}")
