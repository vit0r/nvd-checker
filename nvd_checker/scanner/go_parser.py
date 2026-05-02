"""
Go dependency parser — handles go.mod files.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from nvd_checker.scanner.base import Dependency, DependencyParser

logger = logging.getLogger("nvd_checker")


class GoParser(DependencyParser):
    """Parses Go go.mod files."""

    @property
    def ecosystem(self) -> str:
        return "golang"

    @property
    def supported_files(self) -> list[str]:
        return ["go.mod"]

    def parse(self, filepath: Path) -> list[Dependency]:
        """Parse go.mod require directives."""
        deps: list[Dependency] = []

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.warning(f"Error reading {filepath}: {e}")
            return deps

        in_require_block = False

        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("//"):
                continue

            # Detect require block
            if line.startswith("require ("):
                in_require_block = True
                continue
            if line == ")" and in_require_block:
                in_require_block = False
                continue

            # Single-line require
            single_match = re.match(
                r"^require\s+(\S+)\s+(v[\d.]+\S*)", line
            )
            if single_match:
                module_path = single_match.group(1)
                version = single_match.group(2).lstrip("v")
                name = self._extract_module_name(module_path)
                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_constraint=single_match.group(2),
                        ecosystem=self.ecosystem,
                        source_file=str(filepath),
                    )
                )
                continue

            # Inside require block
            if in_require_block:
                # Skip indirect dependencies
                if "// indirect" in line:
                    continue

                block_match = re.match(r"^(\S+)\s+(v[\d.]+\S*)", line)
                if block_match:
                    module_path = block_match.group(1)
                    version = block_match.group(2).lstrip("v")
                    name = self._extract_module_name(module_path)
                    deps.append(
                        Dependency(
                            name=name,
                            version=version,
                            version_constraint=block_match.group(2),
                            ecosystem=self.ecosystem,
                            source_file=str(filepath),
                        )
                    )

        return deps

    @staticmethod
    def _extract_module_name(module_path: str) -> str:
        """Extract the library name from a Go module path.

        Example: 'github.com/gin-gonic/gin' -> 'gin'
        """
        parts = module_path.rstrip("/").split("/")
        return parts[-1] if parts else module_path
