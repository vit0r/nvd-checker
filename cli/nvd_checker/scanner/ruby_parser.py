"""
Ruby dependency parser — handles Gemfile files.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from nvd_checker.scanner.base import Dependency, DependencyParser
from nvd_checker.utils import strip_version_constraint

logger = logging.getLogger("nvd_checker")


class RubyParser(DependencyParser):
    """Parses Ruby Gemfile files."""

    @property
    def ecosystem(self) -> str:
        return "ruby"

    @property
    def supported_files(self) -> list[str]:
        return ["Gemfile"]

    def parse(self, filepath: Path) -> list[Dependency]:
        """Parse Gemfile gem declarations."""
        deps: list[Dependency] = []
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.warning(f"Error reading {filepath}: {e}")
            return deps

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(
                r"""gem\s+['"]([a-zA-Z0-9_-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""",
                line,
            )
            if match:
                name = match.group(1)
                version_spec = match.group(2)
                version = strip_version_constraint(version_spec) if version_spec else None
                deps.append(
                    Dependency(
                        name=name, version=version,
                        version_constraint=version_spec,
                        ecosystem=self.ecosystem,
                        source_file=str(filepath),
                    )
                )
        return deps
