"""
Node.js dependency parser — handles package.json.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from nvd_checker.scanner.base import Dependency, DependencyParser
from nvd_checker.utils import strip_version_constraint

logger = logging.getLogger("nvd_checker")


class NodeParser(DependencyParser):
    """Parses Node.js package.json files."""

    @property
    def ecosystem(self) -> str:
        return "nodejs"

    @property
    def supported_files(self) -> list[str]:
        return ["package.json"]

    def parse(self, filepath: Path) -> list[Dependency]:
        """Parse package.json dependencies and devDependencies."""
        deps: list[Dependency] = []

        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Error parsing {filepath}: {e}")
            return deps

        # Parse both dependencies and devDependencies
        for section in ("dependencies", "devDependencies"):
            section_deps = data.get(section, {})
            if not isinstance(section_deps, dict):
                continue

            for name, version_spec in section_deps.items():
                if not isinstance(version_spec, str):
                    continue

                # Skip workspace references, git URLs, file paths
                if version_spec.startswith(("workspace:", "git", "file:", "http")):
                    continue

                version = strip_version_constraint(version_spec)

                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_constraint=version_spec,
                        ecosystem=self.ecosystem,
                        source_file=str(filepath),
                    )
                )

        return deps
