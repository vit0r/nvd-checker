"""
Python dependency parsers — handles requirements.txt, Pipfile,
pyproject.toml, and setup.cfg.
"""

from __future__ import annotations

import configparser
import logging
import re
from pathlib import Path

from nvd_checker.scanner.base import Dependency, DependencyParser
from nvd_checker.utils import strip_version_constraint

logger = logging.getLogger("nvd_checker")


class PythonParser(DependencyParser):
    """Parses Python dependency files."""

    @property
    def ecosystem(self) -> str:
        return "python"

    @property
    def supported_files(self) -> list[str]:
        return ["requirements.txt", "Pipfile", "pyproject.toml", "setup.cfg"]

    def parse(self, filepath: Path) -> list[Dependency]:
        """Route to the appropriate parser based on filename."""
        parsers = {
            "requirements.txt": self._parse_requirements,
            "Pipfile": self._parse_pipfile,
            "pyproject.toml": self._parse_pyproject,
            "setup.cfg": self._parse_setup_cfg,
        }

        parser_fn = parsers.get(filepath.name)
        if not parser_fn:
            return []

        try:
            return parser_fn(filepath)
        except Exception as e:
            logger.warning(f"Error parsing {filepath}: {e}")
            return []

    def can_parse(self, filepath: Path) -> bool:
        """Also accept requirements files with variants like requirements-dev.txt."""
        if filepath.name in self.supported_files:
            return True
        return bool(re.match(r"requirements.*\.txt$", filepath.name))

    def _parse_requirements(self, filepath: Path) -> list[Dependency]:
        """Parse requirements.txt format.

        Handles: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg[extra]==1.0
        Ignores: comments (#), empty lines, -r/-c flags, URLs
        """
        deps: list[Dependency] = []
        content = filepath.read_text(encoding="utf-8", errors="ignore")

        for line in content.splitlines():
            line = line.strip()
            # Skip comments, empty lines, flags, and URLs
            if not line or line.startswith("#") or line.startswith("-") or "://" in line:
                continue

            # Remove inline comments
            line = line.split("#")[0].strip()
            # Remove environment markers (e.g., ; python_version >= "3.8")
            line = line.split(";")[0].strip()

            if not line:
                continue

            # Parse: package[extras]>=version,<version
            match = re.match(
                r"^([a-zA-Z0-9_][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(.*)?$", line
            )
            if match:
                name = match.group(1).strip()
                version_spec = (match.group(2) or "").strip()

                version = None
                constraint = version_spec if version_spec else None

                # Extract exact version if pinned (==)
                exact_match = re.search(r"==\s*([^\s,;]+)", version_spec)
                if exact_match:
                    version = exact_match.group(1)
                else:
                    version = strip_version_constraint(version_spec)

                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_constraint=constraint,
                        ecosystem=self.ecosystem,
                        source_file=str(filepath),
                    )
                )

        return deps

    def _parse_pipfile(self, filepath: Path) -> list[Dependency]:
        """Parse Pipfile (TOML-like format).

        Handles the [packages] and [dev-packages] sections.
        """
        deps: list[Dependency] = []
        content = filepath.read_text(encoding="utf-8", errors="ignore")

        # Simple TOML-like parsing for Pipfile
        current_section = None
        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            # Section header
            section_match = re.match(r"^\[(.+)\]$", line)
            if section_match:
                current_section = section_match.group(1).strip()
                continue

            if current_section not in ("packages", "dev-packages"):
                continue

            # Parse key = value
            kv_match = re.match(r'^(["\']?)([a-zA-Z0-9._-]+)\1\s*=\s*(.+)$', line)
            if kv_match:
                name = kv_match.group(2)
                value = kv_match.group(3).strip().strip("\"'")

                version = None
                constraint = None

                if value == "*":
                    pass
                elif value.startswith("{"):
                    # Dict format: {version = ">=1.0"}
                    ver_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                    if ver_match:
                        constraint = ver_match.group(1)
                        version = strip_version_constraint(constraint)
                else:
                    constraint = value
                    version = strip_version_constraint(value)

                deps.append(
                    Dependency(
                        name=name,
                        version=version,
                        version_constraint=constraint,
                        ecosystem=self.ecosystem,
                        source_file=str(filepath),
                    )
                )

        return deps

    def _parse_pyproject(self, filepath: Path) -> list[Dependency]:
        """Parse pyproject.toml for dependencies.

        Handles [project.dependencies] and [tool.poetry.dependencies].
        Uses basic TOML parsing to avoid requiring tomllib on older Python.
        """
        deps: list[Dependency] = []
        content = filepath.read_text(encoding="utf-8", errors="ignore")

        # Try to use tomllib (Python 3.11+) or tomli
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                # Fall back to regex parsing
                return self._parse_pyproject_regex(content, filepath)

        try:
            data = tomllib.loads(content)
        except Exception:
            return self._parse_pyproject_regex(content, filepath)

        # PEP 621: [project.dependencies]
        for dep_str in data.get("project", {}).get("dependencies", []):
            dep = self._parse_pep508_dep(dep_str, filepath)
            if dep:
                deps.append(dep)

        # Poetry: [tool.poetry.dependencies]
        poetry_deps = (
            data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        )
        for name, spec in poetry_deps.items():
            if name.lower() == "python":
                continue
            version = None
            constraint = None
            if isinstance(spec, str):
                constraint = spec
                version = strip_version_constraint(spec)
            elif isinstance(spec, dict):
                constraint = spec.get("version", "")
                version = strip_version_constraint(constraint)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    version_constraint=constraint,
                    ecosystem=self.ecosystem,
                    source_file=str(filepath),
                )
            )

        return deps

    def _parse_pyproject_regex(
        self, content: str, filepath: Path
    ) -> list[Dependency]:
        """Fallback regex parser for pyproject.toml."""
        deps: list[Dependency] = []

        # Find dependencies array
        dep_block = re.search(
            r"dependencies\s*=\s*\[(.*?)\]", content, re.DOTALL
        )
        if dep_block:
            for dep_str in re.findall(r'"([^"]+)"', dep_block.group(1)):
                dep = self._parse_pep508_dep(dep_str, filepath)
                if dep:
                    deps.append(dep)

        return deps

    def _parse_pep508_dep(
        self, dep_str: str, filepath: Path
    ) -> Dependency | None:
        """Parse a PEP 508 dependency string like 'requests>=2.28'."""
        match = re.match(
            r"^([a-zA-Z0-9_][a-zA-Z0-9._-]*)(?:\[.*?\])?\s*(.*)?$",
            dep_str.strip(),
        )
        if not match:
            return None

        name = match.group(1)
        version_spec = (match.group(2) or "").split(";")[0].strip()
        version = strip_version_constraint(version_spec)

        return Dependency(
            name=name,
            version=version,
            version_constraint=version_spec if version_spec else None,
            ecosystem=self.ecosystem,
            source_file=str(filepath),
        )

    def _parse_setup_cfg(self, filepath: Path) -> list[Dependency]:
        """Parse setup.cfg [options] install_requires."""
        deps: list[Dependency] = []
        config = configparser.ConfigParser()

        try:
            config.read(filepath, encoding="utf-8")
        except Exception as e:
            logger.warning(f"Error reading {filepath}: {e}")
            return deps

        install_requires = config.get("options", "install_requires", fallback="")
        for line in install_requires.splitlines():
            line = line.strip()
            if not line:
                continue
            dep = self._parse_pep508_dep(line, filepath)
            if dep:
                deps.append(dep)

        return deps
