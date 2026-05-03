"""
Java dependency parser — handles pom.xml (Maven) files.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from pathlib import Path

from nvd_checker.scanner.base import Dependency, DependencyParser

logger = logging.getLogger("nvd_checker")

# Maven POM namespace
MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


class JavaParser(DependencyParser):
    """Parses Maven pom.xml files."""

    @property
    def ecosystem(self) -> str:
        return "java"

    @property
    def supported_files(self) -> list[str]:
        return ["pom.xml"]

    def parse(self, filepath: Path) -> list[Dependency]:
        """Parse pom.xml <dependency> elements."""
        deps: list[Dependency] = []

        try:
            tree = ET.parse(filepath)  # noqa: S314
            root = tree.getroot()
        except (ET.ParseError, OSError) as e:
            logger.warning(f"Error parsing {filepath}: {e}")
            return deps

        # Detect namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Collect properties for variable resolution
        properties = self._collect_properties(root, ns)

        # Find all <dependency> elements
        for dep_elem in root.iter(f"{ns}dependency"):
            group_id = self._get_text(dep_elem, f"{ns}groupId")
            artifact_id = self._get_text(dep_elem, f"{ns}artifactId")
            version = self._get_text(dep_elem, f"{ns}version")

            if not artifact_id:
                continue

            # Resolve property placeholders like ${project.version}
            if version:
                version = self._resolve_properties(version, properties)

            name = artifact_id
            if group_id:
                name = f"{group_id}:{artifact_id}"

            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    version_constraint=version,
                    ecosystem=self.ecosystem,
                    source_file=str(filepath),
                )
            )

        return deps

    @staticmethod
    def _get_text(element: ET.Element, tag: str) -> str | None:
        """Get text content of a child element."""
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()
        return None

    @staticmethod
    def _collect_properties(root: ET.Element, ns: str) -> dict[str, str]:
        """Collect Maven properties for variable substitution."""
        properties: dict[str, str] = {}
        props_elem = root.find(f"{ns}properties")
        if props_elem is not None:
            for prop in props_elem:
                tag = prop.tag.replace(ns, "")
                if prop.text:
                    properties[tag] = prop.text.strip()
        return properties

    @staticmethod
    def _resolve_properties(value: str, properties: dict[str, str]) -> str:
        """Resolve Maven property placeholders like ${property.name}."""
        import re

        def replacer(match: re.Match) -> str:
            prop_name = match.group(1)
            return properties.get(prop_name, match.group(0))

        return re.sub(r"\$\{(.+?)\}", replacer, value)
