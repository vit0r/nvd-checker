"""
Tests for the dependency scanner parsers.
"""

import textwrap
from pathlib import Path

import pytest

from nvd_checker.scanner.python_parser import PythonParser
from nvd_checker.scanner.node_parser import NodeParser
from nvd_checker.scanner.go_parser import GoParser
from nvd_checker.scanner.java_parser import JavaParser
from nvd_checker.scanner.ruby_parser import RubyParser
from nvd_checker.scanner.detector import DependencyDetector


@pytest.fixture
def tmp_repo(tmp_path):
    """Create a temporary repository structure."""
    return tmp_path


class TestPythonParser:
    def test_requirements_txt(self, tmp_repo):
        req = tmp_repo / "requirements.txt"
        req.write_text(textwrap.dedent("""\
            requests==2.28.1
            flask>=2.0
            django~=4.2
            # comment line
            -r other.txt
            numpy
            pandas[all]==1.5.0  ; python_version >= "3.8"
        """))

        parser = PythonParser()
        deps = parser.parse(req)

        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "django" in names
        assert "numpy" in names
        assert "pandas" in names

        req_dep = next(d for d in deps if d.name == "requests")
        assert req_dep.version == "2.28.1"
        assert req_dep.ecosystem == "python"

    def test_pipfile(self, tmp_repo):
        pf = tmp_repo / "Pipfile"
        pf.write_text(textwrap.dedent("""\
            [packages]
            requests = "==2.28.1"
            flask = "*"
            django = {version = ">=4.0"}

            [dev-packages]
            pytest = ">=7.0"
        """))

        parser = PythonParser()
        deps = parser.parse(pf)

        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "django" in names
        assert "pytest" in names

    def test_pyproject_toml(self, tmp_repo):
        pp = tmp_repo / "pyproject.toml"
        pp.write_text(textwrap.dedent("""\
            [project]
            dependencies = [
                "click>=8.1",
                "requests>=2.28",
                "rich>=13.0",
            ]
        """))

        parser = PythonParser()
        deps = parser.parse(pp)

        names = [d.name for d in deps]
        assert "click" in names
        assert "requests" in names
        assert "rich" in names


class TestNodeParser:
    def test_package_json(self, tmp_repo):
        pkg = tmp_repo / "package.json"
        pkg.write_text(textwrap.dedent("""\
            {
                "dependencies": {
                    "express": "^4.18.2",
                    "lodash": "4.17.21"
                },
                "devDependencies": {
                    "jest": "~29.7.0"
                }
            }
        """))

        parser = NodeParser()
        deps = parser.parse(pkg)

        names = [d.name for d in deps]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names

        lodash = next(d for d in deps if d.name == "lodash")
        assert lodash.version == "4.17.21"
        assert lodash.ecosystem == "nodejs"


class TestGoParser:
    def test_go_mod(self, tmp_repo):
        gm = tmp_repo / "go.mod"
        gm.write_text(textwrap.dedent("""\
            module github.com/example/project

            go 1.21

            require (
                github.com/gin-gonic/gin v1.9.1
                github.com/stretchr/testify v1.8.4
                golang.org/x/crypto v0.14.0 // indirect
            )
        """))

        parser = GoParser()
        deps = parser.parse(gm)

        names = [d.name for d in deps]
        assert "gin" in names
        assert "testify" in names
        # indirect deps should be skipped
        assert "crypto" not in names


class TestJavaParser:
    def test_pom_xml(self, tmp_repo):
        pom = tmp_repo / "pom.xml"
        pom.write_text(textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <properties>
                    <spring.version>5.3.23</spring.version>
                </properties>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>${spring.version}</version>
                    </dependency>
                    <dependency>
                        <groupId>junit</groupId>
                        <artifactId>junit</artifactId>
                        <version>4.13.2</version>
                    </dependency>
                </dependencies>
            </project>
        """))

        parser = JavaParser()
        deps = parser.parse(pom)

        assert len(deps) == 2
        spring = next(d for d in deps if "spring-core" in d.name)
        assert spring.version == "5.3.23"


class TestRubyParser:
    def test_gemfile(self, tmp_repo):
        gf = tmp_repo / "Gemfile"
        gf.write_text(textwrap.dedent("""\
            source 'https://rubygems.org'
            gem 'rails', '~> 7.0'
            gem 'pg', '>= 1.1'
            gem 'puma'
            # gem 'commented_out'
        """))

        parser = RubyParser()
        deps = parser.parse(gf)

        names = [d.name for d in deps]
        assert "rails" in names
        assert "pg" in names
        assert "puma" in names
        assert "commented_out" not in names


class TestDependencyDetector:
    def test_detect_multiple_ecosystems(self, tmp_repo):
        # Create files for multiple ecosystems
        (tmp_repo / "requirements.txt").write_text("requests==2.28.1\n")
        (tmp_repo / "package.json").write_text(
            '{"dependencies": {"express": "^4.18.2"}}'
        )

        detector = DependencyDetector()
        result = detector.scan(tmp_repo)

        assert result.total_dependencies == 2
        ecosystems = result.ecosystems
        assert "python" in ecosystems
        assert "nodejs" in ecosystems

    def test_empty_repo(self, tmp_repo):
        detector = DependencyDetector()
        result = detector.scan(tmp_repo)
        assert result.total_dependencies == 0
