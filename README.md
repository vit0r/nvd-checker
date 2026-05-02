# 🛡️ NVD Checker

CLI tool to scan Git repositories for third-party dependencies and check them against the **National Vulnerability Database (NVD)** for known CVEs. Generates detailed reports with explanations and remediation tips.

## Features

- 🔍 **Auto-detection** — Scans repositories for dependency files across multiple ecosystems
- 🌐 **NVD API 2.0** — Queries the official NIST NVD database for CVE data
- 📊 **Rich Reports** — Terminal (Rich), HTML, and JSON output formats
- 💡 **Remediation Tips** — CWE-based fix guidance and urgency classification
- 🔄 **CI/CD Ready** — `--fail-on` flag for pipeline integration

### Supported Ecosystems

| Ecosystem | Files Parsed |
|-----------|-------------|
| Python    | `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.cfg` |
| Node.js   | `package.json` |
| Go        | `go.mod` |
| Java      | `pom.xml` |
| Ruby      | `Gemfile` |

## Installation

```bash
pip install -e .
```

## Usage

### Scan a Repository

```bash
# Scan the current directory
nvd-checker scan

# Scan a specific path with verbose output
nvd-checker scan --path /path/to/repo --verbose

# Use an API key for faster queries
nvd-checker scan --api-key YOUR_KEY
# or
export NVD_API_KEY=YOUR_KEY
nvd-checker scan

# Generate an HTML report
nvd-checker scan --format html --output report.html

# Generate a JSON report
nvd-checker scan --format json --output report.json

# Filter by minimum severity
nvd-checker scan --severity HIGH

# Fail in CI/CD if critical vulnerabilities found
nvd-checker scan --fail-on CRITICAL
```

### Check a Specific Dependency

```bash
nvd-checker check --name requests --version 2.25.0
nvd-checker check --name log4j --version 2.14.1
```

### Generate Report from Previous Scan

```bash
# Generate HTML from a JSON scan
nvd-checker report nvd-report.json --format html --output report.html
```

## API Key

The NVD API allows usage without a key, but with severe rate limits (5 req/30s).
With an API key, the limit increases to 50 req/30s.

Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_scanner.py -v
```

## Inspired By

- [pyndv](https://github.com/vit0r/pyndv) — NVD stream data downloader

## License

MIT
