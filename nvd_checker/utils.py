"""
Utility functions and helpers for nvd-checker.
"""

import logging
import re

from rich.logging import RichHandler


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    return logging.getLogger("nvd_checker")


def normalize_package_name(name: str) -> str:
    """Normalize a package name for consistent comparison.

    Follows PEP 503: lowercase, replace [-_.] with single hyphens.
    """
    return re.sub(r"[-_.]+", "-", name).lower().strip()


def strip_version_constraint(version_str: str) -> str | None:
    """Extract the exact version number from a constraint string.

    Examples:
        '==1.2.3' -> '1.2.3'
        '>=1.0,<2.0' -> '1.0'
        '~=3.4' -> '3.4'
        '^1.2.3' -> '1.2.3'
        '1.2.3' -> '1.2.3'
        '*' -> None
    """
    if not version_str or version_str.strip() in ("*", "latest", ""):
        return None

    # Remove leading constraint operators
    cleaned = re.sub(r"^[~^>=<!]+", "", version_str.strip())
    # Take only the first version if there's a range (e.g., '1.0,<2.0')
    cleaned = cleaned.split(",")[0].strip()
    # Remove any remaining constraint operators
    cleaned = re.sub(r"[>=<!]+.*", "", cleaned).strip()

    return cleaned if cleaned else None


def truncate_text(text: str, max_length: int = 200) -> str:
    """Truncate text to max_length, adding ellipsis if needed."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
