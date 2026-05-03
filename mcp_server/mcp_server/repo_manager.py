"""
Repository manager — handles cloning Git repositories to temporary
directories and cleaning them up after use.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from urllib.parse import urlparse

logger = logging.getLogger("nvd_checker.mcp")

# Maximum time (seconds) to wait for git clone
CLONE_TIMEOUT = 120


class RepoManager:
    """Manages temporary Git repository clones."""

    @staticmethod
    def is_git_url(target: str) -> bool:
        """Check if the target looks like a Git URL."""
        if target.startswith(("http://", "https://", "git@", "ssh://")):
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        return False

    @staticmethod
    def clone(url: str, timeout: int = CLONE_TIMEOUT) -> Path:
        """Clone a Git repository to a temporary directory.

        Args:
            url: Git repository URL.
            timeout: Maximum seconds to wait for clone.

        Returns:
            Path to the cloned repository.

        Raises:
            RuntimeError: If clone fails.
        """
        tmp_dir = Path(tempfile.mkdtemp(prefix="nvd_mcp_"))
        logger.info(f"Cloning {url} into {tmp_dir}")

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(tmp_dir)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(
                f"Git clone timed out after {timeout}s for: {url}"
            )
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(
                f"Git clone failed for {url}: {e.stderr.strip()}"
            )

        logger.info(f"Successfully cloned {url}")
        return tmp_dir

    @staticmethod
    def cleanup(path: Path) -> None:
        """Remove a cloned repository directory."""
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
            logger.info(f"Cleaned up {path}")

    @classmethod
    @contextmanager
    def temporary_clone(
        cls, url: str, timeout: int = CLONE_TIMEOUT
    ) -> Generator[Path, None, None]:
        """Context manager that clones a repo and cleans up on exit.

        Usage:
            with RepoManager.temporary_clone("https://github.com/...") as repo_path:
                # use repo_path
        """
        repo_path = cls.clone(url, timeout)
        try:
            yield repo_path
        finally:
            cls.cleanup(repo_path)
