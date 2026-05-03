#!/usr/bin/env python3
"""
Entry point for running nvd-checker as a module: python -m nvd_checker
"""

from nvd_checker.cli import cli

if __name__ == "__main__":
    cli()
