"""
FastMCP Server — registers nvd-checker tools and exposes them
via Streamable HTTP transport for remote MCP clients.

Run locally:
    uvicorn mcp_server.server:app --host 0.0.0.0 --port 8000

Or directly:
    python -m mcp_server.server
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP

from mcp_server.tools import (
    check_dependency,
    list_supported_ecosystems,
    scan_repository,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("nvd_checker.mcp")

# ── Initialize FastMCP server ─────────────────────────────────

mcp = FastMCP(
    "NVD Checker",
    instructions=(
        "MCP server for scanning Git repositories and local projects "
        "for vulnerable third-party dependencies using the NVD "
        "(National Vulnerability Database). Provides tools to scan "
        "repositories, check specific packages, and list supported "
        "ecosystems."
    ),
)

# ── Register tools ────────────────────────────────────────────

mcp.tool()(scan_repository)
mcp.tool()(check_dependency)
mcp.tool()(list_supported_ecosystems)

# ── ASGI application for Uvicorn / Kubernetes ─────────────────

app = mcp.http_app()


def main() -> None:
    """Run the MCP server directly (development mode)."""
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
