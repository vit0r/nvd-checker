# ── NVD Checker MCP Server ────────────────────────────────────
# Multi-stage build for a lightweight production image.
#
# Build (from the root directory):
#   docker build -f mcp_server/Dockerfile -t nvd-checker-mcp:latest .
#
# Run:
#   docker run -p 8000:8000 -e NVD_API_KEY=<key> nvd-checker-mcp:latest

# ── Stage 1: Builder ─────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

COPY cli/ cli/
COPY mcp_server/ mcp_server/

RUN pip install --no-cache-dir --prefix=/install -e ./cli -e ./mcp_server

# ── Stage 2: Runtime ─────────────────────────────────────────
FROM python:3.12-slim

# Git is needed for cloning repositories
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r mcpuser && useradd -r -g mcpuser -d /app mcpuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source code
COPY cli/ cli/
COPY mcp_server/ mcp_server/

# Install the package itself (editable install needs source)
RUN pip install --no-cache-dir -e ./cli -e ./mcp_server

# Create temp directory for repo clones
RUN mkdir -p /tmp/nvd_mcp && chown mcpuser:mcpuser /tmp/nvd_mcp

USER mcpuser

EXPOSE 8000

# Health check on the MCP endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/mcp')" || exit 1

CMD ["uvicorn", "mcp_server.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
