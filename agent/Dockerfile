# ── NVD Checker AI Agent ──────────────────────────────────────
# Build (from the root directory):
#   docker build -f agent/Dockerfile -t nvd-checker-agent:latest .
#
# Run (Sleeper Mode for Kubernetes exec):
#   docker run -d nvd-checker-agent:latest
#
# Connect:
#   docker exec -it <container_id> nvd-agent

FROM python:3.12-slim AS builder

WORKDIR /build

COPY cli/ cli/
COPY agent/ agent/

RUN pip install --no-cache-dir --prefix=/install -e ./cli -e ./agent

FROM python:3.12-slim

# Create non-root user
RUN groupadd -r agentuser && useradd -r -g agentuser -d /app agentuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source code
COPY cli/ cli/
COPY agent/ agent/

# Install the package itself (editable install needs source)
RUN pip install --no-cache-dir -e ./cli -e ./agent

USER agentuser

# Run in sleeper mode (keeps the container alive so we can `kubectl exec` into it)
CMD ["sleep", "infinity"]
