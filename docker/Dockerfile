# Multi-stage build for minimal image size
FROM python:3.12-slim AS builder

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.12-slim

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create application directory
WORKDIR /app

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY tools/ ./tools/
COPY certificates/ ./certificates/
COPY requirements.txt .

# Create non-root user for running the application
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8443/health', verify=False)" || exit 1

# Expose port
EXPOSE 8443

# Default command
CMD ["python3", "-m", "src.main", "--config", "/app/config/config.docker.yaml"]

# Build instructions:
# docker build -t api-server:latest -f docker/Dockerfile .
#
# Run instructions:
# docker run -d \
#   --name api-server \
#   -p 8443:8443 \
#   -e AD_PASSWORD=your_password \
#   -e JWT_SECRET=your_secret \
#   -v /path/to/config.yaml:/app/config/config.docker.yaml \
#   api-server:latest
