# Impact-Scan Dockerfile
# Provides a fully self-contained security scanning environment
# Includes all tools: semgrep, pip-audit, safety, playwright
#
# Build: docker build -t impact-scan:latest .
# Run:   docker run -v $(pwd):/workspace impact-scan scan /workspace

FROM python:3.12-slim

LABEL maintainer="Anirudh <anirudh.ashrith2005@gmail.com>"
LABEL description="AI-powered security vulnerability scanner with all dependencies"
LABEL version="0.2.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 scanner && \
    mkdir -p /workspace /app && \
    chown -R scanner:scanner /workspace /app

# Set working directory
WORKDIR /app

# Copy dependency files first (for better caching)
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Install Impact-Scan and all dependencies
RUN pip install --no-cache-dir -e .[all] && \
    pip install --no-cache-dir semgrep pip-audit safety

# Install Playwright browsers (for web intelligence)
RUN playwright install chromium && \
    playwright install-deps chromium

# Switch to non-root user
USER scanner

# Set default workspace
WORKDIR /workspace

# Health check - ensure semgrep is installed
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import semgrep; print('OK')" || exit 1

# Default command: show help
ENTRYPOINT ["impact-scan"]
CMD ["--help"]

# Usage examples:
# docker run -v $(pwd):/workspace impact-scan scan /workspace
# docker run -v $(pwd):/workspace impact-scan scan /workspace --profile comprehensive
# docker run -v $(pwd):/workspace impact-scan doctor
# docker run -it -v $(pwd):/workspace impact-scan tui
# docker run -p 5000:5000 -v $(pwd):/workspace impact-scan web --port 5000
