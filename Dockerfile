FROM ubuntu:24.04

# Add metadata labels for better container management
LABEL maintainer="ClickHouse Security Team" \
      description="ClickBOM - SBOM Management Tool" \
      version="1.0.0" \
      security.scan="enabled"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Create a non-root user early in the build process
RUN groupadd -r clickbom && useradd -r -g clickbom -s /bin/false clickbom

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    python3 \
    python3-pip \
    unzip \
    wget \
    ca-certificates \
    libicu74 \
    vim-common \
    file \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get autoclean

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws/

# Install CycloneDX CLI (prebuilt binary)
RUN wget -O /usr/local/bin/cyclonedx "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.27.2/cyclonedx-linux-x64" \
    && chmod +x /usr/local/bin/cyclonedx

# Create necessary directories with proper permissions
RUN mkdir -p /app /app/temp && \
    chown -R clickbom:clickbom /app

# Set working directory
WORKDIR /app

# Copy application files with proper ownership
COPY --chown=clickbom:clickbom entrypoint.sh /app/entrypoint.sh
COPY --chown=clickbom:clickbom license-mappings.json /app/license-mappings.json

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER clickbom

# Set secure environment variables
ENV PATH="/usr/local/bin:$PATH" \
    TEMP_DIR="/app/temp" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Use absolute path for entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Add security scanning metadata
LABEL security.trivy.enabled="true" \
      security.dockerfile.hadolint="true"
