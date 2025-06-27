FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

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
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws/

# Install CycloneDX CLI (prebuilt binary)
RUN wget -O /usr/local/bin/cyclonedx "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v0.27.2/cyclonedx-linux-x64" \
    && chmod +x /usr/local/bin/cyclonedx

# Copy the main script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy license mappings
COPY license-mappings.json /license-mappings.json

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]