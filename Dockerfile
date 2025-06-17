FROM ubuntu:22.04

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
    openjdk-11-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws/

# Install CycloneDX CLI (Java-based tool for conversion)
RUN wget -O /usr/local/bin/cyclonedx-cli.jar https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-cli-0.25.1.jar \
    && echo '#!/bin/bash\njava -jar /usr/local/bin/cyclonedx-cli.jar "$@"' > /usr/local/bin/cyclonedx \
    && chmod +x /usr/local/bin/cyclonedx

# Copy the main script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/entrypoint.sh"]