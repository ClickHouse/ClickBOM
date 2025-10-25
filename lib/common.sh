#!/bin/bash
# Common utilities used across all modules

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# Logging functions
log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${ORANGE}[DEBUG]${NC} $1"
    fi
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    if [[ -n "$temp_dir" && -d "$temp_dir" ]]; then
        log_info "Cleaning up temporary files"
        rm -rf "$temp_dir"
    fi
}
