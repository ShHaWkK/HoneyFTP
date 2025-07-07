#!/bin/bash
set -euo pipefail

# This script installs dependencies and launches the HoneyFTP honeypot
# inside a restricted Docker container.

if [ "$(id -u)" -ne 0 ]; then
  echo "Ce script doit etre execute avec les privileges root" >&2
  exit 1
fi

# Ensure we're in the script directory
cd "$(dirname "$0")"

# Install Docker and OpenSSL if missing
apt-get update
apt-get install -y --no-install-recommends docker.io openssl

# Ensure the Docker daemon is running
systemctl enable --now docker

# Build and start the honeypot using the existing helper
./start_honeypot_docker.sh

