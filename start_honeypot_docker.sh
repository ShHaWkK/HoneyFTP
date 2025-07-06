#!/bin/bash
set -euo pipefail

# Generate TLS certificate if not already present
if [ ! -f server.crt ] || [ ! -f server.key ]; then
  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=HoneyFTP"
fi

# Build and run the Docker container with minimal privileges

docker build -t honeyftp .

docker run -d --rm --name honeyftp \
  --read-only --cap-drop ALL \
  -p 2121:2121 honeyftp
