#!/bin/sh
set -e

CERT_DIR=/certs

if [ ! -f "$CERT_DIR/server.crt" ]; then
    echo "[SudoTrace] Generating self-signed TLS certificate..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -subj "/CN=localhost/O=SudoTrace" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$CERT_DIR/server.key"
    echo "[SudoTrace] Certificate generated — valid for 10 years."
else
    echo "[SudoTrace] Using existing TLS certificate."
fi
