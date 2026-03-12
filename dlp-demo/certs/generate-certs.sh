#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# DLP Demo — Local CA + TLS certificate generator
# Generates:
#   ca.key / ca.crt       — local Certificate Authority (trust this in OS/browser)
#   server.key / server.crt — TLS cert for the webhook (signed by the CA)
#   spki-hash.txt         — SHA-256 SPKI fingerprint for cert pinning in index.html
# ---------------------------------------------------------------------------
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
INDEX_HTML="$DIR/../dashboard/webui/index.html"

echo "╔══════════════════════════════════════════════════════╗"
echo "║       DLP Demo — TLS Certificate Generator         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 1. Certificate Authority ─────────────────────────────────────────────────
echo "[1/4] Generating local CA..."
openssl genrsa -out "$DIR/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes \
  -key "$DIR/ca.key" \
  -sha256 -days 3650 \
  -subj "/CN=DLP Demo CA/O=DLP Demo/C=US" \
  -out "$DIR/ca.crt" 2>/dev/null

# ── 2. Server key + CSR ───────────────────────────────────────────────────────
echo "[2/4] Generating server key..."
openssl genrsa -out "$DIR/server.key" 2048 2>/dev/null
openssl req -new \
  -key "$DIR/server.key" \
  -subj "/CN=localhost/O=DLP Demo/C=US" \
  -out "$DIR/server.csr" 2>/dev/null

# ── 3. Sign server cert with CA (with SAN) ───────────────────────────────────
echo "[3/4] Signing server certificate with local CA..."
# Write extension file without section headers — compatible with macOS LibreSSL
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
  > "$DIR/server-ext.cnf"

# Create serial file explicitly — avoids macOS LibreSSL dot-in-path bug
# where -CAcreateserial places ca.srl in the wrong directory.
printf '01\n' > "$DIR/ca.srl"

openssl x509 -req \
  -in  "$DIR/server.csr" \
  -CA  "$DIR/ca.crt" \
  -CAkey "$DIR/ca.key" \
  -CAserial "$DIR/ca.srl" \
  -days 825 \
  -sha256 \
  -extfile "$DIR/server-ext.cnf" \
  -out "$DIR/server.crt"

# ── 4. Compute SPKI SHA-256 fingerprint (for cert pinning) ───────────────────
echo "[4/4] Computing SPKI fingerprint for cert pinning..."
SPKI_HASH=$(openssl x509 -in "$DIR/server.crt" -pubkey -noout 2>/dev/null \
  | openssl pkey -pubin -outform DER 2>/dev/null \
  | openssl dgst -sha256 -binary \
  | openssl base64)

echo "$SPKI_HASH" > "$DIR/spki-hash.txt"

# ── Patch index.html with the new SPKI hash ───────────────────────────────────
if [ -f "$INDEX_HTML" ]; then
  sed -i.bak "s|const PINNED_KEY_HASH = \".*\"|const PINNED_KEY_HASH = \"${SPKI_HASH}\"|g" "$INDEX_HTML"
  rm -f "${INDEX_HTML}.bak"
  echo "   ✅ Patched index.html with new SPKI hash"
fi

# ── Cleanup intermediates ─────────────────────────────────────────────────────
rm -f "$DIR/server.csr" "$DIR/server-ext.cnf" "$DIR/ca.srl"

echo ""
echo "══════════════════════════════════════════════════════"
echo "✅ Certificates written to: $DIR/"
echo ""
echo "   ca.crt      → Trust this in your OS/browser"
echo "   server.crt  → Used by the webhook container"
echo "   server.key  → Used by the webhook container"
echo ""
echo "📌 SPKI SHA-256 (cert pin): $SPKI_HASH"
echo ""
echo "══════════════════════════════════════════════════════"
echo "Next steps:"
echo ""
echo "1. Trust the CA on macOS:"
echo "   sudo security add-trusted-cert -d -r trustRoot \\"
echo "     -k /Library/Keychains/System.keychain $DIR/ca.crt"
echo ""
echo "2. Rebuild & start Docker:"
echo "   cd $(dirname "$DIR") && docker compose up --build -d"
echo ""
echo "3. Open: http://localhost:3000  (UI)"
echo "   Uploads go to: https://localhost:8443/upload (encrypted)"
echo "══════════════════════════════════════════════════════"

