# DLP Demo — Data Loss Prevention

A hackathon project that demonstrates an end-to-end **Data Loss Prevention (DLP)** pipeline.  
Files uploaded through a browser UI are intercepted by a Node.js webhook, scanned by a Python/Flask backend powered by [Octopii](https://github.com/redhuntlabs/Octopii) (an open-source PII scanner), and either **blocked** or **allowed** based on a risk score — with low-risk files automatically saved to a download area.

---

## Table of Contents

1. [Introduction](#introduction)
2. [High-Level Architecture](#high-level-architecture)
3. [Port Reference](#port-reference)
4. [Prerequisites](#prerequisites)
5. [Reproducing the Use Case](#reproducing-the-use-case)
6. [Test Files](#test-files)
7. [SSL/TLS Inspection — Implemented](#ssltls-inspection--implemented)

---

## Introduction

Modern organisations need to prevent sensitive data — PII, payment card data, government IDs — from leaving their perimeter undetected.  
This demo simulates that scenario in a local Docker environment:

- A **browser UI** lets you upload a file (PDF, TXT, JPG, PNG) to a simulated destination.
- A **Node.js webhook** intercepts the upload before it reaches the destination and forwards it to the DLP engine.
- A **Flask DLP backend** extracts text from the file (via OCR for images/PDFs), runs Octopii's keyword and regex PII classifiers, and returns a risk score.
- The webhook either **blocks** the request (HTTP 403) or **allows** it, optionally saving low-risk files to `/tmp/`.
- The **dashboard UI** shows every scan result in real time, with risk badges and a "Downloaded Files" panel for allowed low-risk files.

**Risk thresholds (Octopii score):**

| Score | Risk Level | Action |
|-------|-----------|--------|
| < 5   | Low       | ALLOW — file saved to `/tmp/` |
| 5 – 12 | Medium  | BLOCK |
| > 12  | High      | BLOCK |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser  (localhost:3000)                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  DLP Demo UI  (static HTML — python3 -m http.server 3000) │  │
│  │  • File drop zone (PDF / TXT / JPG / PNG)                 │  │
│  │  • Scan Dashboard  (risk badge + score per file)          │  │
│  │  • Downloaded Files panel  (low-risk saves)               │  │
│  └──────────────────────┬────────────────────────────────────┘  │
└─────────────────────────│────────────────────────────────────────┘
                          │  POST /upload  (JSON + base64 body)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  Webhook  — Node.js / Express  (Docker, localhost:8443)          │
│  • Receives file + metadata                                      │
│  • Forwards to DLP backend for inspection                        │
│  • On ALLOW + low-risk: saves file to /tmp/dlp-<timestamp>.*     │
│  • Returns BLOCK (HTTP 403) or ALLOW (HTTP 200) to browser       │
└──────────────────────────┬──────────────────────────────────────┘
                           │  POST /inspect  (internal Docker network)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  DLP Backend  — Python / Flask  (Docker, localhost:5000)         │
│  • Detects file type from magic bytes (PDF / PNG / JPEG / TXT)  │
│  • Writes content to /tmp temp file with correct extension       │
│  • Spawns octopii_runner.py as subprocess                        │
│  │                                                               │
│  │  ┌──────────────────────────────────────────────────────┐    │
│  │  │  octopii_runner.py                                    │    │
│  │  │  • Mocks textract (pure-Python fallback)              │    │
│  │  │  • Loads /opt/octopii (mounted Octopii source)        │    │
│  │  │  • Calls search_pii(file_path) → JSON result          │    │
│  │  └──────────────────────────────────────────────────────┘    │
│  │                                                               │
│  • Computes risk level from score                                │
│  • Returns { action, risk_level, detected, octopii_detail }     │
└──────────────────────────┬──────────────────────────────────────┘
                           │  volume mount
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Octopii  (local source — ./Octopii/ mounted at /opt/octopii)   │
│  • text_utils.py  — keyword scoring, email/phone/ID regex       │
│  • image_utils.py — Tesseract OCR, face detection               │
│  • file_utils.py  — PDF → image via pdf2image                   │
│  • definitions.json — PII category keyword + regex rules        │
└─────────────────────────────────────────────────────────────────┘
```

**Key design decisions:**

- Octopii is mounted as a **volume** (not baked into the image) so local changes take effect without a rebuild.
- File type is detected from **magic bytes** in the backend — never trusts the client-supplied `content_type`.
- The webhook runs on the Docker network so it can resolve `http://backend:5000` by service name.

---

## Port Reference

| Service | Host Port | Container Port | Technology |
|---------|-----------|----------------|------------|
| Web UI (Dashboard) | **3000** | — (static files) | `python3 -m http.server` |
| Webhook (interceptor) | **8443** | 8443 | Node.js / Express (HTTPS) |
| DLP Backend | **5000** | 5000 | Python / Flask |

---

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose v2)
- **Python 3.10+** (only for serving the static UI)
- No other local dependencies — everything else runs inside Docker

---

## Reproducing the Use Case

### 1. Clone / open the workspace

```bash
cd /path/to/Hackethon
```

The workspace layout expected:

```
Hackethon/
├── Octopii/          ← Octopii source (mounted into backend container)
│   ├── octopii.py
│   ├── text_utils.py
│   ├── definitions.json
│   └── ...
└── dlp-demo/
    ├── docker-compose.yml
    ├── backend/          ← Flask DLP API
    ├── interception/
    │   └── webhook/      ← Node.js interceptor
    ├── dashboard/
    │   └── webui/
    │       └── index.html
    └── samples/
        └── generate_test_files.py
sample-files/             ← ready-to-use test files (low / medium / high risk)
```

### 2. Build and start the Docker services

```bash
cd dlp-demo
docker compose up --build -d
```

This starts two containers:

| Container | Exposes |
|-----------|---------|
| `dlp-demo-backend-1` | `localhost:5000` |
| `dlp-demo-webhook-1` | `localhost:8443` (HTTPS) |

Verify both are running:

```bash
docker compose ps
```

### 3. Start the Web UI

In a separate terminal:

```bash
cd dlp-demo/dashboard/webui
python3 -m http.server 3000 --bind 0.0.0.0
```

### 4. Open the dashboard

Navigate to **[http://localhost:3000](http://localhost:3000)** in your browser.

The destination URL field auto-fills to `https://<hostname>:8443/upload`.  
If it does not, enter it manually.

### 5. Upload a file and observe DLP in action

1. Click the **drop zone** or drag a file onto it (`.pdf`, `.txt`, `.jpg`, `.png`).
2. Click **Inspect with DLP**.
3. Observe the result panel:
   - **BLOCKED** (red) — file contained medium or high-risk PII.
   - **ALLOWED** (green) — file is low-risk.
4. The **Scan Dashboard** (right column, top) updates with a risk badge and score for every scan.
5. For allowed low-risk files, the **Downloaded Files** panel (right column, bottom) shows the filename and the path where it was saved inside the webhook container (`/tmp/dlp-<timestamp>-<random>.<ext>`).

### 6. View live container logs

```bash
# All services together
docker compose logs -f

# Backend only (Flask / Octopii output)
docker compose logs -f backend

# Webhook only (Node.js interceptor)
docker compose logs -f webhook
```

### 7. Stopping the demo

```bash
docker compose down
```

---

## Test Files

Pre-generated test files are provided in `sample-files/` (at the workspace root) to cover all three risk tiers across all three file types:

| File | Octopii Score | Risk | Expected Action |
|------|--------------|------|----------------|
| `low-risk.txt` / `.pdf` / `.png` | ~1 | Low | **ALLOW** + saved to `/tmp/` |
| `medium-risk.txt` / `.pdf` / `.png` | ~11 | Medium | **BLOCK** |
| `high-risk.txt` / `.pdf` / `.png` | ~31 | High | **BLOCK** |

To regenerate them:

```bash
cd dlp-demo/samples
python3 generate_test_files.py
# Output is written to dlp-demo/samples/test-files/ — copy files to sample-files/ as needed
```

---

## SSL/TLS Inspection — Implemented

The demo uses **three layers of security** between the browser and the webhook: TLS transport encryption, SPKI certificate pinning, and AES-256-GCM application-layer encryption.

### Traffic Flow

```
Browser (localhost:3000)
  │
  │  1. verifyCertPin()  — fetch /public-key, SHA-256 SPKI hash, compare to pinned value
  │  2. encryptPayload() — AES-256-GCM encrypt with PSK → [IV(12) | ciphertext | authTag(16)]
  │  3. POST /upload     — HTTPS (TLS) carrying the encrypted payload
  │
  ▼
Webhook (localhost:8443 — HTTPS)
  │
  │  TLS terminated with local CA-signed server cert
  │  decryptPayload() — AES-256-GCM decrypt → recovers original base64 file data
  │
  ▼
DLP Backend (localhost:5000)
  POST /inspect — plain HTTP on the internal Docker network
```

---

### Layer 1 — TLS (HTTPS on port 8443)

The Node.js webhook serves HTTPS using a locally-generated server certificate signed by a private CA.

**Certificate generation** (`dlp-demo/certs/generate-certs.sh`):

```bash
cd dlp-demo/certs
bash generate-certs.sh
```

This produces:

| File | Purpose |
|------|---------|
| `ca.key` / `ca.crt` | Local Certificate Authority key + self-signed cert |
| `server.key` / `server.crt` | Server TLS key + cert signed by the local CA |
| `spki-hash.txt` | SHA-256 of the server public key (SPKI) — used for pinning |

The script also automatically patches `PINNED_KEY_HASH` in `index.html` after each run.

**Trust the CA on macOS** (required once, so the browser accepts the cert):

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  dlp-demo/certs/ca.crt
```

**Server startup** (`server.js`):

```js
const httpsServer = https.createServer(
  { key: fs.readFileSync("/app/certs/server.key"),
    cert: fs.readFileSync("/app/certs/server.crt") },
  app
);
httpsServer.listen(8443);
```

---

### Layer 2 — SPKI Certificate Pinning

TLS alone prevents eavesdropping but not all man-in-the-middle attacks (e.g. a rogue CA trusted by the OS).  
Certificate pinning adds a second check: the browser verifies that the server's **public key fingerprint** matches a hardcoded expected value.

**How the SPKI hash is computed:**

```
DER-encode the SubjectPublicKeyInfo structure from the server cert
  → SHA-256 hash
  → base64-encode
  → compare to PINNED_KEY_HASH in index.html
```

**Browser-side** (`index.html` — `verifyCertPin()`):

```js
const PINNED_KEY_HASH = "hEIm24rapPOPCrQ3UJXs2JvjNMkePzBKEJIzh7huzOI=";

async function verifyCertPin(webhookBase) {
  const resp = await fetch(`${webhookBase.replace(/\/upload$/, "")}/public-key`);
  const derBuf = await resp.arrayBuffer();                          // raw SPKI DER bytes
  const hashBuf = await crypto.subtle.digest("SHA-256", derBuf);   // SHA-256
  const b64 = btoa(String.fromCharCode(...new Uint8Array(hashBuf)));
  if (b64 !== PINNED_KEY_HASH) throw new Error("Certificate pin mismatch — possible MITM!");
}
```

**Server-side** (`server.js` — `/public-key` endpoint):

```js
app.get("/public-key", (req, res) => {
  const cert = new crypto.X509Certificate(certPem);
  const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
  res.send(spkiDer);   // returns 294 bytes
});
```

The upload is **blocked** if the hash does not match the pinned value.

---

### Layer 3 — AES-256-GCM Application-Layer Encryption

Even if TLS is somehow stripped (e.g. a transparent proxy that re-signs with a trusted CA), the payload itself is encrypted with a Pre-Shared Key (PSK) known only to the browser and the webhook.

**Key facts:**

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM |
| Key (PSK) | 32-byte hex string hardcoded in `index.html` and `server.js` |
| IV / Nonce | 12 random bytes generated per upload (`crypto.getRandomValues`) |
| Auth Tag | 16 bytes (GCM integrity tag — detects any tampering) |
| Wire format | `base64( IV(12) \| ciphertext \| authTag(16) )` |

**Browser encryption** (`index.html` — `encryptPayload()`):

```js
const PAYLOAD_KEY_HEX = "a1b2c3d4e5f6789012345678aabbccdd1122334455667788aabbccdd11223344";

async function encryptPayload(base64Data) {
  const keyBytes = hexToBytes(PAYLOAD_KEY_HEX);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));           // fresh nonce every upload
  const plaintext = new TextEncoder().encode(base64Data);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  // WebCrypto appends authTag to ciphertext automatically
  const combined = new Uint8Array(12 + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), 12);
  return btoa(String.fromCharCode(...combined));                    // base64 for JSON transport
}
```

**Webhook decryption** (`server.js` — `decryptPayload()`):

```js
const PSK = Buffer.from("a1b2c3d4e5f6789012345678aabbccdd...", "hex");

function decryptPayload(encryptedBase64) {
  const buf      = Buffer.from(encryptedBase64, "base64");
  const iv       = buf.subarray(0, 12);                  // first 12 bytes
  const authTag  = buf.subarray(buf.length - 16);        // last 16 bytes (GCM tag)
  const ciphertext = buf.subarray(12, buf.length - 16);  // everything in between
  const decipher = crypto.createDecipheriv("aes-256-gcm", PSK, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("base64");
}
```

If the auth tag check fails (payload was tampered), `decipher.final()` throws and the request is rejected.

---

### Security Concepts at a Glance

| Term | Role in This Demo |
|------|------------------|
| **TLS / HTTPS** | Encrypts the entire HTTP connection (port 8443); prevents network sniffing |
| **Local CA** | Signs the server cert; client must explicitly trust it |
| **SPKI** | Subject Public Key Info — the public-key portion of the server cert |
| **SPKI Hash** | SHA-256 fingerprint of the server public key; used as the pin |
| **Cert Pinning** | Browser checks the SPKI hash before upload — blocks MITMs using a different cert |
| **AES-256-GCM** | Authenticated symmetric encryption; confidentiality + integrity at application layer |
| **IV / Nonce** | Random 12 bytes per upload; ensures identical files produce different ciphertext |
| **PSK** | Pre-Shared Key (32-byte hex); shared secret between browser and webhook |
| **Auth Tag** | 16-byte GCM integrity tag; any modification of ciphertext causes decryption to fail |

---

### Regenerating Certificates

Regenerate when the cert expires or you rotate keys:

```bash
cd dlp-demo/certs
bash generate-certs.sh
# Re-trust the new CA on macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca.crt
# Rebuild the webhook container
cd .. && docker compose up --build -d
```

The script auto-patches `PINNED_KEY_HASH` in `index.html` — hard-refresh the browser after rebuilding.

---

### Feature Status

| Feature | Status | Notes |
|---------|--------|-------|
| HTTPS interception (TLS) | ✅ Done | Node.js webhook on port 8443 |
| Local CA + cert generation | ✅ Done | `dlp-demo/certs/generate-certs.sh` (macOS LibreSSL compatible) |
| SPKI certificate pinning | ✅ Done | `/public-key` endpoint + `verifyCertPin()` in browser |
| AES-256-GCM payload encryption | ✅ Done | PSK shared between `index.html` and `server.js` |
| File-type detection from magic bytes | ✅ Done | PDF, PNG, JPEG, TXT |
| mTLS between internal services | 🔲 Planned | Flask ssl_context |
| Browser extension interceptor | 🔲 Planned | `dlp-demo/interception/browser-extension/` |
| Policy engine (allow/block rules) | 🔲 Planned | `dlp-demo/policies/` |
| Grafana metrics dashboard | 🔲 Planned | `dlp-demo/dashboard/grafana/` |

---

*Built at Hackathon — March 2026*

