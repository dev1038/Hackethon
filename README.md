# DLP Demo — AI-Powered Data Loss Prevention

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
7. [Further Improvements — SSL/TLS Inspection](#further-improvements--ssltls-inspection)

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
│  Webhook  — Node.js / Express  (Docker, localhost:8080)          │
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
| Webhook (interceptor) | **8080** | 8080 | Node.js / Express |
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
| `dlp-demo-webhook-1` | `localhost:8080` |

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

The destination URL field auto-fills to `http://<hostname>:8080/upload`.  
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

## Further Improvements — SSL/TLS Inspection

The current demo intercepts plain HTTP traffic at the application layer.  
A production-grade DLP system needs to inspect **encrypted HTTPS** traffic as well.  
Below is the roadmap for adding full TLS interception.

### How TLS Inspection Works

```
Client ──TLS──► mitmproxy (MITM CA) ──TLS──► Destination Server
                     │
                     ▼  (decrypted copy)
              DLP Inspection Engine
```

1. A **MITM proxy** (e.g. mitmproxy, Squid with SSL-Bump, or a custom eBPF hook) terminates the client's TLS session using a locally-trusted CA certificate.
2. It re-encrypts the traffic toward the real destination with a fresh certificate.
3. The decrypted payload is forwarded to the DLP engine for inspection — exactly as in the current HTTP demo.
4. The client must **trust the MITM CA** (deployed via MDM, Group Policy, or browser config).

### Implementation Steps

#### Step 1 — Generate a local CA

```bash
# Generate CA key and self-signed cert (valid 10 years)
openssl req -x509 -newkey rsa:4096 -keyout dlp-ca.key \
  -out dlp-ca.crt -days 3650 -nodes \
  -subj "/CN=DLP Inspection CA/O=Demo/C=US"
```

#### Step 2 — Add mitmproxy to docker-compose.yml

```yaml
mitmproxy:
  image: mitmproxy/mitmproxy
  command: >
    mitmweb --mode upstream:http://webhook:8080
            --ssl-insecure
            --cert /certs/dlp-ca.pem
            --web-host 0.0.0.0
  ports:
    - "8081:8080"   # HTTPS intercept proxy
    - "8082:8081"   # mitmweb admin UI
  volumes:
    - ./certs:/certs
```

#### Step 3 — Trust the CA in the browser / OS

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain dlp-ca.crt
```

**Linux / Debian:**
```bash
sudo cp dlp-ca.crt /usr/local/share/ca-certificates/dlp-ca.crt
sudo update-ca-certificates
```

**Browser proxy setting:**  
Set HTTP/HTTPS proxy to `localhost:8081` and import `dlp-ca.crt` into the browser's trusted certificate store.

#### Step 4 — Enable TLS between webhook and backend (mTLS)

For internal service-to-service encryption inside Docker, add TLS to the Flask backend:

```python
# main.py — enable TLS
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000,
            ssl_context=("certs/server.crt", "certs/server.key"))
```

And update the webhook to use `https://backend:5000/inspect`.

#### Step 5 — Certificate pinning bypass for native apps

For mobile or desktop apps that use certificate pinning, consider:
- **Android:** Frida / Objection to hook `TrustManager`
- **iOS:** SSL Kill Switch 2 (jailbreak) or Network Link Conditioner proxy
- **Electron apps:** `--ignore-certificate-errors` flag in dev mode

### Summary of Planned Improvements

| Feature | Status | Notes |
|---------|--------|-------|
| HTTP interception | ✅ Done | Node.js webhook on port 8080 |
| File-type detection from magic bytes | ✅ Done | PDF, PNG, JPEG, TXT |
| HTTPS/TLS interception | 🔲 Planned | mitmproxy + local CA |
| mTLS between internal services | 🔲 Planned | Flask ssl_context |
| Browser extension interceptor | 🔲 Planned | `dlp-demo/interception/browser-extension/` |
| Policy engine (allow/block rules) | 🔲 Planned | `dlp-demo/policies/` |
| Grafana metrics dashboard | 🔲 Planned | `dlp-demo/dashboard/grafana/` |

---

*Built at Hackathon — March 2026*

