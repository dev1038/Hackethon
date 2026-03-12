const express = require("express");
const https   = require("https");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

// ---------------------------------------------------------------------------
// AES-256-GCM Pre-Shared Key (32 bytes, hex)
// Must match PAYLOAD_KEY_HEX in index.html.
// Rotate this for any non-demo use.
// ---------------------------------------------------------------------------
const PSK = Buffer.from("a1b2c3d4e5f6789012345678aabbccdd1122334455667788aabbccdd11223344", "hex");

// ---------------------------------------------------------------------------
// Decrypt AES-256-GCM payload encrypted by the browser (WebCrypto AES-GCM).
// Layout of encryptedBase64, after base64-decode:
//   bytes  0–11  : IV (12 bytes, random)
//   bytes 12–(n-17): ciphertext
//   bytes (n-16)–end : GCM auth tag (16 bytes, appended by WebCrypto)
// ---------------------------------------------------------------------------
function decryptPayload(encryptedBase64) {
  const buf        = Buffer.from(encryptedBase64, "base64");
  const iv         = buf.subarray(0, 12);
  const authTag    = buf.subarray(buf.length - 16);
  const ciphertext = buf.subarray(12, buf.length - 16);
  const decipher   = crypto.createDecipheriv("aes-256-gcm", PSK, iv);
  decipher.setAuthTag(authTag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString("base64");
}

const app = express();
app.use(express.json({ limit: "20mb" }));

// Allow browser requests from localhost or any private-network origin
app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  const isAllowed =
    /^https?:\/\/localhost(:\d+)?$/.test(origin) ||
    /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(origin) ||
    /^https?:\/\/(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$/.test(origin);
  if (isAllowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------------------------------------------------------------------------
// Public-key endpoint — browser fetches this for cert pinning verification.
// Returns the server's SPKI DER bytes as a binary response.
// ---------------------------------------------------------------------------
app.get("/public-key", (req, res) => {
  try {
    const certPem = fs.readFileSync("/app/certs/server.crt", "utf-8");
    const cert    = new crypto.X509Certificate(certPem);
    // cert.publicKey is already a KeyObject in Node.js 15+; export it directly
    const spkiDer = cert.publicKey.export({ type: "spki", format: "der" });
    res.setHeader("Content-Type", "application/octet-stream");
    res.send(spkiDer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/upload", async (req, res) => {
  try {
    const data = req.body;

    const logData = Object.fromEntries(
      Object.entries(data).map(([k, v]) =>
        [k, k === "body_base64" ? `<encrypted+base64 ${(v || "").length} chars>` : v]
      )
    );
    console.log("upload received:", JSON.stringify(logData, null, 2));

    // Decrypt the application-layer payload before DLP inspection
    let decryptedBase64;
    try {
      decryptedBase64 = decryptPayload(data.body_base64);
      console.log("[DLP] Payload decrypted successfully");
    } catch (decErr) {
      console.error("[DLP] Decryption failed:", decErr.message);
      return res.status(400).json({ error: "Payload decryption failed — wrong key or tampered data" });
    }

    // Forward decrypted bytes to DLP backend for inspection
    const inspectBody = { ...data, body_base64: decryptedBase64 };

    const dlpResponse = await fetch("http://backend:5000/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(inspectBody)
    });

    const decision = await dlpResponse.json();
    console.log(`dlpResponse: ${JSON.stringify(decision)}`);

    if (decision.action === "BLOCK") {
      return res.status(403).json({
        message: "Blocked by DLP policy",
        details: decision
      });
    }

    // Low risk — save decrypted file to /tmp/
    let savedPath = null;
    if (decision.risk_level === "low" && decryptedBase64) {
      const ext      = (data.content_type || "").includes("pdf") ? ".pdf"
                     : (data.content_type || "").includes("png") ? ".png"
                     : (data.content_type || "").startsWith("image/") ? ".jpg"
                     : ".txt";
      const filename = `dlp-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${ext}`;
      savedPath      = path.join("/tmp", filename);
      fs.writeFileSync(savedPath, Buffer.from(decryptedBase64, "base64"));
      console.log(`[DLP] Low-risk file saved: ${savedPath}`);
    }

    return res.json({
      message: "Forwarded (simulated)",
      policyDecision: decision,
      ...(savedPath && { saved_to: savedPath })
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// ---------------------------------------------------------------------------
// Start HTTPS server using local CA-signed certificate
// ---------------------------------------------------------------------------
const PORT = 8443;
try {
  const tlsOptions = {
    key:  fs.readFileSync("/app/certs/server.key"),
    cert: fs.readFileSync("/app/certs/server.crt"),
  };
  https.createServer(tlsOptions, app).listen(PORT, () =>
    console.log(`Webhook running on https://localhost:${PORT}  (TLS enabled)`)
  );
} catch (err) {
  console.error("[TLS] Failed to load certificates:", err.message);
  console.error("      Run: cd dlp-demo/certs && bash generate-certs.sh");
  process.exit(1);
}
