const express = require("express");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

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
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.post("/upload", async (req, res) => {
  try {
    const data = req.body;

    const logData = Object.fromEntries(
      Object.entries(data).map(([k, v]) =>
        [k, k === "body_base64" ? `<base64 ${(v || "").length} chars>` : v]
      )
    );
    console.log("upload received:", JSON.stringify(logData, null, 2));

    const dlpResponse = await fetch("http://backend:5000/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });

    const decision = await dlpResponse.json();

    console.log(`dlpResponse: ${JSON.stringify(decision)}`);

    if (decision.action === "BLOCK") {
      return res.status(403).json({
        message: "Blocked by DLP policy",
        details: decision
      });
    }

    // Low risk — save file to /tmp/
    let savedPath = null;
    if (decision.risk_level === "low" && data.body_base64) {
      const ext      = (data.content_type || "").includes("pdf") ? ".pdf"
                     : (data.content_type || "").includes("png") ? ".png"
                     : (data.content_type || "").startsWith("image/") ? ".jpg"
                     : ".txt";
      const filename = `dlp-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${ext}`;
      savedPath      = path.join("/tmp", filename);
      fs.writeFileSync(savedPath, Buffer.from(data.body_base64, "base64"));
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

app.listen(8080, () => console.log("Webhook running on port 8080"));
