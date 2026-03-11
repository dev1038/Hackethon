const express = require("express");

const app = express();
app.use(express.json({ limit: "20mb" }));

// Allow browser requests from any localhost origin
app.use((req, res, next) => {
  const origin = req.headers.origin || "";
  if (/^https?:\/\/localhost(:\d+)?$/.test(origin) || /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)) {
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

    const dlpResponse = await fetch("http://backend:5000/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    });

    const decision = await dlpResponse.json();

    if (decision.action === "BLOCK") {
      return res.status(403).json({
        message: "Blocked by DLP policy",
        details: decision
      });
    }

    return res.json({
      message: "Forwarded (simulated)",
      policyDecision: decision
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.listen(8080, () => console.log("Webhook running on port 8080"));
