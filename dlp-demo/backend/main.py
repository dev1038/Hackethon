from flask import Flask, request, jsonify
import base64
import os
import re
import json
import subprocess
import tempfile

import logging
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Octopii PII detector  (runs as a subprocess via octopii_runner.py)
# ---------------------------------------------------------------------------

def _detect_content_type(raw_bytes):
    """Detect MIME type from file magic bytes — ignores client-supplied header."""
    if raw_bytes[:4] == b'%PDF':
        return "application/pdf"
    if raw_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png"
    if raw_bytes[:3] == b'\xff\xd8\xff':
        return "image/jpeg"
    return "text/plain"

def _ext_for_content_type(content_type):
    if content_type == "application/pdf":
        return ".pdf"
    if content_type == "image/png":
        return ".png"
    if content_type in ("image/jpeg", "image/jpg"):
        return ".jpg"
    return ".txt"

def octopii_inspect(content_type, raw_bytes):
    ext = _ext_for_content_type(content_type)
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False, dir="/tmp") as f:
        f.write(raw_bytes)
        tmp_path = f.name
    try:
        proc = subprocess.run(
            ["python3", "/app/octopii_runner.py", tmp_path],
            capture_output=True, text=True, timeout=120
        )
        match = re.search(r'\{[\s\S]*\}', proc.stdout)
        if match:
            return json.loads(match.group())
        return {
            "error": "No output from Octopii",
            "stdout": proc.stdout[:400],
            "stderr": proc.stderr[:400]
        }
    except subprocess.TimeoutExpired:
        return {"error": "Octopii scan timed out (>120 s)"}
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

def _octopii_has_pii(r):
    return bool(r.get("pii_class") or r.get("emails") or
                r.get("phone_numbers") or r.get("identifiers"))

def _octopii_findings(r):
    out = []
    if r.get("pii_class"):
        out.append(r["pii_class"])
    for e in (r.get("emails") or []):
        out.append(f"EMAIL: {e}")
    if r.get("phone_numbers"):
        out.append(f"PHONE ({len(r['phone_numbers'])} found)")
    identifiers = r.get("identifiers")
    if identifiers:
        # Octopii may return identifiers as a string (e.g. an ID number)
        # or as a list of dicts with an "identifier_class" key.
        if isinstance(identifiers, str):
            out.append(f"IDENTIFIER: {identifiers}")
        elif isinstance(identifiers, list):
            for i in identifiers:
                if isinstance(i, dict):
                    out.append(i.get("identifier_class", "IDENTIFIER"))
                else:
                    out.append(str(i))
    return out

def _octopii_risk_level(result):
    score = result.get("score") or 0
    if score > 20:
        return "high"
    if score >= 5:
        return "medium"
    return "low"

# ---------------------------------------------------------------------------
# Inspect endpoint
# ---------------------------------------------------------------------------

@app.post("/inspect")
def inspect():
    data         = request.json
    body         = base64.b64decode(data.get("body_base64", ""))
    content_type = _detect_content_type(body)   # always derived from actual bytes

    try:
        app.logger.info(f"Inspecting content of type {content_type} and size {len(body)} bytes")
        result = octopii_inspect(content_type, body)
        if "error" in result:
            return jsonify({"action": "ERROR", "error": result["error"],
                            "risk_level": "medium"}), 500
        risk = _octopii_risk_level(result)
        if risk != "low" and _octopii_has_pii(result):
            return jsonify({"action": "BLOCK",
                            "detected": _octopii_findings(result),
                            "risk_level": risk,
                            "octopii_detail": result})
        return jsonify({"action": "ALLOW", "detected": [],
                        "risk_level": risk,
                        "octopii_detail": result})
    except Exception as e:
        return jsonify({"action": "ERROR", "error": str(e),
                        "risk_level": "medium"}), 500


@app.get("/")
def home():
    return "DLP Backend Running!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
