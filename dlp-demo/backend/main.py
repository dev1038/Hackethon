from flask import Flask, request, jsonify
import base64
import io
import os
import re
import json
import subprocess
import tempfile
import pypdf

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Text extraction  (local mode — plain decode or pypdf)
# ---------------------------------------------------------------------------

def extract_text(content_type, raw_bytes):
    if content_type == "application/pdf":
        try:
            reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
            return "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception as e:
            return f"[PDF extraction error: {e}]"
    return raw_bytes.decode(errors="ignore")

# ---------------------------------------------------------------------------
# Local regex-based detector
# ---------------------------------------------------------------------------

def simple_detector(text):
    findings = []
    if re.search(r"\b\d{3}-\d{2}-\d{4}\b", text):
        findings.append("SSN")
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text):
        findings.append("EMAIL")
    if re.search(r"(AKIA|AIza)[A-Za-z0-9]{8,}", text):
        findings.append("API_KEY")
    return findings

# ---------------------------------------------------------------------------
# Octopii PII detector  (runs as a subprocess via octopii_runner.py)
# ---------------------------------------------------------------------------

def _ext_for_content_type(content_type):
    if content_type == "application/pdf":
        return ".pdf"
    if content_type and content_type.startswith("image/"):
        sub = content_type.split("/")[1].split(";")[0].lower()
        return ".jpg" if sub in ("jpeg", "jpg") else f".{sub}"
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

# ── Medium-risk keyword detector (suspicious but not confirmed PII) ─────────
MEDIUM_KEYWORDS = re.compile(
    r'\b(password|passwd|secret|token|credential|private[_\s]?key|'
    r'access[_\s]?key|bearer|confidential|sensitive|auth)\b',
    re.IGNORECASE
)

def medium_detector(text):
    return bool(MEDIUM_KEYWORDS.search(text))

def _octopii_risk_level(result):
    """Return 'medium' if weak signals present in an ALLOW result, else 'low'."""
    score     = result.get("score") or 0
    addresses = result.get("addresses") or []
    faces     = result.get("faces") or 0
    if score > 0 or addresses or faces:
        return "medium"
    return "low"

# ---------------------------------------------------------------------------
# Inspect endpoint
# ---------------------------------------------------------------------------

@app.post("/inspect")
def inspect():
    data         = request.json
    content_type = data.get("content_type", "text/plain")
    dlp_mode     = data.get("dlp_mode", "local")   # "local" | "octopii"
    body         = base64.b64decode(data.get("body_base64", ""))

    try:
        if dlp_mode == "octopii":
            result = octopii_inspect(content_type, body)
            if "error" in result:
                return jsonify({"action": "ERROR", "error": result["error"],
                                "dlp_mode": dlp_mode, "risk_level": "medium"}), 500
            if _octopii_has_pii(result):
                return jsonify({"action": "BLOCK",
                                "detected": _octopii_findings(result),
                                "dlp_mode": dlp_mode,
                                "risk_level": "high",
                                "octopii_detail": result})
            return jsonify({"action": "ALLOW", "detected": [],
                            "dlp_mode": dlp_mode,
                            "risk_level": _octopii_risk_level(result),
                            "octopii_detail": result})
        else:
            text     = extract_text(content_type, body)
            findings = simple_detector(text)
            if findings:
                return jsonify({"action": "BLOCK", "detected": findings,
                                "dlp_mode": dlp_mode, "risk_level": "high"})
            risk = "medium" if medium_detector(text) else "low"
            return jsonify({"action": "ALLOW", "detected": [],
                            "dlp_mode": dlp_mode, "risk_level": risk})
    except Exception as e:
        return jsonify({"action": "ERROR", "error": str(e),
                        "dlp_mode": dlp_mode, "risk_level": "medium"}), 500


@app.get("/")
def home():
    return "DLP Backend Running!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
