"""
Generate 9 test files (low / medium / high risk) × (txt / pdf / png)
for DLP demo testing.

Scoring logic (mirrors Octopii keywords_classify_pii):
  Low    score  < 5   → ALLOW
  Medium score  5–12  → BLOCK (medium risk)
  High   score  > 12  → BLOCK (high risk)

Score = max count of fuzzy-matched (word, keyword) pairs across all
definition categories.  We target:
  Low  → generic meeting notes, ~0–2 keyword hits
  Med  → SSN / phone keywords repeated to reach score ~7
  High → Payment Card keywords (15 keywords) all present → score ~15
"""

import os
import textwrap
from pathlib import Path

# ── output directory (same folder as this script) ──────────────────────────
OUT = Path(__file__).parent / "test-files"
OUT.mkdir(exist_ok=True)

# ── content blocks ──────────────────────────────────────────────────────────

LOW_CONTENT = """\
Team Standup Notes
Date: March 12, 2026

Attendees: Alice, Bob, Charlie

Topics Discussed:
- Sprint velocity is on track
- Code review backlog reduced by 40 percent
- Deployment scheduled for next Tuesday
- Documentation updates pending

Action Items:
- Alice: finish feature branch by Thursday
- Bob: review pull requests
- Charlie: update release notes

Next meeting: March 19, 2026
"""
# Expected score: 0-3 (no PII category keywords present)

MEDIUM_CONTENT = """\
Employee Record - Confidential

Employee Name: John Smith
Department: Engineering

Social Security Number: 456-78-9012
SSN: 456-78-9012

Phone: +1 555-867-5309
Telephone: 555-123-4567
Contact: john.smith@company.com

Social Security Administration Reference
United States of America  USA
Security Verification Code: 7841
Social Insurance on file

Notes: Please verify SSN before processing payroll.
Social security details must remain confidential.
"""
# SSN keywords: Social(×4), Security(×4), SSN(×2), USA(×1) → SSN score ~11
# Expected score: 7-11 → MEDIUM

HIGH_CONTENT = """\
Payment Card Data - Highly Restricted

Cardholder: Jane Doe
Card Type: Visa Mastercard Debit Credit

Card Number: 4111 1111 1111 1111
Bank: First National Bank
Account: Savings Debit Card

Valid Thru: 12/28
Expires: 12/28
Expiry: December 2028
CVV: 456
ATM PIN: 7890

Additional Cards on File:
- American Express (AMEX) credit card expires 06/27
- Rupay debit card valid thru 09/26
- Visa credit card expiry 03/28
- Mastercard debit bank account

Authorization: Bank approved. CVV verified. ATM withdrawal limit: $500.
Debit credit transactions require valid card. Mastercard Visa accepted.
Rupay AMEX American Express thru valid expires expiry atm bank credit debit.
"""
# Payment Card keywords: visa, mastercard, debit, credit, bank, valid, expires,
# expiry, cvv, atm, american, express, amex, rupay, thru → score ~18+
# Expected score: > 12 → HIGH


# ── 1. TXT files ────────────────────────────────────────────────────────────

def write_txt(name, content):
    p = OUT / name
    p.write_text(content, encoding="utf-8")
    print(f"  Created: {p}")

print("Generating TXT files...")
write_txt("low-risk.txt",    LOW_CONTENT)
write_txt("medium-risk.txt", MEDIUM_CONTENT)
write_txt("high-risk.txt",   HIGH_CONTENT)


# ── 2. PDF files (fpdf) ─────────────────────────────────────────────────────

from fpdf import FPDF

def write_pdf(name, title, content):
    pdf = FPDF()
    pdf.set_margins(20, 20, 20)
    pdf.add_page()
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    pdf.set_font("Helvetica", size=11)
    for line in content.splitlines():
        safe = line.encode("latin-1", errors="replace").decode("latin-1")
        # Use cell for each line to avoid width calculation issues
        pdf.cell(0, 6, safe, new_x="LMARGIN", new_y="NEXT")
    p = OUT / name
    pdf.output(str(p))
    print(f"  Created: {p}")

print("Generating PDF files...")
write_pdf("low-risk.pdf",    "Team Standup Notes",              LOW_CONTENT)
write_pdf("medium-risk.pdf", "Employee Record - Confidential",  MEDIUM_CONTENT)
write_pdf("high-risk.pdf",   "Payment Card Data",               HIGH_CONTENT)


# ── 3. PNG image files (PIL) ─────────────────────────────────────────────────

from PIL import Image, ImageDraw, ImageFont

def write_png(name, content):
    # Create a 900×1100 white image with black text (large enough for OCR)
    img  = Image.new("RGB", (900, 1100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("/Library/Fonts/Arial.ttf", 20)
    except Exception:
        font = ImageFont.load_default()

    x, y = 40, 40
    line_h = 26
    for line in content.splitlines():
        draw.text((x, y), line, fill=(0, 0, 0), font=font)
        y += line_h
        if y > 1060:  # stop before bottom margin
            break

    p = OUT / name
    img.save(str(p), "PNG")
    print(f"  Created: {p}")

print("Generating PNG files...")
write_png("low-risk.png",    LOW_CONTENT)
write_png("medium-risk.png", MEDIUM_CONTENT)
write_png("high-risk.png",   HIGH_CONTENT)

print(f"\nDone! 9 test files written to: {OUT}/")
print("""
Expected risk levels when uploaded to the DLP demo:
  low-risk.*    → ALLOW  (score < 5)
  medium-risk.* → BLOCK  (score 5–12, medium risk)
  high-risk.*   → BLOCK  (score > 12, high risk)
""")
