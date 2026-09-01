#!/usr/bin/env python3
"""Fixture generator for the OCR->DLP probe behind PR 4 of the media delivery plan.

Renders a terminal-style screenshot containing FAKE secrets (the canonical AWS
documentation example key, and obviously-fake tokens), so the pipeline can be
exercised without any real credential ever existing.

    python3 ocr_fixture.py            # writes shot.png
    swiftc -O ocr_probe.swift -o ocr  # macOS Vision OCR
    ./ocr shot.png                    # feed this text to the DlpEngine

See `docs/design/001-image-dlp-provenance.md`, section "OCR -> DLP mesure".
"""
# Render a terminal-ish screenshot containing plausible secrets, no deps beyond PIL if present.
try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("NOPIL"); raise SystemExit(0)

lines = [
    "$ cat .env",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    # Canonical AWS *documentation* example credentials, not real.
    "AWS_SECRET_ACCESS_KEY=" + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY",
    "GITHUB_TOKEN=" + "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890",
    "DATABASE_URL=postgres://admin:hunter2@10.0.0.4:5432/prod",
    # Assembled at runtime so the file itself contains no secret-shaped literal
    # (gitleaks flags the joined form, which is exactly the point of the fixture).
    "STRIPE_KEY=" + "sk_" + "live_" + "51H8xYzABCDEFGHIJKLMNOPqr",
    "",
    "$ # contact: jean.dupont@acme-corp.fr  +33 6 12 34 56 78",
]
W, H = 900, 30 * len(lines) + 40
img = Image.new("RGB", (W, H), (24, 24, 28))
d = ImageDraw.Draw(img)
font = None
for p in ["/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Monaco.ttf",
          "/System/Library/Fonts/Supplemental/Courier New.ttf"]:
    try:
        font = ImageFont.truetype(p, 20); break
    except Exception:
        pass
if font is None:
    font = ImageFont.load_default()
for i, ln in enumerate(lines):
    d.text((20, 20 + i * 30), ln, font=font, fill=(220, 220, 210))
img.save("shot.png")
print("OK", W, H)
