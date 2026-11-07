"""
text2pdf - plain text to a small, real PDF. Pure standard library.

Why this exists: exporting a Google Doc to PDF through the Drive API embeds
full font subsets, so a 3 KB document becomes a 60 KB file. That is fine to
download but too large to pass back through a tool call, which makes it
awkward to move a generated PDF anywhere. This produces the same content at
roughly a tenth the size by using the PDF base-14 fonts, which every reader
already has and nobody needs to embed.

  py text2pdf.py input.txt output.pdf ["Title"]

Handles pagination, simple bold headings (a line in ALL CAPS, or one ending
in a colon), and word wrapping. Not a typesetter - it is for reference
documents you want to read, not design.
"""

import sys
import textwrap

PAGE_W, PAGE_H = 612, 792          # US Letter, in points
MARGIN_X, MARGIN_TOP = 62, 62
BODY_SIZE, HEAD_SIZE = 10.5, 12
LEADING = 14.5
WRAP_COLS = 88

# The base-14 fonts use WinAnsi. Map the characters that actually show up in
# documents written by an LLM and would otherwise become garbage.
SUBSTITUTIONS = {
    "—": "",  # em dash
    "–": "",  # en dash
    "‘": "", "’": "",
    "“": "", "”": "",
    "…": "",  # ellipsis
    "•": "",  # bullet
    " ": " ",
}


def _sanitize(s):
    for bad, good in SUBSTITUTIONS.items():
        s = s.replace(bad, good)
    return s


def _esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _is_heading(line):
    stripped = line.strip()
    if not stripped or len(stripped) > 70:
        return False
    letters = [c for c in stripped if c.isalpha()]
    if letters and all(c.isupper() for c in letters):
        return True
    return stripped.endswith(":") and len(stripped.split()) <= 8


def layout(text):
    """Turn raw text into a list of pages, each a list of (size, bold, line)."""
    pages, page, y = [], [], PAGE_H - MARGIN_TOP

    def flush():
        nonlocal page, y
        if page:
            pages.append(page)
        page, y = [], PAGE_H - MARGIN_TOP

    for raw in text.split("\n"):
        raw = _sanitize(raw.rstrip())
        # The Drive export escapes list markers; unescape for readability.
        raw = raw.replace("\\-", "-").replace("\\*", "*")

        if not raw.strip():
            y -= LEADING * 0.55
            continue

        heading = _is_heading(raw)
        size = HEAD_SIZE if heading else BODY_SIZE
        indent = "    " if raw.lstrip().startswith("-") else ""
        wrapped = textwrap.wrap(raw, WRAP_COLS) or [""]

        for i, line in enumerate(wrapped):
            if y < MARGIN_TOP:
                flush()
            page.append((size, heading, (indent if i else "") + line))
            y -= LEADING * (1.25 if heading else 1.0)

    flush()
    return pages


def build(pages, title):
    objects = []           # 1-indexed; objects[i] is object i+1
    font_regular, font_bold = 3, 4
    page_ids = []

    content_ids = []
    for page in pages:
        parts = ["BT"]
        y = PAGE_H - MARGIN_TOP
        for size, bold, line in page:
            font = "F2" if bold else "F1"
            parts.append(f"/{font} {size} Tf")
            parts.append(f"1 0 0 1 {MARGIN_X} {y:.1f} Tm")
            parts.append(f"({_esc(line)}) Tj")
            y -= LEADING * (1.25 if bold else 1.0)
        parts.append("ET")
        stream = "\n".join(parts).encode("cp1252", "replace")
        content_ids.append(stream)

    # Object layout: 1 catalog, 2 pages, 3 font, 4 bold font,
    # then per page: page object, content stream.
    n_pages = len(pages)
    first_page_obj = 5
    for i in range(n_pages):
        page_ids.append(first_page_obj + i * 2)

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Count {n_pages} /Kids [{kids}] >>".encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                   b"/Encoding /WinAnsiEncoding >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                   b"/Encoding /WinAnsiEncoding >>")

    for i, stream in enumerate(content_ids):
        contents_obj = first_page_obj + i * 2 + 1
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 {font_regular} 0 R /F2 {font_bold} 0 R >> >> "
            f"/Contents {contents_obj} 0 R >>".encode()
        )
        objects.append(
            f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream"
        )

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"

    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n").encode()
    return bytes(out)


def convert(text, title="Document"):
    return build(layout(text), title)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    text = open(sys.argv[1], encoding="utf-8").read()
    title = sys.argv[3] if len(sys.argv) > 3 else "Document"
    pdf = convert(text, title)
    open(sys.argv[2], "wb").write(pdf)
    print(f"wrote {sys.argv[2]} ({len(pdf):,} bytes, {len(layout(text))} pages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
