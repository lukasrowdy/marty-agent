"""
Marty DEALS — proposals, invoices, and quotes as a client-ready PDF.

Adapted from brain-jarvis V7's deals.py pipeline, simplified for how Marty actually runs:
brain-jarvis called out to a separate model to draft the content. Marty doesn't need that —
Claude (Marty) drafts the structured JSON directly as part of its own turn, then hands it to
this script for the mechanical part: numbering, HTML rendering, PDF, and the ledger.

Nothing here sends anything to a client. It renders to local files. Placing the result in
front of a real client (email, upload to a client-facing link) is a separate, explicit step —
same "draft only" boundary as the rest of Marty's business-development tooling.

CLI:
    deals.py create <kind> <path-to-draft.json>
        kind: proposal | invoice | quote
        draft.json shape: {"client": "...", "title": "...", "intro": "...",
                            "items": [{"desc": "...", "qty": 1, "unit_price": 0}],
                            "terms": "...", "validity": "...", "notes": ""}
        Prints a JSON result: {"number", "html_path", "pdf_path", "total"}

    deals.py recent [n]        recent ledger entries, most recent first
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(HERE, "ledger.jsonl")
OUT_DIR = os.path.join(HERE, "output")
BUSINESS_FILE = os.path.join(HERE, "business.json")
KINDS = ("proposal", "invoice", "quote")


def _find_edge_or_chrome():
    for name in ("chrome", "google-chrome", "msedge"):
        p = shutil.which(name)
        if p:
            return p
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ):
        if os.path.exists(p):
            return p
    return None


def _business():
    try:
        with open(BUSINESS_FILE, "r", encoding="utf-8") as f:
            b = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        b = {}
    return {"name": b.get("name") or "the client's company",
            "email": b.get("email") or "", "phone": b.get("phone") or ""}


def _num(v, fb=0):
    try:
        return float(str(v).replace("$", "").replace(",", "").strip() or fb)
    except (TypeError, ValueError):
        m = re.search(r"-?\d[\d.]*", str(v or ""))
        try:
            return float(m.group(0)) if m else float(fb)
        except (TypeError, ValueError):
            return float(fb)


def _money(v):
    try:
        f = float(v)
        return "${:,.2f}".format(f).replace(".00", "") if f else "\u2014"
    except (TypeError, ValueError):
        return _esc(v)


def _esc(s):
    return (str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def _next_number(kind):
    n = 0
    try:
        with open(LEDGER, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    if json.loads(line).get("kind") == kind:
                        n += 1
                except (json.JSONDecodeError, AttributeError):
                    pass
    except FileNotFoundError:
        pass
    return f"{kind[:3].upper()}-{time.strftime('%Y')}-{n + 1:03d}"


def _ledger_add(row):
    with open(LEDGER, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def render_html(kind, number, d):
    b = _business()
    today = time.strftime("%B %d, %Y")
    items = [i for i in (d.get("items") or []) if isinstance(i, dict)][:8]
    for i in items:
        i["qty"] = _num(i.get("qty"), 1) or 1
        i["unit_price"] = _num(i.get("unit_price"), 0)
    total = round(sum(i["qty"] * i["unit_price"] for i in items), 2)
    rows = "".join(
        f"<tr><td>{_esc(i.get('desc'))}</td><td class='n'>{_esc(i.get('qty') or 1)}</td>"
        f"<td class='n'>{_money(i.get('unit_price'))}</td>"
        f"<td class='n'>{_money(i['qty'] * i['unit_price'])}</td></tr>"
        for i in items)
    notes = f"<p class='notes'>{_esc(d.get('notes'))}</p>" if (d.get("notes") or "").strip() else ""
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>{_esc(d.get('title'))}</title>
<style>
  @page {{ size: letter; margin: 0; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #F7F3EA; color: #16130D; font-family: Georgia, 'Times New Roman', serif;
         -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .page {{ padding: 64px 72px; min-height: 100vh; }}
  .eyebrow {{ font-family: -apple-system, Helvetica, sans-serif; font-size: 11px; letter-spacing: .28em;
             text-transform: uppercase; color: #0E6B4F; margin-bottom: 10px; }}
  h1 {{ font-size: 34px; font-weight: normal; font-style: italic; line-height: 1.15; margin-bottom: 6px; }}
  .meta {{ font-family: -apple-system, Helvetica, sans-serif; font-size: 12px; color: #6B6455;
          margin-bottom: 34px; }}
  .meta b {{ color: #16130D; font-weight: 600; }}
  .intro {{ font-size: 15px; line-height: 1.65; max-width: 58ch; margin-bottom: 30px; }}
  table {{ width: 100%; border-collapse: collapse; font-family: -apple-system, Helvetica, sans-serif;
          font-size: 13px; }}
  th {{ text-align: left; font-size: 10.5px; letter-spacing: .18em; text-transform: uppercase;
       color: #6B6455; padding: 0 10px 10px 0; border-bottom: 1.5px solid #16130D; }}
  td {{ padding: 12px 10px 12px 0; border-bottom: 1px solid #D9D2C2; line-height: 1.45; }}
  td.n, th.n {{ text-align: right; white-space: nowrap; }}
  .total td {{ border-bottom: none; padding-top: 18px; font-size: 16px; font-weight: 700; }}
  .total .lbl {{ font-size: 10.5px; letter-spacing: .18em; text-transform: uppercase; color: #0E6B4F; }}
  .terms {{ margin-top: 40px; font-size: 13px; line-height: 1.6; color: #3A3428; max-width: 60ch; }}
  .terms .h {{ font-family: -apple-system, Helvetica, sans-serif; font-size: 10.5px; letter-spacing: .18em;
              text-transform: uppercase; color: #0E6B4F; margin-bottom: 6px; }}
  .notes {{ margin-top: 18px; font-style: italic; font-size: 13.5px; color: #3A3428; }}
  .foot {{ margin-top: 56px; padding-top: 14px; border-top: 1px solid #D9D2C2;
          font-family: -apple-system, Helvetica, sans-serif; font-size: 10.5px; letter-spacing: .14em;
          text-transform: uppercase; color: #6B6455; display: flex; justify-content: space-between; }}
</style></head><body><div class="page">
  <div class="eyebrow">{_esc(b["name"])} &middot; {_esc(kind)}</div>
  <h1>{_esc(d.get('title'))}</h1>
  <div class="meta"><b>{_esc(number)}</b> &middot; Prepared for <b>{_esc(d.get('client'))}</b> &middot; {today}</div>
  <p class="intro">{_esc(d.get('intro'))}</p>
  <table>
    <tr><th>Description</th><th class="n">Qty</th><th class="n">Unit</th><th class="n">Amount</th></tr>
    {rows}
    <tr class="total"><td class="lbl">Total</td><td></td><td></td><td class="n">{_money(total)}</td></tr>
  </table>
  <div class="terms"><div class="h">Terms</div>{_esc(d.get('terms'))} &middot; {_esc(d.get('validity'))}</div>
  {notes}
  <div class="foot"><span>{_esc(b["name"])}</span><span>{_esc(b["email"])} {_esc(b["phone"])}</span></div>
</div></body></html>"""
    return html, total


def _pdf(browser, html_path, pdf_path):
    if not browser:
        return False
    try:
        from pathlib import Path
        url = Path(html_path).resolve().as_uri()
        subprocess.run([browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={pdf_path}", url],
                       capture_output=True, timeout=60)
    except Exception:
        return False
    return os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 1500


def create(kind, draft):
    kind = (kind or "").strip().lower()
    if kind in ("estimate", "bid"):
        kind = "quote"
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}, got {kind!r}")
    number = _next_number(kind)
    html, total = render_html(kind, number, draft)
    os.makedirs(OUT_DIR, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", (draft.get("client") or kind).lower()).strip("-")[:32] or kind
    base = os.path.join(OUT_DIR, f"{time.strftime('%Y-%m-%d')}-{number}-{slug}")
    html_path, pdf_path = base + ".html", base + ".pdf"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    have_pdf = _pdf(_find_edge_or_chrome(), html_path, pdf_path)
    _ledger_add({"ts": int(time.time()), "kind": kind, "number": number,
                 "client": draft.get("client"), "title": draft.get("title"), "total": total,
                 "html": html_path, "pdf": pdf_path if have_pdf else None})
    return {"number": number, "html_path": html_path,
            "pdf_path": pdf_path if have_pdf else None, "total": total}


def recent(n=5):
    rows = []
    try:
        with open(LEDGER, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return rows[-n:][::-1]


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    cmd = argv[0].lower()
    if cmd == "create":
        if len(argv) < 3:
            print("usage: deals.py create <kind> <path-to-draft.json>")
            return 1
        with open(argv[2], "r", encoding="utf-8") as f:
            draft = json.load(f)
        result = create(argv[1], draft)
        print(json.dumps(result, indent=2))
        return 0
    if cmd == "recent":
        n = int(argv[1]) if len(argv) > 1 else 5
        print(json.dumps(recent(n), indent=2))
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
