"""
Tonight: the pack quiz page, served by the dashboard.

Merged into the dashboard 2026-09-21 from the standalone marty-portal (8788),
which had its own device list, its own login page, no auto-start, and a
"secure messaging" API that never had real cryptography in it. Now there is
one process, one login gate (dashboard_auth), one supervisor. The messaging
stub was dropped rather than ported; Channel is the real messaging project.

What this module owns: reading the packs out of marty-handoff/inbox, splitting a
pack into cycleable quiz pages, and rendering the page for a given handle. It
holds no auth logic - server.py gates the route before calling page().
"""

import html
import json
import os
import re
from datetime import datetime
from pathlib import Path

HANDOFF = Path(os.environ.get("HANDOFF_ROOT", r"C:\Users\{{WIN_USER}}\marty-handoff"))
INBOX = HANDOFF / "inbox"

# Shown when the inbox has no packs yet, so the page is never empty.
STARTER = [
    {"title": "Same-house surprise", "level": "6",
     "body": "She texts: Come to the bedroom. Door half open. No reply — just walk in."},
    {"title": "Outfit crumb", "level": "5",
     "body": "Leave one piece from the armoire on his pillow. Sticky note: Your move when you find me."},
    {"title": "Toy night (gentle)", "level": "5–6",
     "body": "Rose on her nightstand, face-down ask card beside it. Short warm-up, soft landing."},
    {"title": "Her-in-power stretch", "level": "6",
     "body": "She picks the pace. Steal-this: Hands on your thighs until I say."},
]


def load_packs():
    packs = []
    if INBOX.exists():
        for d in sorted(INBOX.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            pack_md, brief = d / "pack.md", d / "brief.json"
            title, level, body = d.name, "", ""
            if pack_md.exists():
                body = pack_md.read_text(encoding="utf-8", errors="replace")
            if brief.exists():
                try:
                    b = json.loads(brief.read_text(encoding="utf-8"))
                    title = b.get("id") or title
                    level = str(b.get("level", ""))
                    if not body and b.get("ready_texts"):
                        body = "\n".join(b["ready_texts"])
                except Exception:
                    pass
            if body.strip():
                packs.append({"title": title, "level": level, "body": body})
    return packs


def pack_sections(body: str) -> list:
    """Split a markdown pack body into cycleable quiz pages."""
    body = (body or "").replace("\r\n", "\n")
    parts = re.split(r"(?=^##\s+)", body, flags=re.M)
    pages = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        lines = part.split("\n")
        title = "Tonight"
        if lines[0].startswith("##"):
            title = lines[0].lstrip("#").strip()
            rest = "\n".join(lines[1:]).strip()
        else:
            rest = part
        opts = []
        body_lines = []
        for ln in rest.split("\n"):
            m = re.match(r"^\s*-\s*\[[ xX]?\]\s*(.+)$", ln)
            if m:
                opts.append(m.group(1).strip())
            else:
                body_lines.append(ln)
        pages.append({
            "title": title,
            "body": "\n".join(body_lines).strip(),
            "options": opts,
        })
    if not pages:
        pages = [{"title": "Pack", "body": body.strip() or "(empty)", "options": []}]
    return pages


CSS = """
:root { color-scheme: dark; --bg:#0f0e0c; --panel:#141210; --line:#2a2622; --gold:#c4a574; --sand:#a89880; --mute:#6e6558; --ink:#e8e0d4; }
* { box-sizing: border-box; }
body { margin:0; font-family: Georgia, "Times New Roman", serif; background:var(--bg); color:var(--ink); line-height:1.5; }
a { color:var(--gold); text-decoration:none; }
.screen { display:none; min-height:100dvh; padding:1.25rem 1.1rem 2.5rem; }
.screen.on { display:block; }
.brand { letter-spacing:.22em; text-transform:uppercase; font-size:.72rem; color:var(--gold); margin:0 0 .35rem; }
h1 { font-size:1.55rem; font-weight:400; margin:0 0 .4rem; }
.sub { color:var(--mute); font-size:.9rem; margin:0 0 1.5rem; }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:.85rem; }
.tile { background:var(--panel); border:1px solid var(--line); border-radius:4px; padding:1.1rem .85rem 1rem; text-align:center; color:var(--ink); min-height:9.5rem; display:flex; flex-direction:column; align-items:center; justify-content:center; gap:.65rem; cursor:pointer; }
.tile:active { border-color:var(--gold); }
.tile svg { width:52px; height:52px; }
.tile span { font-size:.82rem; color:var(--sand); }
.browse { display:block; text-align:center; margin-top:1rem; padding:.85rem; border:1px solid var(--line); border-radius:4px; color:var(--mute); font-size:.78rem; letter-spacing:.12em; text-transform:uppercase; background:transparent; width:100%; cursor:pointer; }
.back { display:inline-block; margin-bottom:1rem; color:var(--mute); font-size:.8rem; }
.flow .panel { background:var(--panel); border:1px solid var(--line); border-radius:4px; padding:1.25rem 1rem; margin-top:.75rem; }
.flow h2 { font-size:1.15rem; font-weight:400; margin:0 0 .5rem; color:var(--gold); }
.btn { display:inline-block; margin-top:.4rem; padding:.65rem 1rem; border:1px solid var(--gold); color:var(--gold); border-radius:2px; font-size:.8rem; letter-spacing:.1em; text-transform:uppercase; background:transparent; cursor:pointer; }
.meta { color:var(--mute); font-size:.85rem; }
.card { background:#1a1814; border:1px solid var(--line); border-radius:4px; padding:1rem; margin:.75rem 0; }
.lvl { color:var(--gold); font-size:.8rem; }
.gallery { margin:1rem 0; }
.diag { background:var(--panel); border:1px solid var(--line); border-radius:4px; padding:.85rem; margin:.7rem 0; }
.diag figcaption { color:var(--gold); font-size:.72rem; margin:0 0 .55rem; letter-spacing:.14em; text-transform:uppercase; }
.diag svg { width:100%; height:auto; display:block; }
footer { color:var(--mute); font-size:.8rem; margin-top:1.5rem; }
input, select, textarea { width:100%; background:#0f0e0c; border:1px solid var(--line); color:var(--ink); padding:.7rem .75rem; border-radius:2px; font:inherit; margin:.35rem 0 .7rem; }
.quiz-box { max-width:28rem; margin:0 auto; background:var(--panel); border:1px solid var(--line); border-radius:4px; padding:1.15rem 1rem 1.25rem; }
.quiz-box .pack-pick { margin:0 0 1rem; }
.quiz-box label.pick-label { display:block; font-size:.72rem; letter-spacing:.14em; text-transform:uppercase; color:var(--mute); margin-bottom:.35rem; }
.quiz-progress { display:flex; gap:.35rem; justify-content:center; margin:0 0 1rem; flex-wrap:wrap; }
.quiz-progress span { width:.55rem; height:.55rem; border-radius:50%; background:#2a2622; display:inline-block; }
.quiz-progress span.on { background:var(--gold); }
.quiz-page h2 { font-size:1.15rem; font-weight:400; color:var(--gold); margin:0 0 .65rem; }
.quiz-page .body { color:var(--ink); font-size:.95rem; white-space:pre-wrap; }
.quiz-opts { display:flex; flex-direction:column; gap:.5rem; margin-top:1rem; }
.quiz-opts button { text-align:left; padding:.75rem .85rem; border:1px solid var(--line); background:#0f0e0c; color:var(--sand); border-radius:3px; font:inherit; cursor:pointer; }
.quiz-opts button.picked, .quiz-opts button:active { border-color:var(--gold); color:var(--gold); }
.quiz-nav { display:flex; justify-content:space-between; align-items:center; gap:.75rem; margin-top:1.15rem; }
.quiz-nav .btn { margin-top:0; }
.quiz-nav .meta { color:var(--mute); font-size:.8rem; }
"""

ICON_PICTURE = """<svg viewBox="0 0 64 64" fill="none"><rect x="10" y="14" width="44" height="36" stroke="#c4a574" stroke-width="2.25"/><path d="M10 40 L24 28 L34 36 L44 26 L54 38" stroke="#a89880" stroke-width="2"/><circle cx="44" cy="24" r="3.5" stroke="#c4a574" stroke-width="2"/></svg>"""
ICON_VIDEO = """<svg viewBox="0 0 64 64" fill="none"><rect x="8" y="18" width="36" height="28" stroke="#c4a574" stroke-width="2.25"/><path d="M44 24 L56 18 L56 46 L44 40 Z" stroke="#a89880" stroke-width="2"/></svg>"""
ICON_TEXT = """<svg viewBox="0 0 64 64" fill="none"><path d="M12 16 H52 V40 H28 L18 50 V40 H12 Z" stroke="#c4a574" stroke-width="2.25"/><line x1="20" y1="26" x2="44" y2="26" stroke="#a89880" stroke-width="2"/><line x1="20" y1="33" x2="38" y2="33" stroke="#6e6558" stroke-width="2"/></svg>"""
ICON_EVENING = """<svg viewBox="0 0 64 64" fill="none"><circle cx="32" cy="30" r="12" stroke="#c4a574" stroke-width="2.25"/><path d="M32 18 A12 12 0 0 1 32 42" stroke="#8a7355" stroke-width="2.5"/><line x1="18" y1="50" x2="46" y2="50" stroke="#6e6558" stroke-width="2"/></svg>"""

DIAGRAMS = """
<section class="gallery">
  <figure class="diag"><figcaption>Room · foot of bed</figcaption>
  <svg viewBox="0 0 360 240" xmlns="http://www.w3.org/2000/svg"><rect width="360" height="240" fill="#141210"/><rect x="28" y="24" width="304" height="188" fill="none" stroke="#3d3832" stroke-width="1.25"/><line x1="96" y1="36" x2="264" y2="36" stroke="#8a7355" stroke-width="2.5"/><rect x="108" y="48" width="144" height="112" fill="none" stroke="#c4a574" stroke-width="2.75"/><rect x="118" y="56" width="48" height="22" fill="none" stroke="#a89880" stroke-width="1.75"/><rect x="194" y="56" width="48" height="22" fill="none" stroke="#a89880" stroke-width="1.75"/><text x="180" y="118" text-anchor="middle" fill="#8a8074" font-size="10" font-family="Georgia, serif">BED</text><text x="180" y="28" text-anchor="middle" fill="#8a7355" font-size="8" font-family="Georgia, serif" letter-spacing="1.5">HEADBOARD</text></svg></figure>
</section>
"""


def page(handle: str = "lukas"):
    packs = load_packs()

    def _rank(p):
        t = str(p.get("title", "")).lower()
        if "evening" in t:
            return (0, t)
        if "starter" in t:
            return (2, t)
        return (1, t)

    items = sorted(packs if packs else STARTER, key=_rank)
    pack_payload = []
    for p in items:
        pack_payload.append({
            "title": str(p.get("title", "idea")),
            "level": str(p.get("level", "")),
            "pages": pack_sections(str(p.get("body", ""))),
        })
    packs_json = json.dumps(pack_payload, ensure_ascii=False).replace("</", "<\\/")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    src = f"{len(packs)} pack(s)" if packs else "starter set"
    handle_safe = html.escape(handle or "lukas")
    is_their = (handle or "").lower() == "{{FAMILY_NAME_1_LC}}"

    if is_their:
        evening_inner = """
  <div class="panel" id="gate-ask">
    <p>Do you already have something in mind, or do you want a little help?</p>
    <button type="button" class="btn" id="gate-ideas-btn">I have ideas</button>
    <button type="button" class="btn" id="gate-help-btn" style="margin-left:.5rem">I want some help</button>
  </div>
  <div class="panel" id="gate-ideas" hidden>
    <p>Write anything you want to remember — or skip and stay private.</p>
    <textarea id="ideas-box" rows="4" placeholder="Optional notes (stays on this device only)"></textarea>
    <button type="button" class="btn" id="ideas-set-btn">I'm set</button>
    <button type="button" class="btn" data-go="quiz" style="margin-left:.5rem">Actually, open packs</button>
    <p class="meta" id="ideas-done" hidden>Got it. Enjoy your evening.</p>
  </div>
  <div class="panel" id="gate-help" hidden>
    <p>Open packs walks you through tonight's deck — energy check, picks, soft gate. No rush.</p>
    <button type="button" class="btn" data-go="quiz">Open packs</button>
  </div>
"""
        gate_js = """
  document.getElementById('gate-ideas-btn').addEventListener('click', function () {
    document.getElementById('gate-ask').hidden = true;
    document.getElementById('gate-ideas').hidden = false;
    document.getElementById('gate-help').hidden = true;
  });
  document.getElementById('gate-help-btn').addEventListener('click', function () {
    document.getElementById('gate-ask').hidden = true;
    document.getElementById('gate-ideas').hidden = true;
    document.getElementById('gate-help').hidden = false;
  });
  document.getElementById('ideas-set-btn').addEventListener('click', function () {
    document.getElementById('ideas-done').hidden = false;
  });
"""
    else:
        evening_inner = """
  <div class="panel">
    <p>Preview the evening deck from marty-handoff, then open packs for the live quiz.</p>
    <p class="meta">Same pack list she sees · soft gate · local only</p>
    <button type="button" class="btn" data-go="quiz">Open packs</button>
  </div>
"""
        gate_js = ""

    gate_js_f = gate_js.replace("{", "{{").replace("}", "}}")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f0e0c">
<title>Tonight</title>
<style>{CSS}</style>
</head>
<body>

<section id="splash" class="screen on">
  <p class="brand">Tonight</p>
  <h1>Where do you want to begin?</h1>
  <p class="sub">Private tunnel · tasteful only · local only · {handle_safe}</p>
  <div class="grid">
    <button type="button" class="tile" data-go="picture">{ICON_PICTURE}<span>Send a Picture</span></button>
    <button type="button" class="tile" data-go="video">{ICON_VIDEO}<span>Send a Video</span></button>
    <button type="button" class="tile" data-go="text">{ICON_TEXT}<span>Prompt a Sexy Text</span></button>
    <button type="button" class="tile" data-go="evening">{ICON_EVENING}<span>Evening Generator</span></button>
  </div>
  <button type="button" class="browse" data-go="browse">Browse scenarios &amp; outfits</button>
</section>

<section id="picture" class="screen"><div class="flow"><a class="back" href="#" data-go="splash">← Tonight</a><h1>Send a Picture</h1><div class="panel"><p>Camera-roll still over Tailscale. Channel media encrypt wiring next.</p><button type="button" class="btn" data-go="splash">Back</button></div></div></section>
<section id="video" class="screen"><div class="flow"><a class="back" href="#" data-go="splash">← Tonight</a><h1>Send a Video</h1><div class="panel"><p>Short clip, same tunnel privacy model.</p><button type="button" class="btn" data-go="splash">Back</button></div></div></section>
<section id="text" class="screen"><div class="flow"><a class="back" href="#" data-go="splash">← Tonight</a><h1>Prompt a Sexy Text</h1><div class="panel"><p>“Come to the bedroom. Door half open.”</p><p>“Tell me a number 1–10.”</p><button type="button" class="btn" data-go="browse">More ideas</button></div></div></section>

<section id="evening" class="screen">
  <div class="flow">
    <a class="back" href="#" data-go="splash">← Tonight</a>
    <h1>Evening Generator</h1>
    <p class="meta">{html.escape(src)} · {html.escape(now)}</p>
{evening_inner}
  </div>
</section>

<section id="quiz" class="screen">
  <a class="back" href="#" data-go="evening">← Evening</a>
  <p class="brand">Evening Generator</p>
  <h1>Pack quiz</h1>
  <div class="quiz-box" id="quiz-box">
    <div class="pack-pick">
      <label class="pick-label" for="pack-select">Pack</label>
      <select id="pack-select"></select>
    </div>
    <div class="quiz-progress" id="quiz-progress" aria-hidden="true"></div>
    <div class="quiz-page" id="quiz-page"></div>
    <div class="quiz-nav">
      <button type="button" class="btn" id="quiz-prev">Previous</button>
      <span class="meta" id="quiz-pos"></span>
      <button type="button" class="btn" id="quiz-next">Next</button>
    </div>
  </div>
  <footer style="text-align:center;margin-top:1.25rem">Cycle pages · pick answers · soft gate</footer>
</section>

<section id="browse" class="screen">
  <a class="back" href="#" data-go="splash">← Tonight</a>
  <p class="brand">Ideas</p>
  <h1>Scenarios &amp; outfits</h1>
  <p class="meta">{html.escape(src)} · {html.escape(now)}</p>
  {DIAGRAMS}
  <footer>Line art only · no photos</footer>
</section>

<script type="application/json" id="packs-data">{packs_json}</script>
<script>
(function () {{
  var packs = [];
  try {{
    packs = JSON.parse(document.getElementById('packs-data').textContent);
  }} catch (e) {{ packs = []; }}

  var state = {{ packIndex: 0, pageIndex: 0, picks: {{}} }};

  function show(id) {{
    document.querySelectorAll('.screen').forEach(function (el) {{ el.classList.remove('on'); }});
    var el = document.getElementById(id) || document.getElementById('splash');
    el.classList.add('on');
    window.scrollTo(0, 0);
    if (location.hash !== '#' + id) history.replaceState(null, '', '#' + id);
  }}

  document.querySelectorAll('[data-go]').forEach(function (el) {{
    el.addEventListener('click', function (e) {{
      e.preventDefault();
      var go = el.getAttribute('data-go');
      show(go);
      if (go === 'quiz') renderAll(true);
    }});
  }});
{gate_js_f}
  function currentPack() {{
    return packs[state.packIndex] || {{ title: 'None', pages: [{{ title: 'Empty', body: 'No packs in inbox yet.', options: [] }}] }};
  }}

  function fillSelect() {{
    var sel = document.getElementById('pack-select');
    if (!sel) return;
    sel.innerHTML = '';
    packs.forEach(function (p, i) {{
      var opt = document.createElement('option');
      opt.value = String(i);
      opt.textContent = p.title + (p.level ? ' · L' + p.level : '');
      if (i === state.packIndex) opt.selected = true;
      sel.appendChild(opt);
    }});
    if (!packs.length) {{
      var opt = document.createElement('option');
      opt.textContent = 'No packs';
      sel.appendChild(opt);
    }}
  }}

  function renderProgress(n, i) {{
    var row = document.getElementById('quiz-progress');
    if (!row) return;
    row.innerHTML = '';
    for (var k = 0; k < n; k++) {{
      var d = document.createElement('span');
      if (k === i) d.className = 'on';
      row.appendChild(d);
    }}
  }}

  function renderPage() {{
    var pack = currentPack();
    var pages = pack.pages || [];
    if (state.pageIndex < 0) state.pageIndex = 0;
    if (state.pageIndex >= pages.length) state.pageIndex = Math.max(0, pages.length - 1);
    var page = pages[state.pageIndex] || {{ title: 'Pack', body: '', options: [] }};
    renderProgress(pages.length, state.pageIndex);
    var pos = document.getElementById('quiz-pos');
    if (pos) pos.textContent = (state.pageIndex + 1) + ' / ' + Math.max(pages.length, 1);
    var host = document.getElementById('quiz-page');
    if (!host) return;
    host.innerHTML = '<h2></h2><div class="body"></div>';
    host.querySelector('h2').textContent = page.title || pack.title || 'Page';
    host.querySelector('.body').textContent = page.body || '';
    if (page.options && page.options.length) {{
      var opts = document.createElement('div');
      opts.className = 'quiz-opts';
      var key = state.packIndex + ':' + state.pageIndex;
      page.options.forEach(function (label) {{
        var b = document.createElement('button');
        b.type = 'button';
        b.textContent = label;
        if (state.picks[key] === label) b.className = 'picked';
        b.addEventListener('click', function () {{
          state.picks[key] = label;
          opts.querySelectorAll('button').forEach(function (x) {{ x.classList.remove('picked'); }});
          b.classList.add('picked');
        }});
        opts.appendChild(b);
      }});
      host.appendChild(opts);
    }}
    var prev = document.getElementById('quiz-prev');
    var next = document.getElementById('quiz-next');
    if (prev) prev.disabled = state.pageIndex <= 0;
    if (next) next.disabled = state.pageIndex >= pages.length - 1;
  }}

  function renderAll(resetPage) {{
    if (resetPage) state.pageIndex = 0;
    fillSelect();
    renderPage();
  }}

  var packSel = document.getElementById('pack-select');
  if (packSel) packSel.addEventListener('change', function (e) {{
    state.packIndex = parseInt(e.target.value, 10) || 0;
    state.pageIndex = 0;
    renderPage();
  }});
  var qp = document.getElementById('quiz-prev');
  var qn = document.getElementById('quiz-next');
  if (qp) qp.addEventListener('click', function () {{
    if (state.pageIndex > 0) {{ state.pageIndex--; renderPage(); }}
  }});
  if (qn) qn.addEventListener('click', function () {{
    var n = (currentPack().pages || []).length;
    if (state.pageIndex < n - 1) {{ state.pageIndex++; renderPage(); }}
  }});

  document.addEventListener('keydown', function (e) {{
    if (!document.getElementById('quiz').classList.contains('on')) return;
    if (e.key === 'ArrowLeft' && qp) qp.click();
    if (e.key === 'ArrowRight' && qn) qn.click();
  }});

  var start = (location.hash || '#splash').slice(1) || 'splash';
  show(start);
  if (start === 'quiz') renderAll(true);
  window.addEventListener('hashchange', function () {{
    var id = (location.hash || '#splash').slice(1);
    show(id);
    if (id === 'quiz') renderAll(false);
  }});
}})();
</script>
</body>
</html>"""
