"""Write a plain Word document (.docx) with no third-party packages.

Lukas, 2026-09-25: "stop saving documents as MD files. I cannot use them that way. PDF or Docx."
python-docx is not installed on this PC, and a .docx is only a zip of XML, so this builds one
directly: headings, paragraphs, bold runs and bullets, which is all a handoff document needs.

    py -3 tools/simple_docx.py IN.md OUT.docx      convert a simple markdown file
    from simple_docx import Doc                     build one in code

Markdown it understands: '# ', '## ', '### ' headings, '- ' or '* ' bullets (two leading spaces
nest one level), '**bold**' runs, '> ' quotes, '---' (a blank line), '|' table rows (written as
tab-separated lines), and blank lines between paragraphs. Anything else is plain text.
A ``` fenced block (code, diffs) keeps its lines: each line is its own small monospace paragraph, spaces
kept, nothing inside it read as markdown, and the fence lines themselves not printed. Before this
(2026-09-26), fenced lines were joined into one run-on paragraph, so a diff in a Word handoff was unreadable.
An unclosed fence runs to the end of the file.
"""
import re
import sys
import zipfile
from xml.sax.saxutils import escape

_BOLD = re.compile(r"\*\*(.+?)\*\*")

_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""

_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="120" w:line="276" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style>
</w:styles>"""


def _runs(text: str, italic: bool = False) -> str:
    out, pos = [], 0
    for m in _BOLD.finditer(text):
        if m.start() > pos:
            out.append((text[pos:m.start()], False))
        out.append((m.group(1), True))
        pos = m.end()
    if pos < len(text):
        out.append((text[pos:], False))
    xml = []
    for chunk, bold in out:
        props = ("<w:b/>" if bold else "") + ("<w:i/>" if italic else "")
        rpr = f"<w:rPr>{props}</w:rPr>" if props else ""
        xml.append(f'<w:r>{rpr}<w:t xml:space="preserve">{escape(chunk)}</w:t></w:r>')
    return "".join(xml)


class Doc:
    def __init__(self):
        self.body = []

    def heading(self, text: str, level: int = 1):
        self.body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading{level}"/></w:pPr>{_runs(text)}</w:p>')

    def para(self, text: str, italic: bool = False):
        self.body.append(f"<w:p>{_runs(text, italic)}</w:p>")

    def bullet(self, text: str, level: int = 0):
        left = 360 + 360 * level
        self.body.append(
            f'<w:p><w:pPr><w:spacing w:after="60"/><w:ind w:left="{left}" w:hanging="240"/></w:pPr>'
            f'<w:r><w:t xml:space="preserve">• </w:t></w:r>{_runs(text)}</w:p>')

    def blank(self):
        self.body.append("<w:p/>")

    def code(self, text: str):
        """One line of a fenced block: its own paragraph, monospace, spaces kept, no bold or bullets."""
        self.body.append(
            '<w:p><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr>'
            '<w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="16"/></w:rPr>'
            f'<w:t xml:space="preserve">{escape(text) or " "}</w:t></w:r></w:p>')

    def save(self, path: str):
        doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
               + "".join(self.body) +
               '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/>'
               '<w:pgMar w:top="1080" w:right="1080" w:bottom="1080" w:left="1080" w:header="720" w:footer="720" w:gutter="0"/>'
               '</w:sectPr></w:body></w:document>')
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", _CONTENT_TYPES)
            z.writestr("_rels/.rels", _RELS)
            z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
            z.writestr("word/document.xml", doc)
            z.writestr("word/styles.xml", _STYLES)


def from_markdown(md: str) -> Doc:
    d, para = Doc(), []

    def flush():
        if para:
            d.para(" ".join(s.strip() for s in para))
            para.clear()

    fenced = False
    for raw in md.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if s.startswith("```"):          # a fence opens or closes a code block; the fence itself isn't printed
            flush()
            if fenced:
                d.blank()
            fenced = not fenced
            continue
        if fenced:
            d.code(raw)
            continue
        if not s:
            flush()
            continue
        if s == "---":
            flush()
            d.blank()
            continue
        m = re.match(r"^(#{1,3})\s+(.*)$", s)
        if m:
            flush()
            d.heading(m.group(2), len(m.group(1)))
            continue
        m = re.match(r"^( *)[-*]\s+(.*)$", line)
        if m:
            flush()
            d.bullet(m.group(2), min(len(m.group(1)) // 2, 3))
            continue
        if s.startswith(">"):
            flush()
            d.para(s.lstrip("> ").strip(), italic=True)
            continue
        if s.startswith("|"):
            flush()
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            d.para("\t".join(cells))
            continue
        para.append(s)
    flush()
    if fenced:                           # an unclosed fence ran to the end of the file
        d.blank()
    return d


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: simple_docx.py IN.md OUT.docx")
    from_markdown(open(sys.argv[1], encoding="utf-8").read()).save(sys.argv[2])
    print("wrote", sys.argv[2])
