"""Render a Markdown report to PDF using pip-only libraries.

Markdown -> HTML (python-markdown) -> PDF (xhtml2pdf / reportlab). Both are pure
Python wheels, so there is no LaTeX, GTK or wkhtmltopdf to install — it works
from the same venv. PDF support is optional: if the packages are absent the rest
of Aegis is unaffected and `markdown_to_pdf` raises a clear PdfUnavailable.
"""
from __future__ import annotations

from pathlib import Path

try:
    import markdown as _markdown
    from xhtml2pdf import pisa as _pisa
    HAS_PDF = True
except ImportError:  # pragma: no cover - exercised when extras not installed
    HAS_PDF = False


class PdfUnavailable(Exception):
    """Raised when PDF export is requested but unavailable or fails."""


# xhtml2pdf has no emoji font, so map the severity emojis to colored bullets.
_EMOJI = {
    "🔴": '<span style="color:#c0392b">&#8226;</span>',
    "🟠": '<span style="color:#e67e22">&#8226;</span>',
    "🟡": '<span style="color:#b7950b">&#8226;</span>',
    "🔵": '<span style="color:#2980b9">&#8226;</span>',
    "⚪": '<span style="color:#7f8c8d">&#8226;</span>',
}

# The built-in PDF font (Helvetica/WinAnsi) covers Latin-1 only; substitute the
# non-Latin glyphs the reports use with safe equivalents so nothing renders blank.
_TEXT_SUBS = {
    "→": "-&gt;", "←": "&lt;-", "⇒": "=&gt;", "⇐": "&lt;=",
    "×": "x", "↓": "v", "·": "-",
    "…": "...", "’": "'", "‘": "'", "“": '"', "”": '"',
}

_CSS = """
@page { size: A4; margin: 1.8cm 1.5cm; }
body { font-family: Helvetica, Arial, sans-serif; font-size: 9.5pt; color: #222; line-height: 1.4; }
h1 { font-size: 20pt; color: #16304a; border-bottom: 2px solid #16304a; padding-bottom: 4px; }
h2 { font-size: 13pt; color: #1a3a5a; margin-top: 16px; border-bottom: 1px solid #cccccc; padding-bottom: 2px; }
h3 { font-size: 11pt; color: #333333; margin-top: 12px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th, td { border: 1px solid #bbbbbb; padding: 3px 5px; text-align: left; font-size: 8.5pt; vertical-align: top; }
th { background-color: #eef1f4; }
code { font-family: Courier, monospace; font-size: 8.5pt; background-color: #f6f6f6; }
pre { font-family: Courier, monospace; font-size: 8pt; background-color: #f6f6f6; padding: 6px; border: 1px solid #dddddd; }
blockquote { color: #666666; border-left: 3px solid #cccccc; padding-left: 8px; margin-left: 0; }
"""


def build_html(md_text: str, title: str) -> str:
    """Convert report Markdown to a self-contained, print-styled HTML document."""
    if not HAS_PDF:
        raise PdfUnavailable(_install_hint())
    body = _markdown.markdown(
        md_text, extensions=["tables", "fenced_code", "sane_lists"])
    for emoji, span in _EMOJI.items():
        body = body.replace(emoji, span)
    for ch, sub in _TEXT_SUBS.items():
        body = body.replace(ch, sub)
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title><style>{_CSS}</style></head>"
        f"<body>{body}</body></html>"
    )


def markdown_to_pdf(md_text: str, pdf_path: str | Path, title: str = "Report") -> Path:
    """Write `md_text` as a PDF to `pdf_path`. Raises PdfUnavailable on any failure."""
    if not HAS_PDF:
        raise PdfUnavailable(_install_hint())
    html = build_html(md_text, title)
    out = Path(pdf_path)
    with out.open("wb") as fh:
        result = _pisa.CreatePDF(src=html, dest=fh, encoding="utf-8")
    if result.err:
        raise PdfUnavailable(f"PDF generation reported {result.err} error(s)")
    return out


def _install_hint() -> str:
    return ("PDF export needs the 'markdown' and 'xhtml2pdf' packages. "
            "Install them with:  pip install markdown xhtml2pdf   "
            "(or: pip install aegis-vapt[pdf])")
