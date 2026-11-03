"""Tests for Markdown -> PDF export (skipped if the optional extras are absent)."""
import pytest

from aegis import report_pdf
from aegis.report_pdf import HAS_PDF, build_html, markdown_to_pdf

MD = (
    "# Endpoint Assessment\n\n## 3. Executive summary\n\n"
    "| Severity | Count |\n| --- | --- |\n| 🔴 Critical | 1 |\n| 🟠 High | 2 |\n\n"
    "### 6.1 🟠 Finding\n\n**Proof:**\n\n```\nlistening on 0.0.0.0:23\n```\n"
)


@pytest.mark.skipif(not HAS_PDF, reason="PDF extras not installed")
def test_build_html_wraps_and_replaces_emoji():
    html = build_html(MD, "My Report")
    assert "<title>My Report</title>" in html
    assert "<table" in html                 # markdown table rendered
    assert "<pre" in html or "<code" in html  # fenced code rendered
    assert "🔴" not in html and "🟠" not in html  # emoji replaced for the PDF font
    assert "&#8226;" in html                 # colored bullet substituted


@pytest.mark.skipif(not HAS_PDF, reason="PDF extras not installed")
def test_markdown_to_pdf_writes_valid_pdf(tmp_path):
    out = markdown_to_pdf(MD, tmp_path / "report.pdf", title="R")
    data = out.read_bytes()
    assert data.startswith(b"%PDF")       # real PDF signature
    assert len(data) > 500


def test_install_hint_names_packages():
    hint = report_pdf._install_hint()
    assert "markdown" in hint and "xhtml2pdf" in hint
