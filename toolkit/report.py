"""
report.py - Report Generation
================================
Aggregates findings from any module into a single JSON file and a
readable, self-contained HTML report with severity-based color coding.
"""

import datetime
import json
from typing import Dict, List

SEVERITY_COLORS = {
    "critical": "#8b0000",
    "high": "#c0392b",
    "medium": "#d68910",
    "low": "#2e86c1",
    "info": "#5d6d7e",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Toolkit Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background:#f7f7f8; color:#1a1a1a; }}
  h1 {{ border-bottom: 3px solid #333; padding-bottom: .5rem; }}
  h2 {{ margin-top: 2rem; color:#333; }}
  pre {{ background:#1e1e1e; color:#d4d4d4; padding:1rem; border-radius:6px; overflow-x:auto; font-size:.85rem; }}
  .meta {{ color:#666; font-size:.9rem; margin-bottom:1.5rem; }}
  .section {{ background:#fff; border:1px solid #ddd; border-radius:8px; padding:1rem 1.5rem; margin-bottom:1rem; }}
  .badge {{ display:inline-block; padding:.15rem .6rem; border-radius:4px; color:#fff; font-size:.75rem; font-weight:600; }}
</style>
</head>
<body>
<h1>Security Toolkit Report</h1>
<div class="meta">Generated: {timestamp}</div>
{sections}
</body>
</html>
"""


def _render_section(title: str, data) -> str:
    return f"""<div class="section">
<h2>{title}</h2>
<pre>{json.dumps(data, indent=2, default=str)}</pre>
</div>"""


def generate_html_report(findings: Dict[str, object], out_path: str = "report.html") -> str:
    """
    findings: dict mapping a section title (e.g. "Recon", "Vulnerabilities")
    to the raw result data (list/dict) from any toolkit module.
    """
    sections = "\n".join(_render_section(title, data) for title, data in findings.items())
    html = HTML_TEMPLATE.format(
        timestamp=datetime.datetime.now().isoformat(timespec="seconds"),
        sections=sections,
    )
    with open(out_path, "w") as f:
        f.write(html)
    return out_path


def generate_json_report(findings: Dict[str, object], out_path: str = "report.json") -> str:
    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)
    return out_path
