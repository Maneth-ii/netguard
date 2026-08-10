"""
forensics/generate_report.py

Generates a presentation-ready, ATT&CK-mapped PDF incident report from an
alert already stored in MongoDB (via storage/alert_store.py). This is
called on-demand from the web dashboard ("Generate Report" button) or
from the CLI for testing.
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

BASE_DIR = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR
OUTPUT_DIR = BASE_DIR.parent / "output" / "reports"


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_report_for_alert(alert: dict) -> dict:
    """
    alert: full alert document as stored by storage/alert_store.insert_alert()
           and retrieved via storage/alert_store.get_alert().

    Returns {"output_path": str, "report_hash": str}.
    """
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("report_template.html")

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # alert stored in Mongo has datetime objects for timestamps; template
    # needs strings, so normalize before rendering.
    alert_render = dict(alert)
    if isinstance(alert_render.get("detected_timestamp"), datetime):
        alert_render["detected_timestamp"] = alert_render["detected_timestamp"].isoformat()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"{alert['alert_id']}.pdf"

    def render_html(report_hash_placeholder):
        return template.render(
            alert=alert_render,
            device=alert["device"],
            features=alert["detection_features"],
            timeline=alert["timeline"],
            evidence=alert["evidence"],
            attack=alert["attack_info"],
            severity_label=alert["severity_label"],
            severity_color=_severity_to_color(alert["severity_label"]),
            combined_score=round(alert["severity_score"], 2),
            generated_at=generated_at,
            report_hash=report_hash_placeholder,
        )

    HTML(string=render_html("PENDING")).write_pdf(str(output_path))
    report_hash = sha256_of_file(output_path)
    HTML(string=render_html(report_hash)).write_pdf(str(output_path))

    return {"output_path": str(output_path), "report_hash": report_hash}


def _severity_to_color(label: str) -> str:
    return {
        "Critical": "#7a1f2b",
        "High": "#b3541e",
        "Medium": "#8a6d1a",
        "Low": "#2f6b3c",
    }.get(label, "#4b5563")
