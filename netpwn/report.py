"""Report module — generate JSON + Markdown reports to reports/ directory."""

from __future__ import annotations

import json
import os
import time
from typing import Any


def ensure_reports_dir(path: str = "reports") -> str:
    """Create and return the reports directory path."""
    os.makedirs(path, exist_ok=True)
    return path


def generate_report(
    data: dict[str, Any],
    title: str = "netpwn Report",
    path: str = "reports",
    filename: str | None = None,
) -> dict[str, str]:
    """Write JSON + Markdown reports. Returns dict of file paths."""
    ensure_reports_dir(path)
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = filename or f"report_{ts}"

    json_path = os.path.join(path, f"{base}.json")
    md_path = os.path.join(path, f"{base}.md")

    # JSON
    with open(json_path, "w") as f:
        json.dump({"title": title, "generated": ts, **data}, f, indent=2, default=str)

    # Markdown
    md_lines = [f"# {title}", "", f"Generated: {ts}", ""]
    for section, content in data.items():
        md_lines.append(f"## {section}")
        md_lines.append("")
        if isinstance(content, dict):
            for k, v in content.items():
                md_lines.append(f"- **{k}**: {v}")
        elif isinstance(content, list):
            for item in content:
                md_lines.append(f"- {item}")
        else:
            md_lines.append(str(content))
        md_lines.append("")

    with open(md_path, "w") as f:
        f.write("\n".join(md_lines))

    return {"json": json_path, "markdown": md_path}


def demo() -> None:
    print("[report] Generate test report ...")
    data = {
        "summary": {
            "modules_run": 7,
            "tests_passed": 30,
            "anomalies_detected": 2,
            "mode": "dry-run",
        },
        "details": [
            "ARP build/parse: OK",
            "DHCP starvation: 10 MACs",
            "DNS spoof detection: 1 ID mismatch flagged",
        ],
    }
    paths = generate_report(data, title="netpwn Demo Report", path="/tmp/netpwn_reports")
    assert os.path.isfile(paths["json"])
    assert os.path.isfile(paths["markdown"])

    with open(paths["json"]) as f:
        loaded = json.load(f)
    assert loaded["summary"]["tests_passed"] == 30

    with open(paths["markdown"]) as f:
        md = f.read()
    assert "# netpwn Demo Report" in md

    os.unlink(paths["json"])
    os.unlink(paths["markdown"])
    print(f"  OK — JSON ({os.path.getsize(paths['json']) if os.path.exists(paths['json']) else 'deleted'}) + Markdown written")
    print("[report] All demos passed.")
