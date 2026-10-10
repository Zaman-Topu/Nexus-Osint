"""
Export utility for NexusOSINT scan results.
Supports exporting results to JSON and clean Markdown reports.
"""

from datetime import datetime
import json
import os
from typing import Any, Dict


def get_reports_dir() -> str:
    """Ensure and return the reports directory."""
    cwd = os.getcwd()
    reports_dir = os.path.join(cwd, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def export_to_json(module_name: str, target: str, data: Dict[str, Any]) -> str:
    """Save scan data to a JSON file."""
    reports_dir = get_reports_dir()
    safe_target = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{module_name}_{safe_target}_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)

    payload = {
        "tool": "NexusOSINT",
        "timestamp": datetime.now().isoformat(),
        "module": module_name,
        "target": target,
        "data": data,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return filepath


def export_to_markdown(module_name: str, target: str, data: Dict[str, Any]) -> str:
    """Save scan data to a structured Markdown report."""
    reports_dir = get_reports_dir()
    safe_target = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{module_name}_{safe_target}_{timestamp}.md"
    filepath = os.path.join(reports_dir, filename)

    lines = [
        f"# NexusOSINT Reconnaissance Report",
        f"",
        f"- **Module:** `{module_name.upper()}`",
        f"- **Target:** `{target}`",
        f"- **Generated:** `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
        f"",
        f"---",
        f"",
        f"## Scan Findings",
        f"",
    ]

    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"### {key.replace('_', ' ').title()}")
            lines.append("")
            for sub_k, sub_v in value.items():
                if isinstance(sub_v, list):
                    lines.append(f"- **{sub_k.title()}:**")
                    for item in sub_v:
                        lines.append(f"  - {item}")
                else:
                    lines.append(f"- **{sub_k.title()}:** {sub_v}")
            lines.append("")
        elif isinstance(value, list):
            lines.append(f"### {key.replace('_', ' ').title()}")
            lines.append("")
            if value:
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"- " + ", ".join(f"**{k}**: {v}" for k, v in item.items()))
                    else:
                        lines.append(f"- {item}")
            else:
                lines.append("_None detected_")
            lines.append("")
        else:
            lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

    lines.append("")
    lines.append("---")
    lines.append("*Generated automatically by NexusOSINT*")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return filepath
