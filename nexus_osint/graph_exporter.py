"""
Interactive Visual Network Graph Exporter for NexusOSINT.
Generates a standalone HTML document using Vis.js to visualize target entity graphs.
"""

from datetime import datetime
import json
import os
from typing import Any, Dict, List
from nexus_osint.exporter import get_reports_dir


def generate_graph_html(target: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Return the raw Vis.js HTML document string."""
    nodes_json = json.dumps(nodes, indent=2)
    edges_json = json.dumps(edges, indent=2)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NexusOSINT Entity Graph: {target}</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{
      margin: 0;
      padding: 0;
      background-color: #0b0f19;
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      overflow: hidden;
    }}
    #header {{
      position: absolute;
      top: 15px;
      left: 20px;
      z-index: 100;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(8px);
      padding: 12px 20px;
      border-radius: 10px;
      border: 1px solid #1e293b;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
    }}
    h1 {{
      margin: 0 0 4px 0;
      font-size: 1.15rem;
      color: #38bdf8;
      letter-spacing: 0.5px;
    }}
    .meta {{
      font-size: 0.82rem;
      color: #94a3b8;
    }}
    #network {{
      width: 100vw;
      height: 100vh;
    }}
    .legend {{
      position: absolute;
      bottom: 20px;
      right: 20px;
      z-index: 100;
      background: rgba(15, 23, 42, 0.85);
      backdrop-filter: blur(8px);
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid #1e293b;
      font-size: 0.78rem;
    }}
    .legend-item {{
      display: flex;
      align-items: center;
      margin-bottom: 4px;
    }}
    .legend-color {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
      margin-right: 8px;
    }}
  </style>
</head>
<body>
  <div id="header">
    <h1>⚡ NexusOSINT Target Graph</h1>
    <div class="meta">Target: <b>{target}</b> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
  </div>

  <div id="network"></div>

  <div class="legend">
    <div class="legend-item"><div class="legend-color" style="background:#eab308"></div>Target Seed</div>
    <div class="legend-item"><div class="legend-color" style="background:#06b6d4"></div>Identity / User</div>
    <div class="legend-item"><div class="legend-color" style="background:#10b981"></div>Platform / Profile</div>
    <div class="legend-item"><div class="legend-color" style="background:#3b82f6"></div>Domain / Subdomain</div>
    <div class="legend-item"><div class="legend-color" style="background:#f97316"></div>IP Address</div>
    <div class="legend-item"><div class="legend-color" style="background:#ef4444"></div>Port / CVE</div>
    <div class="legend-item"><div class="legend-color" style="background:#a855f7"></div>Cloud Asset</div>
  </div>

  <script type="text/javascript">
    const nodes = new vis.DataSet({nodes_json});
    const edges = new vis.DataSet({edges_json});

    const container = document.getElementById('network');
    const data = {{ nodes: nodes, edges: edges }};
    const options = {{
      nodes: {{
        shape: 'dot',
        size: 18,
        font: {{
          size: 13,
          color: '#f8fafc',
          strokeWidth: 2,
          strokeColor: '#0f172a'
        }},
        borderWidth: 2
      }},
      edges: {{
        width: 1.5,
        color: {{ color: '#334155', highlight: '#38bdf8' }},
        arrows: {{ to: {{ enabled: true, scaleFactor: 0.7 }} }},
        smooth: {{ type: 'continuous' }}
      }},
      physics: {{
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {{
          gravitationalConstant: -40,
          centralGravity: 0.01,
          springLength: 95,
          springConstant: 0.08
        }},
        maxVelocity: 50,
        minVelocity: 0.1,
        stabilization: {{ iterations: 120 }}
      }},
      interaction: {{
        hover: true,
        tooltipDelay: 100,
        navigationButtons: true
      }}
    }};

    const network = new vis.Network(container, data, options);
  </script>
</body>
</html>
"""


def export_network_graph_html(target: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], output_path: str = None) -> str:
    """Generate and save an interactive HTML network graph using Vis.js."""
    html_content = generate_graph_html(target, nodes, edges)

    if not output_path:
        reports_dir = get_reports_dir()
        safe_target = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(reports_dir, f"graph_{safe_target}_{timestamp}.html")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return output_path
