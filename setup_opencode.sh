#!/usr/bin/env bash
# Inject/update the robin-tools MCP entry in ~/.config/opencode/opencode.json
# Works on Mac and Linux. Run from anywhere — uses this script's location as repo root.
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENCODE_CFG="${HOME}/.config/opencode/opencode.json"

if [ ! -f "$OPENCODE_CFG" ]; then
  echo "Error: $OPENCODE_CFG not found. Is OpenCode installed?"
  exit 1
fi

# Use python3 to safely merge the robin-tools entry into the existing JSON
python3 - "$OPENCODE_CFG" "$REPO_ROOT" <<'EOF'
import json, sys

cfg_path = sys.argv[1]
repo_root = sys.argv[2]

with open(cfg_path) as f:
    cfg = json.load(f)

cfg.setdefault("mcp", {})
cfg["mcp"]["robin-tools"] = {
    "command": [
        f"{repo_root}/.venv/bin/python3",
        f"{repo_root}/mcp_server.py"
    ],
    "enabled": True,
    "timeout": 300000,
    "type": "local"
}

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

print(f"Updated {cfg_path} with repo root: {repo_root}")
EOF
