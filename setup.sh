#!/usr/bin/env bash
# TheRobin — Environment Setup
# Run once: bash setup.sh
# Then use: ./run.sh  OR  source venv/bin/activate && python3 main.py

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

VENV_DIR=".venv"
PYTHON="python3"

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │      TheRobin — Setup                            │"
echo "  └──────────────────────────────────────────────────┘"
echo ""

# Check Python
if ! command -v "$PYTHON" &>/dev/null; then
    echo "  [ERROR] python3 not found. Install Python 3.10+ first."
    exit 1
fi

PYTHON_VERSION=$($PYTHON --version 2>&1 | cut -d' ' -f2)
echo "  [OK] Python $PYTHON_VERSION found"

# Check Ollama
if curl -s http://localhost:11434/api/tags &>/dev/null; then
    echo "  [OK] Ollama is running"
    MODELS=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys,json; m=json.load(sys.stdin).get('models',[]); print(', '.join(x['name'] for x in m[:5]))" 2>/dev/null)
    echo "  [OK] Models: $MODELS"
else
    echo "  [WARN] Ollama not responding at localhost:11434"
    echo "         Start it with: ollama serve"
fi

# Create venv
echo ""
echo "  Creating virtual environment..."
$PYTHON -m venv "$VENV_DIR"
echo "  [OK] venv created at ./$VENV_DIR"

# Activate and install
source "$VENV_DIR/bin/activate"

echo ""
echo "  Installing dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo "  [OK] Dependencies installed:"
pip show rich requests beautifulsoup4 PySocks selenium 2>/dev/null | grep -E "^(Name|Version):" | paste - - | awk '{print "       " $0}'

# Check for Chromium/Chrome (needed for browser vision)
echo ""
if command -v chromium-browser &>/dev/null || command -v chromium &>/dev/null \
   || [ -f /snap/chromium/current/usr/lib/chromium-browser/chrome ] \
   || [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ] \
   || [ -f "/Applications/Chromium.app/Contents/MacOS/Chromium" ]; then
    echo "  [OK] Chrome/Chromium found (browser vision enabled)"
else
    echo "  [WARN] Chrome/Chromium not found — browser screenshot features will be disabled"
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "         Install with: brew install --cask chromium"
        echo "         Or just install Google Chrome — it works too"
    else
        echo "         Install with: sudo snap install chromium"
        echo "         Or: sudo apt install chromium-browser"
    fi
fi

# Create run script
cat > run.sh << 'EOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
source "$DIR/.venv/bin/activate"
python3 "$DIR/main.py" "$@"
EOF
chmod +x run.sh

# Generate .mcp.json for Claude Code
echo ""
echo "  Generating .mcp.json for Claude Code..."
# Detect Windows (Git Bash / MSYS / Cygwin) vs Unix for Python path
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    PYTHON_PATH="${REPO_ROOT}/.venv/Scripts/python.exe"
else
    PYTHON_PATH="${REPO_ROOT}/.venv/bin/python3"
fi
sed -e "s|__REPO_ROOT__|${REPO_ROOT}|g" -e "s|__PYTHON_PATH__|${PYTHON_PATH}|g" "${REPO_ROOT}/.mcp.json.template" > "${REPO_ROOT}/.mcp.json"
echo "  [OK] .mcp.json generated"

# Patch ~/.config/opencode/opencode.json if OpenCode is installed
OPENCODE_CFG="${HOME}/.config/opencode/opencode.json"
if [ -f "$OPENCODE_CFG" ]; then
    echo ""
    echo "  Patching OpenCode MCP config..."
    python3 - "$OPENCODE_CFG" "$REPO_ROOT" <<'PYEOF'
import json, sys
cfg_path, repo_root = sys.argv[1], sys.argv[2]
with open(cfg_path) as f:
    cfg = json.load(f)
cfg.setdefault("mcp", {})
cfg["mcp"]["robin-tools"] = {
    "command": f"{repo_root}/.venv/bin/python3",
    "args": [f"{repo_root}/mcp_server.py"],
    "enabled": True,
    "timeout": 300000,
    "type": "local"
}
with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYEOF
    echo "  [OK] OpenCode MCP config updated"

    # Sync all available Ollama models into opencode.json
    if curl -s http://localhost:11434/api/tags &>/dev/null; then
        echo "  Syncing Ollama models into OpenCode config..."
        python3 - "$OPENCODE_CFG" <<'PYEOF'
import json, sys, urllib.request
cfg_path = sys.argv[1]
try:
    with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as r:
        models = json.load(r).get("models", [])
except Exception as e:
    print(f"  [WARN] Could not fetch Ollama models: {e}")
    sys.exit(0)

with open(cfg_path) as f:
    cfg = json.load(f)

cfg.setdefault("provider", {}).setdefault("ollama", {}).setdefault("models", {})
for m in models:
    name = m["name"]
    cfg["provider"]["ollama"]["models"][name] = {"name": name}

# Ensure required ollama provider fields are set
cfg["provider"]["ollama"].setdefault("name", "Ollama (local)")
cfg["provider"]["ollama"].setdefault("npm", "@ai-sdk/openai-compatible")
cfg["provider"]["ollama"].setdefault("options", {"baseURL": "http://127.0.0.1:11434/v1"})

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

print(f"  [OK] Synced {len(models)} Ollama model(s) into OpenCode config")
PYEOF
    else
        echo "  [SKIP] Ollama not running — skipping model sync"
    fi
else
    echo "  [SKIP] OpenCode not found (skipping MCP patch)"
fi

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │  Setup complete!                                  │"
echo "  │                                                   │"
echo "  │  Start console:  ./run.sh                         │"
echo "  │  With target:    ./run.sh -t http://target.com    │"
echo "  │  With model:     ./run.sh -m glm-5:cloud          │"
echo "  └──────────────────────────────────────────────────┘"
echo ""
