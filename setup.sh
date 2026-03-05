#!/usr/bin/env bash
# TheRobin — Environment Setup
# Run once: bash setup.sh
# Then use: ./run.sh  OR  source venv/bin/activate && python3 main.py

set -e
cd "$(dirname "$0")"

VENV_DIR="venv"
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
source "$DIR/venv/bin/activate"
python3 "$DIR/main.py" "$@"
EOF
chmod +x run.sh

echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │  Setup complete!                                  │"
echo "  │                                                   │"
echo "  │  Start console:  ./run.sh                         │"
echo "  │  With target:    ./run.sh -t http://target.com    │"
echo "  │  With model:     ./run.sh -m kimi-k2.5:cloud       │"
echo "  └──────────────────────────────────────────────────┘"
echo ""
