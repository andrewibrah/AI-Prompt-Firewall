#!/usr/bin/env bash
set -e

echo "═══════════════════════════════════════════════"
echo "  AI Prompt Firewall — Setup"
echo "═══════════════════════════════════════════════"

# Create venv if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "[1/5] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/5] Virtual environment exists, skipping..."
fi

source .venv/bin/activate

echo "[2/5] Installing dependencies..."
pip install -e ".[dev]" --quiet

echo "[3/5] Downloading NLP models (first run may take a minute)..."
python -c "from presidio_analyzer import AnalyzerEngine; AnalyzerEngine(); print('  ✓ Presidio ready')"
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2'); print('  ✓ Sentence-transformer ready')"

echo "[4/5] Setting up config..."
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "  ✓ Created .env from template — edit it with your LLM_API_KEY"
else
    echo "  ✓ .env already exists"
fi

echo "[5/5] Creating data directories..."
mkdir -p data/threats data/attacks

echo ""
echo "═══════════════════════════════════════════════"
echo "  Setup complete. Next steps:"
echo ""
echo "  1. Edit .env with your LLM API key"
echo "  2. Start:    source .venv/bin/activate && uvicorn api.server:app --reload"
echo "  3. Test:     pytest tests/ -v"
echo "  4. Red team: python -m scripts.red_team_runner"
echo "  5. Dashboard: open dashboard/index.html"
echo "═══════════════════════════════════════════════"
