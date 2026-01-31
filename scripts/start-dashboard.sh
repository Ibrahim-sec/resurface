#!/usr/bin/env bash
# Launch the Resurface Streamlit dashboard
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "🔍 Starting Resurface Dashboard..."
echo "   URL: http://127.0.0.1:8501"
echo ""

streamlit run src/dashboard/app.py \
    --server.port 8501 \
    --server.address 127.0.0.1
