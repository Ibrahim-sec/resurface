#!/bin/bash
# ============================================
# Resurface Demo Script
# Runs the full pipeline against the test app
# ============================================

set -e
cd /root/resurface

BANNER='
╔══════════════════════════════════════════════════╗
║        🔄 RESURFACE — LIVE DEMO                 ║
║   LLM-Powered Vulnerability Regression Hunter    ║
╚══════════════════════════════════════════════════╝
'
echo "$BANNER"

# Check for Gemini API key
if [ -z "$GEMINI_API_KEY" ]; then
    echo "❌ Set GEMINI_API_KEY first:"
    echo "   export GEMINI_API_KEY='your-key-here'"
    exit 1
fi

TARGET="http://127.0.0.1:9999"

# Check if test app is running
if ! curl -s "$TARGET/health" > /dev/null 2>&1; then
    echo "⚠️  Test app not running. Starting it..."
    python3 testapp/app.py &
    sleep 2
fi

echo "🎯 Target: $TARGET"
echo ""

# Demo reports to test
REPORTS=(
    "900001:Reflected XSS"
    "900002:IDOR User API"
    "900003:Open Redirect"
    "900004:Info Disclosure"
    "900005:Path Traversal"
)

for entry in "${REPORTS[@]}"; do
    IFS=':' read -r REPORT_ID REPORT_NAME <<< "$entry"
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📋 Report $REPORT_ID: $REPORT_NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Parse
    echo ""
    echo "🧠 Step 1: Parsing report with LLM..."
    python3 resurface.py parse --report "$REPORT_ID"
    
    echo ""
    echo "🔄 Step 2: Replaying against target..."
    python3 resurface.py replay --report "$REPORT_ID" --target "$TARGET"
    
    echo ""
    echo ""
    sleep 2
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Demo complete! Check data/results/ for reports."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
