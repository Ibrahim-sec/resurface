#!/bin/bash
# Resurface — Juice Shop Demo
# Tests against OWASP Juice Shop (real app, not our testapp)
set -e

JUICE_SHOP_URL="http://localhost:3333"
REPORTS_SRC="data/juiceshop_reports"
REPORTS_DST="data/reports"

echo "╔══════════════════════════════════════════════════╗"
echo "║  🔄 Resurface × OWASP Juice Shop Demo           ║"
echo "║  Testing against a REAL vulnerable application   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Check Juice Shop is running
echo "🔍 Checking Juice Shop at ${JUICE_SHOP_URL}..."
if ! curl -s -o /dev/null -w "" --max-time 5 "${JUICE_SHOP_URL}"; then
    echo "❌ Juice Shop not reachable at ${JUICE_SHOP_URL}"
    echo "   Start it with: docker run -d -p 3333:3000 --name juice-shop bkimminich/juice-shop"
    exit 1
fi
echo "✅ Juice Shop is running!"
echo ""

# Copy Juice Shop reports
echo "📋 Loading Juice Shop vulnerability reports..."
mkdir -p "${REPORTS_DST}"

# Backup existing reports
if ls "${REPORTS_DST}"/*.json >/dev/null 2>&1; then
    mkdir -p "${REPORTS_DST}/.backup"
    cp "${REPORTS_DST}"/*.json "${REPORTS_DST}/.backup/" 2>/dev/null || true
fi

cp "${REPORTS_SRC}"/js_*.json "${REPORTS_DST}/"
echo "   Loaded $(ls ${REPORTS_SRC}/js_*.json | wc -l) reports"
echo ""

# Parse all reports
echo "🧠 Parsing reports with LLM..."
python resurface.py parse --all
echo ""

# Replay against Juice Shop
echo "🔄 Replaying against Juice Shop (${JUICE_SHOP_URL})..."
if [ "${DEMO_VERBOSE:-false}" = "true" ]; then
    python resurface.py replay-all --target "${JUICE_SHOP_URL}" --verbose
elif [ "${DEMO_ASYNC:-false}" = "true" ]; then
    python resurface.py replay-all --target "${JUICE_SHOP_URL}" --async --concurrency "${DEMO_CONCURRENCY:-3}"
else
    python resurface.py replay-all --target "${JUICE_SHOP_URL}"
fi
echo ""

# Stats
echo "📊 Results:"
python resurface.py stats
echo ""

# Export
echo "📄 Generating HTML report..."
python resurface.py export --format html
echo ""

echo "═══════════════════════════════════════════════════"
echo "  ✅ Demo complete!"
echo "  📊 HTML report: data/results/summary.html"
echo "  🔄 This tested against REAL OWASP Juice Shop —"
echo "     not a custom testapp. The AI parsed reports"
echo "     it never saw before against an app it has"
echo "     zero knowledge of."
echo "═══════════════════════════════════════════════════"
