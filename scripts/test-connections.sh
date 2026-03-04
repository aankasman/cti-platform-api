#!/bin/bash
# =============================================================================
# Comprehensive Integration Test Connection Validator
# Hits POST /v1/config/api-keys/:id/test for every built-in API key slot
# =============================================================================

API="http://localhost:3001"
API_KEY="${RINJANI_API_KEY:-o67GrOVJzbo59AdSRXzEvIk1}"
PASS=0
FAIL=0
SKIP=0

SLOTS=(
    "nvd"
    "virustotal"
    "virustotal-livehunt"
    "alienvault"
    "misp"
    "abuseipdb"
    "ipinfo"
    "google-safebrowsing"
    "exa"
    "threatfox"
    "abusech"
    "malpedia"
    "google-gemini"
    "openrouter"
)

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Integration Test Connection Validator                      ║"
echo "║  Backend: $API                                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

for SLOT in "${SLOTS[@]}"; do
    # Call the test endpoint
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API/v1/config/api-keys/$SLOT/test" -H "X-API-Key: $API_KEY" 2>/dev/null)
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    # Parse the response
    SUCCESS=$(echo "$BODY" | jq -r '.data.success' 2>/dev/null)
    MESSAGE=$(echo "$BODY" | jq -r '.data.message' 2>/dev/null)
    STATUS=$(echo "$BODY" | jq -r '.data.status // empty' 2>/dev/null)

    # Show result
    if [ "$SUCCESS" = "true" ]; then
        echo "  ✅  $SLOT — $MESSAGE (HTTP $STATUS)"
        PASS=$((PASS + 1))
    elif [ "$MESSAGE" = "API key not configured" ]; then
        echo "  ⬜  $SLOT — $MESSAGE (skipped, no key set)"
        SKIP=$((SKIP + 1))
    elif [ "$MESSAGE" = "Unknown API key slot" ]; then
        echo "  ❌  $SLOT — $MESSAGE ← SLOT NOT IN DB (needs restart/bootstrap)"
        FAIL=$((FAIL + 1))
    elif [ -z "$BODY" ] || [ "$HTTP_CODE" = "000" ]; then
        echo "  ❌  $SLOT — Backend unreachable (is it running?)"
        FAIL=$((FAIL + 1))
    else
        echo "  ❌  $SLOT — $MESSAGE ${STATUS:+(HTTP $STATUS)}"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Results: ✅ $PASS passed | ❌ $FAIL failed | ⬜ $SKIP skipped (no key)"
echo "════════════════════════════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "  ⚠️  $FAIL slot(s) need attention."
    echo "  If 'SLOT NOT IN DB', restart the backend to re-run bootstrap."
fi
