#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DASHBOARD_DIR="$ROOT/o11y"
RUNBOOK_DIR="$ROOT/docs/runbooks"
ERRORS=0

echo "=== Validating dashboard JSON files ==="

for file in "$DASHBOARD_DIR"/*.json; do
    filename=$(basename "$file")
    echo -n "  $filename ... "

    if ! jq empty "$file" 2>/dev/null; then
        echo "INVALID JSON"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    for key in title uid panels templating tags time schemaVersion; do
        if ! jq -e ".$key != null" "$file" > /dev/null 2>&1; then
            echo "MISSING KEY: $key"
            ERRORS=$((ERRORS + 1))
        fi
    done

    uid=$(jq -r '.uid' "$file")
    if [[ ! "$uid" =~ ^pico- ]]; then
        echo "INVALID UID format: $uid (must start with 'pico-')"
        ERRORS=$((ERRORS + 1))
    fi

    has_owner=$(jq -r '.tags | index("owner:sre-team")' "$file")
    if [[ "$has_owner" == "null" ]]; then
        echo "MISSING owner tag"
        ERRORS=$((ERRORS + 1))
    fi

    var_count=$(jq '.templating.list | length' "$file")
    if [[ "$var_count" -lt 2 ]]; then
        echo "WARNING: only $var_count variables (expected >= 2: region, cell)"
    fi

    runbook_tag=$(jq -r '[.tags[] | select(startswith("runbook:"))][0] // empty' "$file")
    if [[ -z "$runbook_tag" ]]; then
        echo "MISSING runbook tag"
        ERRORS=$((ERRORS + 1))
        continue
    fi
    runbook_path="$ROOT/${runbook_tag#runbook:}"
    if [[ ! -f "$runbook_path" ]]; then
        echo "MISSING runbook file: $runbook_path"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    echo "OK"
done

echo "=== Validating alert runbook links ==="

RULES_FILE="$DASHBOARD_DIR/rules/pico-recording-rules.yaml"
if [[ -f "$RULES_FILE" ]]; then
    while IFS= read -r runbook; do
        [[ -z "$runbook" ]] && continue
        echo -n "  alert runbook $runbook ... "
        if [[ ! -f "$ROOT/$runbook" ]]; then
            echo "MISSING"
            ERRORS=$((ERRORS + 1))
        else
            echo "OK"
        fi
    done < <(grep -E 'runbook:[[:space:]]' "$RULES_FILE" | sed -E 's/.*runbook:[[:space:]]*//' | sort -u)
fi

echo "=== Validating runbook required sections ==="

required_headings=("First checks" "Mitigation" "Escalation" "Rollback")
for file in "$RUNBOOK_DIR"/*.md; do
    filename=$(basename "$file")
    if [[ "$filename" == "README.md" ]]; then
        continue
    fi
    echo -n "  $filename ... "
    missing=()
    for heading in "${required_headings[@]}"; do
        if ! grep -q "^## $heading" "$file"; then
            missing+=("$heading")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "MISSING SECTIONS: ${missing[*]}"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK"
    fi
done

echo "=== Validating runbook coverage files ==="

coverage_files=(
    "docs/runbooks/README.md"
    "docs/runbooks/lifecycle-operations.md"
    "docs/runbooks/control-plane.md"
    "docs/runbooks/scheduling-capacity.md"
    "docs/runbooks/host-health.md"
    "docs/runbooks/runtime-backend.md"
    "docs/runbooks/image-cache.md"
    "docs/runbooks/networking.md"
    "docs/runbooks/dns.md"
    "docs/runbooks/snapshot-fork.md"
    "docs/runbooks/cleanup-reconciliation.md"
    "docs/runbooks/host-quarantine.md"
    "docs/runbooks/audit-telemetry.md"
    "docs/runbooks/slo-error-budget.md"
    "docs/runbooks/drills/boot-non-ready-and-quarantine.md"
)
for rel in "${coverage_files[@]}"; do
    echo -n "  $rel ... "
    if [[ ! -f "$ROOT/$rel" ]]; then
        echo "MISSING"
        ERRORS=$((ERRORS + 1))
    else
        echo "OK"
    fi
done

if [[ $ERRORS -gt 0 ]]; then
    echo "=== $ERRORS validation errors found ==="
    exit 1
fi

echo "=== All dashboards and runbooks validated ==="
