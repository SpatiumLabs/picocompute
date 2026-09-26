#!/bin/bash
# Coverage collector and gate for PicoCompute launch reviews.
#
# Collects LLVM source-based coverage with cargo-llvm-cov, aggregates line
# coverage per security-sensitive crate, compares against
# .config/coverage.json floors, and writes a revision-pinned candidate bundle.
#
# Gate behavior is block: exit 1 when any floor fails. The bundle uploads
# anyway so triage never loses the failing numbers.
#
# Usage:
#   scripts/coverage.sh [--output-dir DIR] [--thresholds FILE] [--json FILE]
#   scripts/coverage.sh --check-config
#
# Options:
#   --output-dir DIR   bundle dir (default target/coverage/bundle-<sha>)
#   --thresholds FILE  threshold config (default .config/coverage.json)
#   --json FILE        skip collection, gate this coverage.json (testing)
#   --check-config     validate thresholds config and exit
#   -h/--help          usage
#
# Env:
#   COVERAGE_WARN_ONLY=1  record a failing bundle but exit 0 (calibration
#                         runs only; CI default is block)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

THRESHOLDS=".config/coverage.json"
OUT_DIR=""
JSON_OVERRIDE=""
CHECK_CONFIG=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUT_DIR="$2"; shift 2 ;;
    --thresholds) THRESHOLDS="$2"; shift 2 ;;
    --json) JSON_OVERRIDE="$2"; shift 2 ;;
    --check-config) CHECK_CONFIG=1; shift ;;
    -h|--help)
      sed -n '1,20p' "$0"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ ! -f "$THRESHOLDS" ]]; then
  echo "thresholds file missing: $THRESHOLDS" >&2
  exit 2
fi

# Validate config schema with python3 (no extra deps). Fails fast on
# malformed floors so CI never gates on a typo.
python3 - "$THRESHOLDS" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
assert cfg["version"] == 1, "unsupported coverage config version"
assert cfg["metric"] == "line", "gate metric must be line"
t = cfg["thresholds"]
assert 0 < t["workspace_line"] <= 100, "workspace_line out of range"
for crate, floor in t["per_crate_line"].items():
    assert 0 <= floor <= 100, f"floor out of range for {crate}"
print("coverage config ok:", sys.argv[1])
PY

if [[ "$CHECK_CONFIG" == "1" ]]; then
  exit 0
fi

REVISION="${GITHUB_SHA:-$(git rev-parse HEAD)}"
if git diff --quiet && git diff --cached --quiet; then
  DIRTY="false"
else
  DIRTY="true"
fi
TOOLCHAIN="$(rustc --version 2>/dev/null || echo unknown)"
STAMP="$(date -u +%FT%TZ)"

if [[ -z "$OUT_DIR" ]]; then
  SHORT="$(echo "$REVISION" | cut -c1-12)"
  OUT_DIR="target/coverage/bundle-${SHORT}"
fi
mkdir -p "$OUT_DIR"

COVERAGE_JSON="$OUT_DIR/coverage.json"
LCOV_INFO="$OUT_DIR/lcov.info"

if [[ -n "$JSON_OVERRIDE" ]]; then
  # Testing seam: gate a prebuilt JSON without running the suite.
  # Used by the artificial-lowering test plan without a scratch branch.
  cp "$JSON_OVERRIDE" "$COVERAGE_JSON"
  # Synthetic placeholder so the bundle stays complete. Marked clearly so
  # it is never mistaken for measured evidence.
  if [[ ! -f "$LCOV_INFO" ]]; then
    {
      echo "# SYNTHETIC PLACEHOLDER - testing seam only, not measured coverage"
      echo "TN:"
      echo "end_of_record"
    } > "$LCOV_INFO"
  fi
else
  if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo "cargo-llvm-cov missing; install with: cargo install cargo-llvm-cov --locked" >&2
    exit 2
  fi
  if ! cargo nextest --version >/dev/null 2>&1; then
    echo "cargo-nextest missing; coverage collection uses nextest" >&2
    exit 2
  fi
  echo "collecting coverage (nextest, workspace, all features)..."
  # JSON first (full data), then lcov report reuses profile data without rerun.
  # Both commands carry the same workspace/feature scope so the two
  # artifacts describe the same code set.
  cargo llvm-cov nextest --workspace --all-features --json --output-path "$COVERAGE_JSON"
  cargo llvm-cov report --lcov --output-path "$LCOV_INFO"
fi

# Gate evaluation. Aggregates only crates/*/src paths so tests/examples
# never inflate the number. Per-file summary lines carry covered/count.
# Workspace and per-crate floors all use this filtered scope, never the
# unfiltered llvm-cov totals (which include tests/examples/build scripts
# and ungated crates). Unfiltered totals are recorded informationally.
GATE_OUT="$OUT_DIR/gate.json"
python3 - "$COVERAGE_JSON" "$THRESHOLDS" "$GATE_OUT" <<'PY'
import json, sys
cov_path, cfg_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
cov = json.load(open(cov_path))
cfg = json.load(open(cfg_path))
data = cov["data"][0]
tot = data["totals"]
llvm_totals = {
    "lines": round(tot["lines"]["percent"], 2),
    "regions": round(tot["regions"]["percent"], 2),
    "functions": round(tot["functions"]["percent"], 2),
}

# Aggregate filtered crates/*/src counts for lines, regions, functions.
per = {}
f_lines = f_covered = 0
f_regions = f_regions_covered = 0
f_funcs = f_funcs_covered = 0
for f in data.get("files", []):
    name = f.get("filename", "")
    marker = "crates/"
    if marker not in name or "/src/" not in name:
        continue
    try:
        crate = name.split("crates/", 1)[1].split("/", 1)[0]
    except IndexError:
        continue
    s = f["summary"]
    lc, lcovd = s["lines"]["count"], s["lines"]["covered"]
    rc, rcovd = s["regions"]["count"], s["regions"]["covered"]
    fc, fcovd = s["functions"]["count"], s["functions"]["covered"]
    c, covd = per.get(crate, (0, 0))
    per[crate] = (c + lc, covd + lcovd)
    f_lines += lc
    f_covered += lcovd
    f_regions += rc
    f_regions_covered += rcovd
    f_funcs += fc
    f_funcs_covered += fcovd

ws_line = (100.0 * f_covered / f_lines) if f_lines else 0.0
ws_region = (100.0 * f_regions_covered / f_regions) if f_regions else 0.0
ws_func = (100.0 * f_funcs_covered / f_funcs) if f_funcs else 0.0

floors = cfg["thresholds"]["per_crate_line"]
rows = []
failed = []
for crate in sorted(floors):
    floor = floors[crate]
    count, covered = per.get(crate, (0, 0))
    pct = (100.0 * covered / count) if count else 0.0
    if floor == 0:
        rows.append({"crate": crate, "lines": count, "covered": covered,
                     "percent": round(pct, 2), "floor": floor,
                     "status": "information"})
        continue
    ok = pct >= floor
    rows.append({"crate": crate, "lines": count, "covered": covered,
                 "percent": round(pct, 2), "floor": floor,
                 "status": "pass" if ok else "fail"})
    if not ok:
        failed.append(crate)

ws_floor = cfg["thresholds"]["workspace_line"]
ws_ok = ws_line >= ws_floor
if not ws_ok:
    failed.append("workspace")

warn_floor = cfg.get("warn_only", {}).get("workspace_region", 0)
region_warn = ws_region < warn_floor

result = {
    "workspace_line": round(ws_line, 2),
    "workspace_lines": f_lines,
    "workspace_covered": f_covered,
    "workspace_floor": ws_floor,
    "workspace_status": "pass" if ws_ok else "fail",
    "workspace_region": round(ws_region, 2),
    "workspace_region_warn_floor": warn_floor,
    "workspace_region_warn": region_warn,
    "workspace_functions": round(ws_func, 2),
    "llvm_totals": llvm_totals,
    "per_crate": rows,
    "failed": failed,
    "verdict": "pass" if not failed else "fail",
}
json.dump(result, open(out_path, "w"), indent=2)
print(json.dumps(result, indent=2))
PY

VERDICT="$(python3 - "$GATE_OUT" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["verdict"])
PY
)"

# Revision-pinned metadata. Values pass through the environment so
# python json encoding escapes toolchain/revision strings; no shell
# interpolation lands inside JSON literals.
REVISION="$REVISION" DIRTY="$DIRTY" TOOLCHAIN="$TOOLCHAIN" STAMP="$STAMP" THRESHOLDS_FILE="$THRESHOLDS" python3 - "$GATE_OUT" <<'PY' > "$OUT_DIR/meta.json"
import json, sys, os
gate = json.load(open(sys.argv[1]))
thresholds_path = os.environ["THRESHOLDS_FILE"]
meta = {
    "schema": "coverage-bundle/1",
    "revision": os.environ["REVISION"],
    "dirty": (os.environ.get("DIRTY", "false") == "true"),
    "toolchain": os.environ.get("TOOLCHAIN", "unknown"),
    "collected_at": os.environ.get("STAMP", ""),
    "thresholds_file": thresholds_path,
    "thresholds": json.load(open(thresholds_path))["thresholds"],
    "verdict": gate["verdict"],
    "workspace_line": gate["workspace_line"],
    "workspace_region": gate["workspace_region"],
}
print(json.dumps(meta, indent=2))
PY

# Human summary for step summary and release review attachment.
{
  echo "# Coverage bundle"
  echo ""
  echo "- Revision: \`$REVISION\` (dirty: $DIRTY)"
  echo "- Toolchain: $TOOLCHAIN"
  echo "- Collected: $STAMP"
  echo "- Verdict: \`$VERDICT\`"
  echo ""
  echo "## Workspace"
  echo ""
  python3 - "$GATE_OUT" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
print(f"- Line (filtered crates/*/src): {g['workspace_line']}% (floor {g['workspace_floor']}%) status {g['workspace_status']}")
print(f"- Lines counted: {g.get('workspace_lines', '?')}, covered: {g.get('workspace_covered', '?')}")
print(f"- Region (filtered): {g['workspace_region']}% (warn floor {g['workspace_region_warn_floor']}%) warn={g['workspace_region_warn']}")
print(f"- Functions (filtered): {g['workspace_functions']}% (informational)")
llvm = g.get("llvm_totals")
if llvm:
    print(f"- Unfiltered llvm-cov totals (informational): line {llvm.get('lines')}% region {llvm.get('regions')}% functions {llvm.get('functions')}%")
PY
  echo ""
  echo "## Per-crate line coverage"
  echo ""
  echo "| Crate | Lines | Covered | Percent | Floor | Status |"
  echo "|---|---|---|---|---|---|"
  python3 - "$GATE_OUT" <<'PY'
import json, sys
g = json.load(open(sys.argv[1]))
for r in g["per_crate"]:
    print(f"| {r['crate']} | {r['lines']} | {r['covered']} | {r['percent']}% | {r['floor']}% | {r['status']} |")
PY
  echo ""
  echo "## Reproduce"
  echo ""
  echo '```bash'
  echo "git rev-parse HEAD # must match revision above, clean tree"
  echo "scripts/coverage.sh"
  echo '```'
  echo ""
  echo "- Full data: \`coverage.json\` (llvm-cov JSON), \`lcov.info\`"
  echo "- Gate inputs: \`$THRESHOLDS\`, gate output \`gate.json\`, pins \`meta.json\`"
} > "$OUT_DIR/summary.md"
cat "$OUT_DIR/summary.md"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$OUT_DIR/summary.md" >> "$GITHUB_STEP_SUMMARY"
fi

echo "bundle: $OUT_DIR"
if [[ "$VERDICT" != "pass" ]]; then
  # Calibration seam: first main runs may observe real coverage below the
  # starter floors. COVERAGE_WARN_ONLY=1 records the failing bundle and
  # exits 0 for observation without changing the default block behavior.
  if [[ "${COVERAGE_WARN_ONLY:-0}" == "1" ]]; then
    echo "coverage gate FAILED but COVERAGE_WARN_ONLY=1, exiting 0 for calibration (see $GATE_OUT)" >&2
    exit 0
  fi
  echo "coverage gate FAILED (see $GATE_OUT)" >&2
  exit 1
fi
echo "coverage gate passed"
