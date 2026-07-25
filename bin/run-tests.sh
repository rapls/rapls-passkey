#!/usr/bin/env bash
#
# Run the plugin's standalone smoke tests (and, when a built ZIP is present, the
# final-artifact distribution check). Prints a per-file PASS/FAIL manifest and
# exits non-zero on any failure — suitable as a CI gate.
#
#   bin/run-tests.sh
#
# Override the PHP binary with PHP=/path/to/php (e.g. Local by Flywheel bundles
# its own). Lives in bin/ (never shipped).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SLUG="$(basename "$ROOT")"
PHP_BIN="${PHP:-php}"

command -v "$PHP_BIN" >/dev/null 2>&1 || { echo "php not found — set PHP=/path/to/php" >&2; exit 1; }

echo "== ${SLUG}: smoke tests =="
files=0; ok=0; bad=0
for t in "$ROOT"/tests/smoke-*.php; do
	[ -e "$t" ] || continue
	files=$((files+1))
	out="$("$PHP_BIN" "$t" 2>&1)"
	if printf '%s' "$out" | grep -qE 'FAIL|Fatal error|Parse error'; then
		bad=$((bad+1))
		echo "  FAIL  $(basename "$t")"
		printf '%s\n' "$out" | grep -E 'FAIL|Fatal error|Parse error' | sed 's/^/          /' | head -5
	else
		ok=$((ok+1))
		summary="$(printf '%s' "$out" | grep -oE '[0-9]+ passed' | head -1)"
		echo "  PASS  $(basename "$t")  (${summary:-ok})"
	fi
done
echo "  -> ${ok}/${files} smoke files passed"

# Final-artifact check, if the distributable ZIP has been built.
zip="$ROOT/../${SLUG}.zip"
dist_bad=0
if [ -f "$zip" ] && [ -f "$ROOT/bin/verify-dist.php" ]; then
	echo "== ${SLUG}: distribution ZIP =="
	if "$PHP_BIN" "$ROOT/bin/verify-dist.php" "$zip"; then
		echo "  -> dist verify PASS"
	else
		dist_bad=1
		echo "  -> dist verify FAIL"
	fi
else
	echo "== ${SLUG}: distribution ZIP not built (run bin/build-dist.sh to include it) =="
fi

if [ "$bad" -ne 0 ] || [ "$dist_bad" -ne 0 ]; then
	echo "RESULT: FAIL"
	exit 1
fi
echo "RESULT: PASS"
