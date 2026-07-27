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
	code=$?
	name="$(basename "$t")"

	# Three independent conditions, because any one of them alone can be fooled:
	#   - a non-zero exit says the process itself failed (or the test called exit(1)
	#     without printing anything we would recognise),
	#   - the FAIL / Fatal / Parse markers catch a test that reports failure and
	#     exits 0 anyway,
	#   - and the summary line must be there and must say zero failures, so a file
	#     that asserts nothing — or dies before its last line — cannot pass.
	summary="$(printf '%s' "$out" | grep -oE '[0-9]+ passed, [0-9]+ failed' | tail -1)"
	reason=""
	if [ "$code" -ne 0 ]; then
		reason="exit code ${code}"
	elif printf '%s' "$out" | grep -qE 'FAIL|Fatal error|Parse error'; then
		reason="reported a failure"
	elif [ -z "$summary" ]; then
		reason="no assertion summary (the file asserted nothing, or stopped early)"
	elif ! printf '%s' "$summary" | grep -qE ', 0 failed$'; then
		reason="$summary"
	fi

	if [ -n "$reason" ]; then
		bad=$((bad+1))
		echo "  FAIL  ${name}  (${reason})"
		printf '%s\n' "$out" | grep -E 'FAIL|Fatal error|Parse error' | sed 's/^/          /' | head -5
	else
		ok=$((ok+1))
		echo "  PASS  ${name}  (${summary})"
	fi
done
echo "  -> ${ok}/${files} smoke files passed"

# A suite that found no files has not passed — it has not run. This is the state
# a bad path, a failed checkout or a renamed directory produces, and it must not
# look like success.
if [ "$files" -eq 0 ]; then
	echo "  -> NO TEST FILES FOUND in ${ROOT}/tests — refusing to report success"
	bad=$((bad+1))
fi

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
