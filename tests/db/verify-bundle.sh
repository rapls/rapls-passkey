#!/usr/bin/env bash
#
# Reproduce the submitted TEST-LOG.txt from the attachments, end to end.
#
# This bundle carries the full source of both plugins plus their tests, because a
# WordPress.org distribution ZIP ships runtime files only — and its bundled
# libraries are namespace-prefixed, so the tests cannot run inside it.
#
# What the script does:
#   1. verifies the SHA-256 of the two submitted plugin ZIPs
#   2. runs the smoke suites against the SOURCE tree bundled here (this is what
#      produced the submitted log)
#   3. runs the same suites INSIDE the submitted ZIPs (bin/verify-dist-functional.php)
#   4. runs bin/verify-dist.php against the submitted ZIPs — that is the check
#      that validates the shipped artifact (prefixing, class map, licences)
#   4. runs the real-database tests, if database options are given
#
#   ./verify.sh --free ../rapls-passkey.zip --pro ../rapls-passkey-pro.zip \
#       [--db-host 127.0.0.1 --db-port 3306 --db-name rapls_test \
#        --db-user root --db-pass secret] [--workers 100]
#
# Without database options the smoke suites and the distribution checks run and
# the real-database tests are skipped (and said so, loudly).
#
# Exit code 0 only if everything that ran, passed.

set -u

FREE_ZIP=""; PRO_ZIP=""
DB_HOST=""; DB_PORT="3306"; DB_NAME=""; DB_USER=""; DB_PASS=""; DB_SOCKET=""
WORKERS="100"
PHP_BIN="${PHP:-php}"

# The artifacts this bundle was built alongside. --skip-sha bypasses the check if
# you are deliberately testing a different build.
FREE_SHA="__FREE_SHA__"
PRO_SHA="__PRO_SHA__"
# The reviewer bundle bakes the submitted hashes in; in-repo runs build fresh ZIPs.
case "$FREE_SHA" in __*) CHECK_SHA=0 ;; *) CHECK_SHA=1 ;; esac

while [ $# -gt 0 ]; do
	case "$1" in
		--free) FREE_ZIP="$2"; shift 2 ;;
		--pro) PRO_ZIP="$2"; shift 2 ;;
		--db-host) DB_HOST="$2"; shift 2 ;;
		--db-port) DB_PORT="$2"; shift 2 ;;
		--db-name) DB_NAME="$2"; shift 2 ;;
		--db-user) DB_USER="$2"; shift 2 ;;
		--db-pass) DB_PASS="$2"; shift 2 ;;
		--db-socket) DB_SOCKET="$2"; shift 2 ;;
		--workers) WORKERS="$2"; shift 2 ;;
		--skip-sha) CHECK_SHA=0; shift ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

# The bundle holds a copy of each plugin's source. In the repository this script
# lives at tests/db/, so the source root is two levels up and its sibling.
BUNDLE="$(cd "$(dirname "$0")" && pwd)"
if [ ! -d "$BUNDLE/rapls-passkey" ]; then
	BUNDLE="$(cd "$BUNDLE/../../.." && pwd)"
fi
FAILED=0

command -v "$PHP_BIN" >/dev/null 2>&1 || { echo "php not found — set PHP=/path/to/php" >&2; exit 2; }
command -v unzip >/dev/null 2>&1 || { echo "unzip not found" >&2; exit 2; }

sha_of() {
	if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
	else sha256sum "$1" | awk '{print $1}'; fi
}

stage_plugin() {          # slug, zip, expected-sha
	local slug="$1" zip="$2" want="$3"
	[ -f "$zip" ] || { echo "  MISSING  $zip"; return 1; }
	local got; got="$(sha_of "$zip")"
	if [ "$CHECK_SHA" = "1" ] && [ "$got" != "$want" ]; then
		echo "  SHA MISMATCH  $zip"
		echo "      expected $want"
		echo "      actual   $got"
		return 1
	fi
	echo "  sha256 ok  $slug  $got"

	# The SOURCE tree (bundled here) is what the tests run against. The shipped ZIP
	# is the same code with its bundled libraries rewritten into a private
	# namespace by PHP-Scoper, so a test that names \Webauthn\… would not resolve
	# inside it; the ZIP is instead checked by bin/verify-dist.php, which is what
	# validates the prefixing, the class map and the third-party licences.
	cp -R "$BUNDLE/$slug" "$WORK/$slug" || return 1
	# bin/run-tests.sh looks for ../<slug>.zip to run those distribution checks.
	cp "$zip" "$WORK/$slug.zip"
	return 0
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== staging the submitted plugin ZIPs =="
[ -n "$FREE_ZIP" ] || { echo "--free <path/to/rapls-passkey.zip> is required" >&2; exit 2; }
stage_plugin rapls-passkey "$FREE_ZIP" "$FREE_SHA" || exit 1
if [ -n "$PRO_ZIP" ]; then
	stage_plugin rapls-passkey-pro "$PRO_ZIP" "$PRO_SHA" || exit 1
else
	echo "  (no --pro given: the Pro suite is skipped)"
fi
echo

echo "== smoke suites (source tree) + distribution checks (submitted ZIPs) =="
for slug in rapls-passkey rapls-passkey-pro; do
	[ -d "$WORK/$slug" ] || continue
	( cd "$WORK/$slug" && PHP="$PHP_BIN" bash bin/run-tests.sh ) || FAILED=1
done
echo

# The same suites again, but executed INSIDE the submitted ZIP: the artifact is
# extracted and the tests are run against the code it actually contains, after
# PHP-Scoper has rewritten the bundled libraries. This is what shows the shipped
# build behaves like the source it was built from, rather than merely having the
# right shape. Suites that name those libraries by their original names are
# skipped and listed — they cannot run in a scoped build by construction.
echo "== the SHIPPED code, exercised (submitted ZIPs) =="
for slug in rapls-passkey rapls-passkey-pro; do
	[ -d "$WORK/$slug" ] || continue
	"$PHP_BIN" "$WORK/rapls-passkey/bin/verify-dist-functional.php" "$WORK/$slug.zip" \
		--tests "$WORK/$slug/tests" --sibling "$WORK/rapls-passkey.zip" || FAILED=1
done
echo

if [ -z "$DB_NAME" ]; then
	echo "== real-database tests: SKIPPED (no --db-name given) =="
	echo "   The cap, quota and attempt-limit guarantees are enforced by database"
	echo "   constraints, so they are NOT covered by the run above. Pass the"
	echo "   database options to exercise them."
else
	# An array, so a path containing spaces survives.
	if [ -n "$DB_SOCKET" ]; then
		DB_ARGS=( "--socket=$DB_SOCKET" )
	else
		DB_ARGS=( "--host=$DB_HOST" "--port=$DB_PORT" )
	fi
	DB_ARGS+=( "--db=$DB_NAME" "--user=$DB_USER" "--pass=$DB_PASS" )
	cd "$WORK/rapls-passkey"
	for mode in default found_rows; do
		echo "== real-database tests ($mode connection flags) =="
		if [ "$mode" = "found_rows" ]; then export RAPLS_CLIENT_FOUND_ROWS=1; else unset RAPLS_CLIENT_FOUND_ROWS; fi
		"$PHP_BIN" tests/db/integration.php "${DB_ARGS[@]}" --workers=20 || FAILED=1
		"$PHP_BIN" tests/db/concurrency.php "${DB_ARGS[@]}" --workers="$WORKERS" || FAILED=1
		echo
	done
	unset RAPLS_CLIENT_FOUND_ROWS
fi

echo
if [ "$FAILED" = "0" ]; then
	echo "RESULT: PASS"
else
	echo "RESULT: FAIL"
fi
exit "$FAILED"
