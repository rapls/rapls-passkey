#!/usr/bin/env bash
#
# Build a SCOPED WordPress.org distribution ZIP: the bundled libraries are
# rewritten into the RaplsPasskey\Vendor\ prefix with PHP-Scoper so they cannot
# collide with another plugin's copy (see docs/vendor-prefixing.md, F-12).
#
# Run the free plugin's build FIRST, then the Pro plugin's — Pro's scoping points
# the shared libraries at the free plugin's prefix.
#
# Prerequisites (one-time):
#   - Composer on PATH.
#   - PHP-Scoper as a standalone PHAR at bin/php-scoper.phar (kept OUT of the
#     shipped vendor so the tool itself is never scoped/shipped). Download it:
#       curl -L -o bin/php-scoper.phar \
#         https://github.com/humbug/php-scoper/releases/download/0.18.11/php-scoper.phar
#     (or any newer 0.18.x). Override the location with PHP_SCOPER=/path/to.phar.
#
#   bin/build-dist.sh
#
# NOTE: verify the output before shipping — see the checklist in
# docs/vendor-prefixing.md. This produces ../rapls-passkey.zip.
set -euo pipefail

SLUG="rapls-passkey"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(cd "$ROOT/.." && pwd)"       # the wp-content/plugins directory
BUILD="$ROOT/build"
ZIP="$OUT/$SLUG.zip"
SCOPER="${PHP_SCOPER:-$ROOT/bin/php-scoper.phar}"
# php / composer may not be on PATH (e.g. Local by Flywheel bundles its own PHP).
# Override with e.g. PHP=/path/to/php COMPOSER_BIN=/path/to/composer.phar.
# NOTE: do not use a plain COMPOSER env var — Composer reserves it to locate a
# composer.json, which would break the build.
PHP_BIN="${PHP:-php}"
COMPOSER_BIN="${COMPOSER_BIN:-composer}"

command -v "$PHP_BIN" >/dev/null 2>&1 || { echo "php not found — set PHP=/path/to/php or add it to PATH" >&2; exit 1; }
command -v "$COMPOSER_BIN" >/dev/null 2>&1 || { echo "composer not found — install it or set COMPOSER=/path/to/composer(.phar) (needs php on PATH too)" >&2; exit 1; }
if [ ! -f "$SCOPER" ]; then
	echo "php-scoper PHAR not found at: $SCOPER" >&2
	echo "Download it (one-time):" >&2
	echo "  curl -L -o bin/php-scoper.phar https://github.com/humbug/php-scoper/releases/download/0.18.11/php-scoper.phar" >&2
	echo "or set PHP_SCOPER=/path/to/php-scoper.phar" >&2
	exit 1
fi

cd "$ROOT"

# Runtime deps ONLY — dev tooling (php-scoper, its parser, the WP-excludes
# package) must never end up in the shipped, scoped vendor. The scoper PHAR is
# run from outside this tree, so it is not affected.
"$COMPOSER_BIN" install --no-dev --optimize-autoloader

# 1) Scope src + vendor + root files into build/.
rm -rf "$BUILD"
"$PHP_BIN" "$SCOPER" add-prefix --output-dir="$BUILD" --force --config="$ROOT/scoper.inc.php"

# 2) Regenerate a production autoloader over the scoped classes. dump-autoload
#    needs composer.json (+ lock) in the scoped tree; they are excluded from the
#    ZIP again by .distignore below.
cp composer.json "$BUILD/composer.json"
[ -f composer.lock ] && cp composer.lock "$BUILD/composer.lock"
"$COMPOSER_BIN" dump-autoload --working-dir="$BUILD" --classmap-authoritative --no-dev

# 3) Stage runtime files from the SCOPED tree (honouring .distignore) and zip.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/$SLUG"
mkdir -p "$STAGE"
rsync -a --exclude-from="$ROOT/.distignore" "$BUILD/" "$STAGE/"
# data/ and non-PHP assets are not scoped by php-scoper; copy them across as-is.
rsync -a --exclude-from="$ROOT/.distignore" --exclude 'src' --exclude 'vendor' "$ROOT/." "$STAGE/"

rm -f "$ZIP"
( cd "$TMP" && zip -rqX "$ZIP" "$SLUG" )

echo "Built (scoped): $ZIP"
echo "Verify against docs/vendor-prefixing.md before shipping."
