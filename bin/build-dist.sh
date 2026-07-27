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
#   - Composer on PATH (or COMPOSER_BIN=/path/to/composer.phar; needs php on PATH).
#   - PHP-Scoper as a standalone PHAR at bin/php-scoper.phar (kept OUT of the
#     shipped vendor). Download it:
#       curl -L -o bin/php-scoper.phar \
#         https://github.com/humbug/php-scoper/releases/download/0.18.11/php-scoper.phar
#     (or any newer 0.18.x). Override the location with PHP_SCOPER=/path/to.phar.
#
#   bin/build-dist.sh
#
# Verify the output with bin/verify-dist.php before shipping. Produces
# ../rapls-passkey.zip.
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
command -v "$COMPOSER_BIN" >/dev/null 2>&1 || { echo "composer not found — install it or set COMPOSER_BIN=/path/to/composer(.phar) (needs php on PATH too)" >&2; exit 1; }
if [ ! -f "$SCOPER" ]; then
	echo "php-scoper PHAR not found at: $SCOPER" >&2
	echo "  curl -L -o bin/php-scoper.phar https://github.com/humbug/php-scoper/releases/download/0.18.11/php-scoper.phar" >&2
	exit 1
fi

cd "$ROOT"

# Runtime deps ONLY — dev tooling must never end up in the shipped, scoped vendor.
"$COMPOSER_BIN" install --no-dev --optimize-autoloader

# 1) Generate an AUTHORITATIVE classmap BEFORE scoping, so PHP-Scoper rewrites the
#    class-name strings in vendor/composer/autoload_classmap.php together with the
#    code. Running dump-autoload AFTER scoping would regenerate an unscoped-PSR-4
#    classmap that SKIPS the now-prefixed vendor classes (they would never
#    autoload — the plugin would treat WebAuthn as missing).
"$COMPOSER_BIN" dump-autoload --no-dev --classmap-authoritative

# 2) Scope src + vendor + the composer autoloader into build/. Do NOT dump again.
rm -rf "$BUILD"
"$PHP_BIN" "$SCOPER" add-prefix --output-dir="$BUILD" --force --config="$ROOT/scoper.inc.php"

# 3) Stage runtime files. PHP-Scoper only copies *.php, so carry over the rest.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/$SLUG"
mkdir -p "$STAGE"
# Scoped tree (src + vendor .php, plus scoper-autoload.php / composer autoloader).
rsync -a --exclude-from="$ROOT/.distignore" "$BUILD/" "$STAGE/"
# Non-PHP assets bundled under src/ (e.g. FIDO MDS root certs, data files).
rsync -a --exclude='*.php' "$ROOT/src/" "$STAGE/src/"
# Third-party LICENSE / NOTICE files in vendor/ (MIT / BSD notice retention).
rsync -a --prune-empty-dirs \
	--include='*/' \
	--include='LICENSE*' --include='License*' --include='license*' \
	--include='COPYING*' --include='COPYRIGHT*' --include='NOTICE*' \
	--exclude='*' "$ROOT/vendor/" "$STAGE/vendor/"
# The plugin's own non-src/vendor tree (data/, assets/, languages/, readme, the
# entrypoint & uninstall — which carry no scoped `use` and require scoper-autoload).
rsync -a --exclude-from="$ROOT/.distignore" --exclude 'src' --exclude 'vendor' "$ROOT/." "$STAGE/"

# A manifest tying the artifact to the exact source it was built from, so a
# reviewer holding only the ZIP can match it against a commit in the repository.
VERSION="$(sed -n 's/^ \* Version: *\(.*\)$/\1/p' "$ROOT/$SLUG.php" | head -1 | tr -d ' \r')"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
DIRTY="$(test -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" && echo true || echo false)"

# Everything that determined the bytes in this ZIP, so "which inputs produced
# this artifact" can be answered from the artifact alone: the source tree as git
# sees it, the dependency lock, the transformer, and the script doing the work.
hash_of() { [ -f "$1" ] && shasum -a 256 "$1" | cut -d' ' -f1 || echo "absent"; }
# The commit's own time, used for every timestamp in the artifact.
SOURCE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)"
[ "$SOURCE_EPOCH" = "0" ] && SOURCE_EPOCH="$(date -u +%s)"
TREE_HASH="$(git -C "$ROOT" rev-parse HEAD^{tree} 2>/dev/null || echo unknown)"
LOCK_HASH="$(hash_of "$ROOT/composer.lock")"
SCOPER_HASH="$(hash_of "$ROOT/bin/php-scoper.phar")"
SCOPER_CONF_HASH="$(hash_of "$ROOT/scoper.inc.php")"
BUILD_HASH="$(hash_of "$ROOT/bin/build-dist.sh")"

cat > "$STAGE/build-manifest.json" <<JSON
{
    "plugin": "$SLUG",
    "version": "$VERSION",
    "source_commit": "$COMMIT",
    "source_tree": "$TREE_HASH",
    "source_dirty": $DIRTY,
    "composer_lock_sha256": "$LOCK_HASH",
    "scoper_phar_sha256": "$SCOPER_HASH",
    "scoper_config_sha256": "$SCOPER_CONF_HASH",
    "build_script_sha256": "$BUILD_HASH",
    "built_at": "$(date -u -r "$SOURCE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$SOURCE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)",
    "php": "$("$PHP_BIN" -r 'echo PHP_VERSION;')"
}
JSON

# A build of the same commit must produce the same bytes, so that one version
# number can only ever mean one artifact. Two things otherwise vary: the file
# timestamps the archive records, and the order entries are added in. Both are
# pinned here — every file gets the commit's own timestamp, and the entry list is
# sorted — so rebuilding the same commit is a no-op rather than a second release
# candidate. (built_at in the manifest is the commit time for the same reason.)
find "$STAGE" -exec touch -h -t "$(date -u -r "$SOURCE_EPOCH" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$SOURCE_EPOCH" +%Y%m%d%H%M.%S)" {} + 2>/dev/null || true

rm -f "$ZIP"
( cd "$TMP" && find "$SLUG" -print | LC_ALL=C sort | zip -qX "$ZIP" -@ )

echo "Built (scoped): $ZIP"
echo "  source commit: $COMMIT (dirty: $DIRTY)"
echo "Now verify:  $PHP_BIN bin/verify-dist.php \"$ZIP\""
