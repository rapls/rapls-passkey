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

# A RELEASE IS BUILT FROM A COMMIT, OR IT IS NOT A RELEASE (V69-01).
#
# The manifest records source_commit and source_dirty, and a reviewer holding
# the ZIP is expected to check out that commit and rebuild it. If the tree was
# dirty, that cannot work: source_commit describes what was committed and the
# ZIP contains something else. It happened — the same version was published
# twice with different bytes, because the build ran before the last commit.
#
# Checked BEFORE Composer runs, so the answer is about the source and not about
# anything this script did to it. Explicit override for local experiments; the
# release path never sets it, and make-bundle.sh refuses a dirty manifest too.
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
	if [ -n "$(git -C "$ROOT" status --porcelain)" ] && [ "${ALLOW_DIRTY_BUILD:-}" != "1" ]; then
		echo "refusing to build: the working tree has uncommitted changes (V69-01)." >&2
		echo "  A release ZIP records source_commit, and this one could not be rebuilt from it." >&2
		echo "  Commit first, or set ALLOW_DIRTY_BUILD=1 for a throwaway build." >&2
		git -C "$ROOT" status --short >&2
		exit 1
	fi
fi

# Runtime deps ONLY — dev tooling must never end up in the shipped, scoped vendor.
"$COMPOSER_BIN" install --no-dev --optimize-autoloader

# 1) Generate an AUTHORITATIVE classmap BEFORE scoping, so PHP-Scoper rewrites the
#    class-name strings in vendor/composer/autoload_classmap.php together with the
#    code. Running dump-autoload AFTER scoping would regenerate an unscoped-PSR-4
#    classmap that SKIPS the now-prefixed vendor classes (they would never
#    autoload — the plugin would treat WebAuthn as missing).
"$COMPOSER_BIN" dump-autoload --no-dev --classmap-authoritative

# 1b) AND THE TREE THAT IS ABOUT TO BE SCOPED IS THE RECORDED ONE (V84-01).
#     Here, after composer has finished with it and before a single byte is
#     copied into the package.
# ALWAYS, NOT ONLY WHEN vendor/ WAS ALREADY THERE (V85-01). The first version
# skipped this whenever the checkout had no vendor/, on the reasoning that
# Composer had just created it from composer.lock. But composer.lock pins which
# packages and which references — it does not pin the bytes on disk, the
# executable bits, files a package ships that the lock never names, or what a
# different Composer version generates. That is provenance standing in for
# content, which is the same substitution V84-01 was about. The tree that is
# about to be scoped is compared, however it got here.
"$PHP_BIN" "$ROOT/bin/vendor-digest.php" --check || {
	echo "refusing to build: vendor/ is not the dependency tree this release recorded" >&2
	echo "  (a different Composer version can produce a different tree; that is a" >&2
	echo "   refusal on purpose — the manifest fixes the tree, not the intention)" >&2
	exit 1
}

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
# THE TRACKED TREE, AS THE COMMIT HAS IT (V71-01, V71-02).
#
# Two things have to be true at once: nothing untracked may reach the package,
# and .distignore must decide what of the tracked material is shipped. The
# previous attempt did the first by feeding `git ls-files` to `rsync
# --files-from` — and rsync does NOT apply exclude rules to files named
# explicitly that way, so .distignore stopped working entirely and the package
# gained tests/, bin/, .github/, composer.json and (on Pro) the whole licence
# server. Reproducible, and reproducibly wrong.
#
# So: materialise the commit into a temporary tree with `git archive`, and copy
# from THAT with .distignore applied normally. The exclude rules work because
# they are back to filtering a directory walk; the untracked file is gone
# because git archive never had it. src/'s non-PHP assets come from the same
# snapshot for the same reason.
TRACKED="$TMP/tracked"
mkdir -p "$TRACKED"
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
	git -C "$ROOT" archive HEAD | tar -x -C "$TRACKED"
else
	echo "build-dist: no git here — snapshotting the directory instead" >&2
	rsync -a --exclude '.git' "$ROOT/" "$TRACKED/"
fi

# Non-PHP assets bundled under src/ (e.g. FIDO MDS root certs, data files).
rsync -a --exclude='*.php' "$TRACKED/src/" "$STAGE/src/"
# Third-party LICENSE / NOTICE files in vendor/ (MIT / BSD notice retention).
rsync -a --prune-empty-dirs \
	--include='*/' \
	--include='LICENSE*' --include='License*' --include='license*' \
	--include='COPYING*' --include='COPYRIGHT*' --include='NOTICE*' \
	--exclude='*' "$ROOT/vendor/" "$STAGE/vendor/"
# The plugin's own non-src/vendor tree (data/, assets/, languages/, readme, the
# entrypoint & uninstall — which carry no scoped `use` and require scoper-autoload).
#
# FROM git ls-files, NOT FROM THE DIRECTORY (V70-02). Copying $ROOT/. swept in
# whatever happened to be lying there, and `git status --porcelain` — the clean-
# tree gate added in V69-01 — says nothing about files git has been told to
# ignore. So .ci/, .idea/, an editor's scratch file: invisible to the gate,
# copied by rsync, shipped in a package whose manifest says source_dirty false.
# The new promise is that the recorded commit reproduces the ZIP, and only
# tracked files can keep it. .distignore still applies on top, and a build from
# an export (no git) falls back to the old behaviour rather than shipping
# nothing.
rsync -a --exclude-from="$ROOT/.distignore" --exclude 'src' --exclude 'vendor' "$TRACKED/" "$STAGE/"

# Everything that goes INTO the artifact must be stated, never guessed: the same
# inputs have to produce the same bytes on someone else's machine, and a silent
# fallback to "now" would make that impossible to notice. Each of these can be
# supplied from the environment (for a build from an export with no .git); when
# neither git nor the environment can answer, the build stops.
SOURCE_EPOCH="${SOURCE_DATE_EPOCH-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)}"
SOURCE_COMMIT="${SOURCE_COMMIT-$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)}"
SOURCE_TREE="${SOURCE_TREE-$(git -C "$ROOT" rev-parse HEAD^{tree} 2>/dev/null || true)}"
if [ -z "$SOURCE_EPOCH" ] || [ -z "$SOURCE_COMMIT" ] || [ -z "$SOURCE_TREE" ]; then
	echo "build-dist: no git metadata here." >&2
	echo "  Set SOURCE_DATE_EPOCH, SOURCE_COMMIT and SOURCE_TREE to build from an export." >&2
	echo "  (Guessing them would produce an artifact nobody else can reproduce.)" >&2
	exit 1
fi

# A manifest tying the artifact to the exact source it was built from, so a
# reviewer holding only the ZIP can match it against a commit in the repository.
VERSION="$(sed -n 's/^ \* Version: *\(.*\)$/\1/p' "$ROOT/$SLUG.php" | head -1 | tr -d ' \r')"
COMMIT="$SOURCE_COMMIT"
# "false" must mean "checked and clean", not "could not check". Without git — a
# build from an export — the honest answer is that we do not know.
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
	DIRTY="$(test -n "$(git -C "$ROOT" status --porcelain)" && echo '"true"' || echo '"false"')"
else
	DIRTY='"unknown"'
fi

# Everything that determined the bytes in this ZIP, so "which inputs produced
# this artifact" can be answered from the artifact alone: the source tree as git
# sees it, the dependency lock, the transformer, and the script doing the work.
hash_of() { [ -f "$1" ] && shasum -a 256 "$1" | cut -d' ' -f1 || echo "absent"; }

# The transformer is part of the input: a different PHP-Scoper writes different
# output, so the build refuses one it does not recognise. Update this line
# deliberately when moving to a new release.
EXPECTED_SCOPER="ad8aa6987f062c2c981d876f17c8c51e68dd27505ae9d03fcb914545d2945e8e"
ACTUAL_SCOPER="$(hash_of "$SCOPER")"
if [ "$ACTUAL_SCOPER" != "$EXPECTED_SCOPER" ]; then
	echo "build-dist: unexpected php-scoper.phar" >&2
	echo "  expected $EXPECTED_SCOPER" >&2
	echo "  found    $ACTUAL_SCOPER" >&2
	echo "  Download 0.18.11 from https://github.com/humbug/php-scoper/releases, or update EXPECTED_SCOPER." >&2
	exit 1
fi
TREE_HASH="$SOURCE_TREE"
LOCK_HASH="$(hash_of "$ROOT/composer.lock")"
SCOPER_HASH="$ACTUAL_SCOPER"
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
    "php_requirement": "$(sed -n 's/^ \* Requires PHP: *\(.*\)$/\1/p' "$ROOT/$SLUG.php" | head -1 | tr -d ' \r')"
}
JSON

# A build of the same commit must produce the same bytes, so that one version
# number can only ever mean one artifact. Two things otherwise vary: the file
# timestamps the archive records, and the order entries are added in. Both are
# pinned here — every file gets the commit's own timestamp, and the entry list is
# sorted — so rebuilding the same commit is a no-op rather than a second release
# candidate. (built_at in the manifest is the commit time for the same reason.)
STAMP="$(date -u -r "$SOURCE_EPOCH" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$SOURCE_EPOCH" +%Y%m%d%H%M.%S)"
find "$STAGE" -exec touch -h -t "$STAMP" {} +

rm -f "$ZIP"
( cd "$TMP" && find "$SLUG" -print | LC_ALL=C sort | zip -qX "$ZIP" -@ )

echo "Built (scoped): $ZIP"
echo "  source commit: $COMMIT (dirty: $DIRTY)"
echo "Now verify:  $PHP_BIN bin/verify-dist.php \"$ZIP\""
