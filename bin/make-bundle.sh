#!/usr/bin/env bash
#
# Assemble the verification bundle (rapls-passkey-tests.zip) and the submission
# archive that carries it.
#
#   bin/make-bundle.sh [--out /path/to/plugins-dir] [--ci-artifacts /path/to/json-dir]
#
# The bundle is built from an ALLOWLIST — `git ls-files` plus `vendor/`, which is
# generated rather than tracked. Copying the working directory instead is how a
# local editor's settings file, with machine paths and database credentials in it,
# ended up in a bundle sent for review (V34-05). Nothing untracked is included
# unless it is named here.
#
# Lives in bin/ (never shipped).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGINS="$(cd "$ROOT/.." && pwd)"
CI_ARTIFACTS=""

while [ $# -gt 0 ]; do
	case "$1" in
		--out) PLUGINS="$2"; shift 2 ;;
		--ci-artifacts) CI_ARTIFACTS="$2"; shift 2 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

FREE="$PLUGINS/rapls-passkey"
PRO="$PLUGINS/rapls-passkey-pro"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Never in the bundle, whatever git says: the live licence configuration and the
# licence data hold secrets.
SECRETS=(
	"tools/license-server/rpls-license-config.php"
	"tools/license-server/rpls-license-data.json"
)

stage_plugin() {
	local src="$1" slug="$2" dest="$STAGE/$2"
	[ -d "$src" ] || return 0

	mkdir -p "$dest"
	# Tracked files only.
	( cd "$src" && git ls-files -z ) | while IFS= read -r -d '' file; do
		for secret in "${SECRETS[@]}"; do
			[ "$file" = "$secret" ] && continue 2
		done
		mkdir -p "$dest/$(dirname "$file")"
		cp "$src/$file" "$dest/$file"
	done

	# vendor/ is generated, not tracked, and the suites need it.
	if [ -d "$src/vendor" ]; then
		rsync -a --exclude '.git' "$src/vendor/" "$dest/vendor/"
	fi

	# The scoper PHAR is 8 MB of third-party binary; the build script fetches it.
	rm -f "$dest/bin/php-scoper.phar"
}

stage_plugin "$FREE" rapls-passkey
stage_plugin "$PRO" rapls-passkey-pro

# The reproduction script, with the digests of the ZIPs it is meant to check.
FREE_SHA="$(shasum -a 256 "$PLUGINS/rapls-passkey.zip" | cut -d' ' -f1)"
PRO_SHA="$(shasum -a 256 "$PLUGINS/rapls-passkey-pro.zip" | cut -d' ' -f1)"
sed -e "s/__FREE_SHA__/$FREE_SHA/" -e "s/__PRO_SHA__/$PRO_SHA/" \
	"$FREE/tests/db/verify-bundle.sh" > "$STAGE/verify.sh"
chmod +x "$STAGE/verify.sh"

cp "$PLUGINS/E2E-TESTING.md" "$STAGE/" 2>/dev/null || true
[ -f "$PLUGINS/BUNDLE-README.md" ] && cp "$PLUGINS/BUNDLE-README.md" "$STAGE/README.md"

if [ -n "$CI_ARTIFACTS" ] && [ -d "$CI_ARTIFACTS" ]; then
	mkdir -p "$STAGE/ci-artifacts"
	find "$CI_ARTIFACTS" -name '*.json' -exec cp {} "$STAGE/ci-artifacts/" \;
fi

# Refuse to ship anything that looks like machine-local editor state or a secret.
BAD="$(find "$STAGE" \( -name 'settings.local.json' -o -name '.env' -o -name 'rpls-license-data.json' -o -name 'rpls-license-config.php' \) -print)"
if [ -n "$BAD" ]; then
	echo "refusing to build: local or secret files in the bundle:" >&2
	echo "$BAD" >&2
	exit 1
fi
if grep -rlE '[a-f0-9]{128}' "$STAGE" >/dev/null 2>&1; then
	echo "refusing to build: something in the bundle looks like a secret key" >&2
	grep -rlE '[a-f0-9]{128}' "$STAGE" >&2
	exit 1
fi

ZIP="$PLUGINS/rapls-passkey-tests.zip"
rm -f "$ZIP"
( cd "$STAGE" && find . -print | LC_ALL=C sort | zip -qX "$ZIP" -@ )

echo "Built: $ZIP"
echo "  files: $(unzip -l "$ZIP" | tail -1 | awk '{print $2}')"
echo "  free zip: $FREE_SHA"
echo "  pro zip:  $PRO_SHA"
