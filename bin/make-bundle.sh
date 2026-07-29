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
CI_RUN=""

while [ $# -gt 0 ]; do
	case "$1" in
		--out) PLUGINS="$2"; shift 2 ;;
		--ci-artifacts) CI_ARTIFACTS="$2"; shift 2 ;;
		--ci-run) CI_RUN="$2"; shift 2 ;;
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
	# Where they came from, written here rather than described in a README that
	# outlives the run it names (V50-07). The result files carry no run id of
	# their own, so this is the only place the association is recorded.
	printf '{\n  "run_id": "%s",\n  "run_url": "https://github.com/rapls/rapls-passkey/actions/runs/%s",\n  "free_commit": "%s",\n  "pro_commit": "%s",\n  "files": %s,\n  "bundled_at": "%s"\n}\n' \
		"${CI_RUN:-unknown}" "${CI_RUN:-unknown}" \
		"$( cd "$FREE" && git rev-parse HEAD )" \
		"$( cd "$PRO" && git rev-parse HEAD 2>/dev/null || echo unknown )" \
		"$( ls -1 "$STAGE/ci-artifacts" | grep -c '\.json$' )" \
		"$( date -u +%Y-%m-%dT%H:%M:%SZ )" \
		> "$STAGE/ci-artifacts/PROVENANCE.json"
fi

# Refuse to ship machine-local state or anything shaped like a credential. This
# is a net, not a proof — a dedicated scanner (gitleaks and friends) is the tool
# for that — but it catches the shapes that actually turn up in a tree like this,
# and it fails the build rather than warning.
# fido-mds-roots.pem is the FIDO Alliance's PUBLIC root certificates, shipped on
# purpose; it is named here so the exception is visible rather than a hole in the
# pattern.
BAD="$(find "$STAGE" \( \
	-name 'settings.local.json' -o -name '.env' -o -name '.env.*' \
	-o -name 'rpls-license-data.json' -o -name 'rpls-license-config.php' \
	-o -name 'auth.json' -o -name '.npmrc' -o -name '.netrc' \
	-o -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.p12' -o -name '*.pfx' \
	-o \( -name '*.pem' ! -name 'fido-mds-roots.pem' \) \
	-o -name 'credentials' -o -name 'credentials.json' -o -name '*.kdbx' \
	\) -print)"
if [ -n "$BAD" ]; then
	echo "refusing to build: local or secret-bearing files in the bundle:" >&2
	echo "$BAD" >&2
	exit 1
fi

# Content shapes. Deliberately aimed at SECRETS, not at every long string: a
# 64-character hex value is an Ed25519 PUBLIC key or a SHA-256 digest and appears
# all over this tree legitimately, while 128 hex characters is the size of an
# Ed25519 secret. Anything wider than this needs a real scanner (gitleaks or
# similar); this is the last line of a checklist, not a substitute for one.
PATTERNS=(
	'[0-9a-fA-F]{128,}'
	'-----BEGIN [A-Z ]*PRIVATE KEY-----'
	'gh[pousr]_[A-Za-z0-9]{20,}'
	'github_pat_[A-Za-z0-9_]{20,}'
	'AKIA[0-9A-Z]{16}'
	'aws_secret_access_key'
	'xox[abprs]-[A-Za-z0-9-]{10,}'
	'-----BEGIN PGP PRIVATE KEY BLOCK-----'
)
# Files that legitimately contain long hex or base64: dependency locks (integrity
# hashes), our own manifest of digests, and the CI result JSON. Named here so the
# allowlist is a decision rather than a silent exception.
ALLOW='composer.lock|build-manifest.json|ci-artifacts/|SHA256SUMS|package-lock.json|fido-mds-roots.pem|make-bundle.sh'
FOUND=""
for pattern in "${PATTERNS[@]}"; do
	HITS="$(grep -rlE "$pattern" "$STAGE" 2>/dev/null | grep -vE "$ALLOW" || true)"
	[ -n "$HITS" ] && FOUND="$FOUND$HITS"$'\n'
done
if [ -n "$(printf '%s' "$FOUND" | tr -d '[:space:]')" ]; then
	echo "refusing to build: something in the bundle is shaped like a credential:" >&2
	printf '%s' "$FOUND" >&2
	echo "  (if it is legitimate, add it to ALLOW in bin/make-bundle.sh — deliberately)" >&2
	exit 1
fi

ZIP="$PLUGINS/rapls-passkey-tests.zip"
rm -f "$ZIP"
( cd "$STAGE" && find . -print | LC_ALL=C sort | zip -qX "$ZIP" -@ )

echo "Built: $ZIP"
echo "  files: $(unzip -l "$ZIP" | tail -1 | awk '{print $2}')"
echo "  free zip: $FREE_SHA"
echo "  pro zip:  $PRO_SHA"
