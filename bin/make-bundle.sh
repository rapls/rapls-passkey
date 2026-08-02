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
# Reading the artifacts' provenance needs a JSON parser; php is already required
# to build a package at all. Override with PHP=/path/to/php, as the other scripts do.
PHP_BIN="${PHP:-php}"

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

# THE RELEASE METADATA MUST NAME THE ARTIFACT GOING INTO THIS BUNDLE (V61-01).
#
# update-info.json is written by hand after the build, and a release once went
# out announcing 0.14.63 over a 0.14.62 ZIP because a shell chain silently
# skipped the version bump. bin/verify-dist.php compares the version and the
# sequence; it deliberately does NOT compare the digest, because any rebuild is
# a different artifact by design. Here is the one place where the digest IS a
# release property: this bundle is the thing being submitted, and the metadata
# has to describe the ZIP inside it.
# MISSING IS A FAILURE (V62-09). This used to run only when both files existed,
# so a misplaced update-info.json skipped the check that exists to catch a
# misplaced update-info.json.
if [ -f "$PLUGINS/rapls-passkey-pro.zip" ] && [ ! -f "$PRO/tools/license-server/update-info.json" ]; then
	echo "refusing to build: a Pro ZIP is being bundled but tools/license-server/update-info.json is missing (V62-09)" >&2
	exit 1
fi
if [ -f "$PRO/tools/license-server/update-info.json" ] && [ -f "$PLUGINS/rapls-passkey-pro.zip" ]; then
	PRO_ZIP_VER="$(unzip -p "$PLUGINS/rapls-passkey-pro.zip" rapls-passkey-pro/rapls-passkey-pro.php 2>/dev/null |
		sed -n 's/^[[:space:]]*\*[[:space:]]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -1)"
	PRO_ZIP_SEQ="$(unzip -p "$PLUGINS/rapls-passkey-pro.zip" rapls-passkey-pro/rapls-passkey-pro.php 2>/dev/null |
		sed -n "s/.*RAPLS_PASSKEY_PRO_RELEASE_SEQUENCE'[[:space:]]*,[[:space:]]*\([0-9]*\).*/\1/p" | head -1)"
	INFO="$PRO/tools/license-server/update-info.json"
	INFO_VER="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INFO" | head -1)"
	INFO_SEQ="$(sed -n 's/.*"release_sequence"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$INFO" | head -1)"
	INFO_SHA="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INFO" | head -1)"

	if [ "$INFO_VER" != "$PRO_ZIP_VER" ] || [ "$INFO_SEQ" != "$PRO_ZIP_SEQ" ] || [ "$INFO_SHA" != "$PRO_SHA" ]; then
		echo "refusing to build: update-info.json does not describe the Pro ZIP (V61-01)" >&2
		echo "  ZIP:          version $PRO_ZIP_VER, sequence $PRO_ZIP_SEQ, sha $PRO_SHA" >&2
		echo "  update-info:  version $INFO_VER, sequence $INFO_SEQ, sha $INFO_SHA" >&2
		exit 1
	fi
	echo "release metadata ok: $PRO_ZIP_VER / sequence $PRO_ZIP_SEQ / $PRO_SHA"
fi
sed -e "s/__FREE_SHA__/$FREE_SHA/" -e "s/__PRO_SHA__/$PRO_SHA/" \
	"$FREE/tests/db/verify-bundle.sh" > "$STAGE/verify.sh"
chmod +x "$STAGE/verify.sh"

# NEITHER ZIP MAY COME FROM A DIRTY TREE (V69-01). build-dist.sh refuses to make
# one now, but the bundle is what goes out, and it must not be possible to put a
# ZIP in it that no commit can reproduce — including one built before that check
# existed, or with ALLOW_DIRTY_BUILD set.
for z in "$PLUGINS/rapls-passkey.zip" "$PLUGINS/rapls-passkey-pro.zip"; do
	[ -f "$z" ] || continue
	slug="$(basename "$z" .zip)"
	dirty="$(unzip -p "$z" "$slug/build-manifest.json" 2>/dev/null |
		sed -n 's/.*"source_dirty": *"\([a-z]*\)".*/\1/p' | head -1)"
	if [ "$dirty" != "false" ]; then
		echo "refusing to build: $slug.zip was built from a tree that is not clean (source_dirty: ${dirty:-absent}) — V69-01" >&2
		echo "  Commit the source and rebuild; a ZIP that cannot be reproduced from its own commit is not a release." >&2
		exit 1
	fi
done
echo "provenance ok: both ZIPs were built from a clean tree"

# THE RUNBOOK EXISTS TWICE AND MUST NOT DIFFER (V68-03). One copy ships in this
# bundle, one lives in the free plugin's docs, and the test that compares them
# SKIPS wherever only one is present — which is every path except a full source
# checkout. This is the gate that always runs: no bundle is built from a
# document that has drifted, or from a missing one.
E2E_TOP="$PLUGINS/E2E-TESTING.md"
E2E_DOC="$FREE/docs/E2E-TESTING.md"
for f in "$E2E_TOP" "$E2E_DOC"; do
	[ -f "$f" ] || { echo "refusing to build: $f is missing (V68-03)" >&2; exit 1; }
done
if [ "$(shasum -a 256 "$E2E_TOP" | cut -d' ' -f1)" != "$(shasum -a 256 "$E2E_DOC" | cut -d' ' -f1)" ]; then
	echo "refusing to build: the two copies of E2E-TESTING.md differ (V68-03)" >&2
	diff -u "$E2E_DOC" "$E2E_TOP" | head -40 >&2
	exit 1
fi
echo "runbook ok: both copies of E2E-TESTING.md agree"
cp "$E2E_TOP" "$STAGE/"
[ -f "$PLUGINS/BUNDLE-README.md" ] && cp "$PLUGINS/BUNDLE-README.md" "$STAGE/README.md"

if [ -n "$CI_ARTIFACTS" ] && [ -d "$CI_ARTIFACTS" ]; then
	mkdir -p "$STAGE/ci-artifacts"
	find "$CI_ARTIFACTS" -name '*.json' -exec cp {} "$STAGE/ci-artifacts/" \;
	# Where they came from, written here rather than described in a README that
	# outlives the run it names (V50-07).
	#
	# READ OUT OF THE ARTIFACTS, NOT ASSERTED OVER THEM (V79-04). This used to
	# write "${CI_RUN:-unknown}" — and with no --ci-run given it shipped
	# run_id "unknown" beside a reply that named a specific run, so the one
	# association the bundle exists to record was the one thing in it nobody
	# could check. The workflow stamps each result file with the run that wrote
	# it; this reads them back, requires every file to name the SAME run, and
	# refuses to build if any of them cannot say. An operator-supplied --ci-run
	# is now a cross-check, not the source.
	#
	# Two different commits, and conflating them is how a bundle claims to have
	# tested code it did not ship. The ZIP's commit is read out of the artifact
	# itself (build-manifest.json) because that is what a reproducer must check
	# out; the repository head is what CI ran. A release-metadata commit made
	# after the build makes the two differ legitimately.
	zip_commit() {
		unzip -p "$1" "$2/build-manifest.json" 2>/dev/null |
			sed -n 's/.*"source_commit"[^"]*"\([0-9a-f]*\)".*/\1/p' | head -1
	}

	PROV="$( "$PHP_BIN" -r '
		$dir = $argv[1];
		$claimed = isset($argv[2]) ? trim($argv[2]) : "";
		$files = glob($dir . "/*.json");
		sort($files);
		$runs = array();
		$shas = array();
		$rows = array();
		$mute = array();
		foreach ($files as $f) {
			if ("PROVENANCE.json" === basename($f)) { continue; }
			$d  = json_decode((string) file_get_contents($f), true);
			$ci = is_array($d) && isset($d["ci"]) && is_array($d["ci"]) ? $d["ci"] : array();
			$id = isset($ci["run_id"]) ? (string) $ci["run_id"] : "";
			if ("" === $id || "unknown" === $id) { $mute[] = basename($f); }
			else { $runs[$id] = true; $shas[(string) ($ci["sha"] ?? "")] = true; }
			$rows[] = array(
				"file"    => basename($f),
				"sha256"  => hash_file("sha256", $f),
				"job"     => (string) ($ci["job"] ?? ""),
				"matrix"  => (string) ($ci["matrix"] ?? ""),
				"attempt" => (string) ($ci["run_attempt"] ?? ""),
				"passed"  => (bool) (is_array($d) && ! empty($d["passed"])),
			);
		}
		if ($mute) {
			fwrite(STDERR, "refusing to build: these CI results do not say which run produced them: " . implode(", ", $mute) . "\n");
			fwrite(STDERR, "  (re-download them from a run of the workflow that stamps them — see .github/workflows/tests.yml)\n");
			exit(1);
		}
		if (1 !== count($runs)) {
			fwrite(STDERR, "refusing to build: the CI results come from more than one run: " . implode(", ", array_keys($runs)) . "\n");
			exit(1);
		}
		$run = (string) array_key_first($runs);
		if ("" !== $claimed && $claimed !== $run) {
			fwrite(STDERR, "refusing to build: --ci-run says {$claimed}, the results say {$run}\n");
			exit(1);
		}
		echo json_encode(array(
			"run_id"    => $run,
			"run_sha"   => (string) array_key_first($shas),
			"artifacts" => $rows,
		));
	' "$STAGE/ci-artifacts" "${CI_RUN:-}" )" || exit 1

	RUN_ID="$( printf '%s' "$PROV" | sed -n 's/.*"run_id":"\([0-9]*\)".*/\1/p' )"
	printf '{\n  "run_id": "%s",\n  "run_url": "https://github.com/rapls/rapls-passkey/actions/runs/%s",\n  "run_sha": %s,\n  "free_zip_commit": "%s",\n  "pro_zip_commit": "%s",\n  "free_head": "%s",\n  "pro_head": "%s",\n  "files": %s,\n  "bundled_at": "%s",\n  "artifacts": %s\n}\n' \
		"$RUN_ID" "$RUN_ID" \
		"$( printf '%s' "$PROV" | sed -n 's/.*\("run_sha":"[0-9a-f]*"\).*/\1/p' | sed 's/"run_sha"://' )" \
		"$( zip_commit "$PLUGINS/rapls-passkey.zip" rapls-passkey )" \
		"$( zip_commit "$PLUGINS/rapls-passkey-pro.zip" rapls-passkey-pro )" \
		"$( cd "$FREE" && git rev-parse HEAD )" \
		"$( cd "$PRO" && git rev-parse HEAD 2>/dev/null || echo unknown )" \
		"$( ls -1 "$STAGE/ci-artifacts" | grep -c '\.json$' )" \
		"$( date -u +%Y-%m-%dT%H:%M:%SZ )" \
		"$( printf '%s' "$PROV" | "$PHP_BIN" -r 'echo json_encode(json_decode(stream_get_contents(STDIN), true)["artifacts"], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);' )" \
		> "$STAGE/ci-artifacts/PROVENANCE.json"
	echo "ci provenance ok: run $RUN_ID, $( ls -1 "$STAGE/ci-artifacts" | grep -c '\.json$' ) files, each naming it"
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
