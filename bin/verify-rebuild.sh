#!/usr/bin/env bash
#
# Rebuild a submitted ZIP from an export of its own source, and assert EXACTLY
# how the result may differ.
#
#   bin/verify-rebuild.sh --slug rapls-passkey --zip ../rapls-passkey.zip [--src <dir>]
#
# WHY THIS EXISTS (V87-01). The bundle's README said the build is reproducible
# and that the rebuilt digest "equals the digest above", while the TEST-LOG in
# the same submission said DIFFER for both plugins. Both statements were
# published together. The honest position is narrower and worth stating
# precisely: a rebuild from a git checkout is deterministic, and a rebuild from
# an export WITHOUT git metadata differs in two files, for two reasons that are
# about the checkout rather than about the code:
#
#   build-manifest.json            source_dirty is "unknown" instead of "false",
#                                  because there is no git to ask. Guessing
#                                  "false" is what V41 removed.
#   vendor/composer/installed.php  the ROOT package's pretty_version, version
#                                  and reference. This file is loaded by the
#                                  autoloader — it is generated PHP, not a
#                                  document — so the difference is named field
#                                  by field rather than waved through.
#
# "Only two files" is not a thing to observe once and write down; it is a claim,
# and this is the check. Anything else differing, or a different field inside
# those two, fails.
#
# Lives in bin/ (never shipped).
set -euo pipefail

SLUG=""
ZIP=""
SRC=""
PHP_BIN="${PHP:-php}"
while [ $# -gt 0 ]; do
	case "$1" in
		--slug) SLUG="$2"; shift 2 ;;
		--zip)  ZIP="$2";  shift 2 ;;
		--src)  SRC="$2";  shift 2 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGINS="$(cd "$ROOT/.." && pwd)"
[ -n "$SLUG" ] || { echo "--slug is required" >&2; exit 2; }
[ -n "$ZIP" ]  || ZIP="$PLUGINS/$SLUG.zip"
[ -n "$SRC" ]  || SRC="$PLUGINS/$SLUG"
[ -f "$ZIP" ]  || { echo "no such ZIP: $ZIP" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The three values a reproducer is told to pass, read out of the artifact.
manifest_value() {
	unzip -p "$ZIP" "$SLUG/build-manifest.json" | "$PHP_BIN" -r \
		'$j = json_decode(stream_get_contents(STDIN), true); echo (string) ($j[$argv[1]] ?? "");' "$1"
}
EPOCH="$(manifest_value source_date_epoch)"
COMMIT="$(manifest_value source_commit)"
TREE="$(manifest_value source_tree)"
for pair in "source_date_epoch:$EPOCH" "source_commit:$COMMIT" "source_tree:$TREE"; do
	[ -n "${pair#*:}" ] || { echo "the ZIP's build-manifest.json has no ${pair%%:*}" >&2; exit 1; }
done

# An export with NO git metadata — which is what the verification bundle ships,
# and the case the claim is about.
mkdir -p "$WORK/src"
( cd "$SRC" && git archive --format=tar "$COMMIT" ) | ( cd "$WORK/src" && tar -xf - )
cp -R "$SRC/vendor" "$WORK/src/vendor"
cp "$SRC/bin/php-scoper.phar" "$WORK/src/bin/" 2>/dev/null || true
[ -d "$WORK/src/.git" ] && { echo "the export carries git metadata; that is not the case under test" >&2; exit 1; }

( cd "$WORK/src" && SOURCE_DATE_EPOCH="$EPOCH" SOURCE_COMMIT="$COMMIT" SOURCE_TREE="$TREE" \
	PHP="$PHP_BIN" bash bin/build-dist.sh ) > "$WORK/build.log" 2>&1 || {
	echo "the export could not be rebuilt at all:" >&2
	tail -5 "$WORK/build.log" >&2
	exit 1
}
REBUILT="$WORK/$SLUG.zip"
[ -f "$REBUILT" ] || { echo "the rebuild produced no ZIP" >&2; tail -5 "$WORK/build.log" >&2; exit 1; }

A="$(shasum -a 256 "$REBUILT" | cut -d' ' -f1)"
B="$(shasum -a 256 "$ZIP" | cut -d' ' -f1)"
echo "  ${SLUG}: rebuilt ${A}"
echo "  ${SLUG}: shipped ${B}"
if [ "$A" = "$B" ]; then
	echo "  ${SLUG}: identical"
	exit 0
fi

mkdir -p "$WORK/a" "$WORK/b"
( cd "$WORK/a" && unzip -q "$REBUILT" )
( cd "$WORK/b" && unzip -q "$ZIP" )

# EXACTLY these two paths, and nothing else.
# diff exits 1 when it finds differences, which is the case this runs in — and
# with pipefail that would end the script before the interesting part.
DIFFERING="$( cd "$WORK" && { diff -rq a b 2>/dev/null || true; } | sed -n 's/^Files a\/\(.*\) and b\/.* differ$/\1/p' | sort )"
ONLY_IN="$( cd "$WORK" && { diff -rq a b 2>/dev/null || true; } | grep -c '^Only in' || true )"
EXPECTED="$( printf '%s/build-manifest.json\n%s/vendor/composer/installed.php\n' "$SLUG" "$SLUG" | sort )"
if [ "$ONLY_IN" != "0" ]; then
	echo "  ${SLUG}: a file exists on one side only — the rebuild is not what this claim allows" >&2
	( cd "$WORK" && { diff -rq a b || true; } | grep '^Only in' | sed 's/^/    /' >&2 ) || true
	exit 1
fi
if [ "$DIFFERING" != "$EXPECTED" ]; then
	echo "  ${SLUG}: the set of differing files is not the one this claim allows" >&2
	echo "    allowed:" >&2; printf '%s\n' "$EXPECTED" | sed 's/^/      /' >&2
	echo "    found:"   >&2; printf '%s\n' "$DIFFERING" | sed 's/^/      /' >&2
	exit 1
fi

# And inside those two, exactly these fields.
"$PHP_BIN" -r '
	list($slug, $a, $b) = array_slice($argv, 1);
	$bad = array();

	// build-manifest.json: source_dirty only, and only false <-> unknown.
	$ma = json_decode((string) file_get_contents("$a/$slug/build-manifest.json"), true);
	$mb = json_decode((string) file_get_contents("$b/$slug/build-manifest.json"), true);
	if (!is_array($ma) || !is_array($mb)) { $bad[] = "build-manifest.json is not JSON on one side"; }
	else {
		foreach (array_unique(array_merge(array_keys($ma), array_keys($mb))) as $k) {
			if (($ma[$k] ?? null) === ($mb[$k] ?? null)) { continue; }
			if ("source_dirty" !== $k) { $bad[] = "build-manifest.json: {$k} differs, which this claim does not allow"; continue; }
			$pair = array((string) ($ma[$k] ?? ""), (string) ($mb[$k] ?? ""));
			sort($pair);
			if (array("false", "unknown") !== $pair) { $bad[] = "build-manifest.json: source_dirty is " . implode(" vs ", $pair) . ", not false vs unknown"; }
		}
	}

	// installed.php: the ROOT package'"'"'s three values, in both places it is
	// described. Compared after the same normalisation vendor-digest.php applies,
	// so anything else in the file — every line of code in it — must match.
	$norm = static function ($body) {
		$blank = static function ($body, $marker) {
			$at = strpos($body, $marker);
			while (false !== $at) {
				$open = strpos($body, "(", $at); $depth = 0; $end = $open;
				for ($i = $open, $n = strlen($body); $i < $n; $i++) {
					if ("(" === $body[$i]) { $depth++; }
					elseif (")" === $body[$i]) { $depth--; if (0 === $depth) { $end = $i; break; } }
				}
				$block = substr($body, $at, $end - $at + 1);
				$fixed = preg_replace("/(\x27(?:pretty_version|version|reference)\x27\s*=>\s*)(?:NULL|null|\x27[^\x27]*\x27)/", "\$1<volatile>", $block);
				$body  = substr($body, 0, $at) . $fixed . substr($body, $end + 1);
				$at    = strpos($body, $marker, $at + strlen($fixed));
			}
			return $body;
		};
		$body = $blank($body, "\x27root\x27 => array(");
		if (preg_match("/\x27root\x27 => array\(\s*\x27name\x27 => \x27([^\x27]+)\x27/", $body, $nm)) {
			$body = $blank($body, "\x27" . $nm[1] . "\x27 => array(");
		}
		return $body;
	};
	$ia = (string) file_get_contents("$a/$slug/vendor/composer/installed.php");
	$ib = (string) file_get_contents("$b/$slug/vendor/composer/installed.php");
	if ($norm($ia) !== $norm($ib)) {
		$bad[] = "installed.php differs in more than the root package version and reference";
	}

	if ($bad) {
		fwrite(STDERR, "  " . $slug . ": " . implode("\n  " . $slug . ": ", $bad) . "\n");
		exit(1);
	}
' "$SLUG" "$WORK/a" "$WORK/b" || exit 1

echo "  ${SLUG}: differs in exactly two files, and in exactly the fields allowed"
echo "    build-manifest.json           source_dirty: unknown (no git in an export) vs false"
echo "    vendor/composer/installed.php the root package's pretty_version, version, reference"
