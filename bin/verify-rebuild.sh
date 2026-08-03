#!/usr/bin/env bash
#
# Rebuild a submitted ZIP from a copy of its own source, and assert EXACTLY how
# the result may differ.
#
#   bin/verify-rebuild.sh --slug rapls-passkey \
#       [--zip ../rapls-passkey.zip] [--src <dir>] [--scoper <php-scoper.phar>]
#
# WHY THIS EXISTS (V87-01). The bundle's README said the build is reproducible
# and that the rebuilt digest "equals the digest above", while the TEST-LOG in
# the same submission said DIFFER for both plugins. Both were published
# together. The honest position is narrower: a rebuild from a git checkout is
# deterministic, and a rebuild from a source tree WITHOUT git metadata differs
# in two files, for two reasons that are about the checkout rather than the
# code:
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
# THE SOURCE IS COPIED, NOT RE-EXPORTED (V88-01). The first version ran
# `git archive` on $SRC, which meant it could not run on the thing it is about:
# the bundle's own source has no .git and no parent repository, so the command
# in README.md died at "not a git repository". Worse, re-exporting silently
# discarded any untracked file in $SRC — so the sensitivity check that put a
# stowaway there proved nothing about the published script. What is under test
# is the DIRECTORY, whatever is in it.
#
# Lives in bin/ (never shipped).
set -euo pipefail
export LC_ALL=C

SLUG=""
ZIP=""
SRC=""
SCOPER=""
COMPARE_A=""
COMPARE_B=""
PHP_BIN="${PHP:-php}"
while [ $# -gt 0 ]; do
	case "$1" in
		--slug)   SLUG="$2";   shift 2 ;;
		--zip)    ZIP="$2";    shift 2 ;;
		--src)    SRC="$2";    shift 2 ;;
		--scoper) SCOPER="$2"; shift 2 ;;
		# The comparison on its own, over two directories that already exist.
		# It is the part with the rules in it, and a rule nobody can run on
		# demand is a rule that gets tested once by hand (V88-02).
		--compare) COMPARE_A="$2"; COMPARE_B="$3"; shift 3 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PLUGINS="$(cd "$HERE/.." && pwd)"
[ -n "$SLUG" ] || { echo "--slug is required" >&2; exit 2; }

# The comparison, as a value so it can be used twice: by --compare and by the
# rebuild path below.
read -r -d '' COMPARATOR <<'COMPARATOR_PHP' || true

	list($slug, $a, $b) = array_slice($argv, 1);

	$map = static function ( $root ) {
		$out  = array();
		$base = rtrim( $root, "/" );
		if ( ! is_dir( $base ) ) { return $out; }
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS ),
			RecursiveIteratorIterator::SELF_FIRST
		);
		foreach ( $it as $path => $info ) {
			$rel = substr( (string) $path, strlen( $base ) + 1 );
			if ( "" === $rel ) { continue; }
			if ( is_link( $path ) )     { $out[ $rel ] = "link:0:" . hash( "sha256", (string) readlink( $path ) ); continue; }
			if ( is_dir( $path ) )      { $out[ $rel ] = "dir:0:-"; continue; }
			$exec = ( fileperms( $path ) & 0111 ) ? "1" : "0";
			$out[ $rel ] = "file:" . $exec . ":" . hash_file( "sha256", $path );
		}
		ksort( $out, SORT_STRING );
		return $out;
	};

	$ma = $map( $a );
	$mb = $map( $b );
	$differ = array();
	foreach ( array_unique( array_merge( array_keys( $ma ), array_keys( $mb ) ) ) as $rel ) {
		if ( ( $ma[ $rel ] ?? null ) !== ( $mb[ $rel ] ?? null ) ) { $differ[] = $rel; }
	}
	sort( $differ );

	// AT MOST these two, not EXACTLY these two. Requiring equality made a tree
	// that matched COMPLETELY a failure — which is how this first behaved in CI,
	// where the two packages differed only in ZIP metadata and not in a single
	// file. "No more than these may differ" is the claim; fewer is better.
	$allowed = array( "$slug/build-manifest.json", "$slug/vendor/composer/installed.php" );
	sort( $allowed );
	$extra = array_values( array_diff( $differ, $allowed ) );
	if ( $extra ) {
		fwrite( STDERR, "  {$slug}: paths differ that this claim does not allow\n" );
		fwrite( STDERR, "    allowed: " . implode( ", ", $allowed ) . "\n" );
		foreach ( $extra as $rel ) {
			$what = ! isset( $ma[ $rel ] ) ? "only in the shipped ZIP"
				: ( ! isset( $mb[ $rel ] ) ? "only in the rebuild"
				: ( explode( ":", $ma[ $rel ] )[0] !== explode( ":", $mb[ $rel ] )[0]
					? "changed kind: " . explode( ":", $ma[ $rel ] )[0] . " vs " . explode( ":", $mb[ $rel ] )[0]
					: "content differs" ) );
			fwrite( STDERR, "    found:   {$rel} — {$what}\n" );
		}
		exit( 1 );
	}

	$bad = array();

	// THE EXEMPTION IS FOR CONTENT, NOT FOR EVERYTHING (V89-01). Two paths are
	// allowed to differ; nothing said they had to stay the same KIND, or keep
	// the same executable bit. The map recorded both and the exemption threw
	// them away, so `chmod +x` on installed.php — or replacing it with a symlink
	// to a file of the same text, which file_get_contents() would follow —
	// passed. What is permitted is a difference in two named fields inside two
	// regular files, and that is now what is checked.
	$kind_ok = array();
	foreach ( $allowed as $rel ) {
		$kind_ok[ $rel ] = true;
		if ( ! in_array( $rel, $differ, true ) ) { continue; }
		$ka = $ma[ $rel ] ?? null;
		$kb = $mb[ $rel ] ?? null;
		if ( null === $ka || null === $kb ) {
			$bad[] = "{$rel} is missing on one side";
			$kind_ok[ $rel ] = false;
			continue;
		}
		list( $kinda, $execa ) = explode( ":", $ka );
		list( $kindb, $execb ) = explode( ":", $kb );
		if ( "file" !== $kinda || "file" !== $kindb ) {
			$bad[] = "{$rel} is not a regular file on both sides ({$kinda} vs {$kindb})";
			$kind_ok[ $rel ] = false;
			continue;
		}
		if ( $execa !== $execb ) {
			$bad[] = "{$rel} differs in its executable bit";
			$kind_ok[ $rel ] = false;
		}
	}

	// Only files that actually differ are examined — a file that matches has
	// nothing to allow or refuse, and reading one that is not there is how this
	// reported "not JSON on one side" for two identical trees.
	// build-manifest.json: source_dirty only, and only false <-> unknown.
	if ( in_array( "$slug/build-manifest.json", $differ, true ) && ! empty( $kind_ok[ "$slug/build-manifest.json" ] ) ) {
	$ja = json_decode( (string) file_get_contents( "$a/$slug/build-manifest.json" ), true );
	$jb = json_decode( (string) file_get_contents( "$b/$slug/build-manifest.json" ), true );
	if ( ! is_array( $ja ) || ! is_array( $jb ) ) {
		$bad[] = "build-manifest.json is not JSON on one side";
	} else {
		foreach ( array_unique( array_merge( array_keys( $ja ), array_keys( $jb ) ) ) as $k ) {
			if ( ( $ja[ $k ] ?? null ) === ( $jb[ $k ] ?? null ) ) { continue; }
			if ( "source_dirty" !== $k ) { $bad[] = "build-manifest.json: {$k} differs, which this claim does not allow"; continue; }
			$pair = array( (string) ( $ja[ $k ] ?? "" ), (string) ( $jb[ $k ] ?? "" ) );
			sort( $pair );
			if ( array( "false", "unknown" ) !== $pair ) { $bad[] = "build-manifest.json: source_dirty is " . implode( " vs ", $pair ) . ", not false vs unknown"; }
		}
	}
	}

	// installed.php: the ROOT package s three values, in both places it is
	// described. Normalised exactly as bin/vendor-digest.php normalises them, so
	// every other byte of the file — all of its code — must match.
	$norm = static function ( $body ) {
		$blank = static function ( $body, $marker ) {
			$at = strpos( $body, $marker );
			while ( false !== $at ) {
				$open = strpos( $body, "(", $at ); $depth = 0; $end = $open;
				for ( $i = $open, $n = strlen( $body ); $i < $n; $i++ ) {
					if ( "(" === $body[ $i ] ) { $depth++; }
					elseif ( ")" === $body[ $i ] ) { $depth--; if ( 0 === $depth ) { $end = $i; break; } }
				}
				$block = substr( $body, $at, $end - $at + 1 );
				$fixed = preg_replace( "/(\x27(?:pretty_version|version|reference)\x27\s*=>\s*)(?:NULL|null|\x27[^\x27]*\x27)/", "\$1<volatile>", $block );
				$body  = substr( $body, 0, $at ) . $fixed . substr( $body, $end + 1 );
				$at    = strpos( $body, $marker, $at + strlen( $fixed ) );
			}
			return $body;
		};
		$body = $blank( $body, "\x27root\x27 => array(" );
		if ( preg_match( "/\x27root\x27 => array\(\s*\x27name\x27 => \x27([^\x27]+)\x27/", $body, $nm ) ) {
			$body = $blank( $body, "\x27" . $nm[1] . "\x27 => array(" );
		}
		return $body;
	};
	if ( in_array( "$slug/vendor/composer/installed.php", $differ, true )
		&& ! empty( $kind_ok[ "$slug/vendor/composer/installed.php" ] )
		&& $norm( (string) file_get_contents( "$a/$slug/vendor/composer/installed.php" ) )
		!== $norm( (string) file_get_contents( "$b/$slug/vendor/composer/installed.php" ) ) ) {
		$bad[] = "installed.php differs in more than the root package version and reference";
	}

	if ( $bad ) {
		fwrite( STDERR, "  " . $slug . ": " . implode( "\n  " . $slug . ": ", $bad ) . "\n" );
		exit( 1 );
	}

	// SAY WHAT DIFFERED, NOT WHAT WAS PERMITTED (V89-03). The check is a subset
	// test, and it reported "differs in exactly two paths" whatever it found —
	// including for two trees that were identical, which the log then recorded
	// as a difference.
	if ( ! $differ ) {
		echo "  {$slug}: the two packages are identical\n";
	} else {
		echo "  {$slug}: differs only in " . implode( " and ", $differ ) . " — and only in the fields allowed\n";
	}
COMPARATOR_PHP

# Extracted so --compare can reach it without a rebuild.
compare_trees() {   # $1 = slug, $2 = tree A, $3 = tree B
	"$PHP_BIN" -r "$COMPARATOR" "$1" "$2" "$3"
}

# --compare IS A WHOLE MODE, NOT A SHORTCUT THROUGH THIS ONE (V89-02). It used
# to fall through the ZIP, source and PHAR checks, which have nothing to do with
# comparing two directories that already exist — while nothing checked the two
# directories themselves, and the map of a directory that is not there is empty.
# Two empty maps agree, so a mistyped fixture path passed. Everything it needs
# is required; nothing it does not need is.
if [ -n "$COMPARE_A" ] || [ -n "$COMPARE_B" ]; then
	for side in "A:$COMPARE_A" "B:$COMPARE_B"; do
		name="${side%%:*}"; dir="${side#*:}"
		[ -n "$dir" ]      || { echo "--compare needs two directories (side $name is missing)" >&2; exit 2; }
		[ -d "$dir" ]      || { echo "--compare: no such directory: $dir" >&2; exit 2; }
		[ -d "$dir/$SLUG" ] || { echo "--compare: $dir holds no $SLUG/ — is --slug right?" >&2; exit 2; }
		[ -n "$( ls -A "$dir/$SLUG" 2>/dev/null )" ] || { echo "--compare: $dir/$SLUG is empty" >&2; exit 2; }
	done
	compare_trees "$SLUG" "$COMPARE_A" "$COMPARE_B" || exit 1
	exit 0
fi

[ -n "$ZIP" ]  || ZIP="$PLUGINS/$SLUG.zip"
[ -n "$SRC" ]  || SRC="$PLUGINS/$SLUG"
[ -f "$ZIP" ]  || { echo "no such ZIP: $ZIP" >&2; exit 2; }
[ -d "$SRC" ]  || { echo "no such source directory: $SRC" >&2; exit 2; }

# PHP-Scoper is 8 MB of third-party binary and is not tracked, so a source tree
# handed to a reviewer does not carry it. Say where to get it rather than
# failing three steps later with something obscure.
if [ -z "$SCOPER" ]; then
	for candidate in "$SRC/bin/php-scoper.phar" "$HERE/bin/php-scoper.phar" "$PLUGINS/$SLUG/bin/php-scoper.phar"; do
		[ -f "$candidate" ] && { SCOPER="$candidate"; break; }
	done
fi
if [ -z "$SCOPER" ] || [ ! -f "$SCOPER" ]; then
	cat >&2 <<'MISSING'
php-scoper.phar was not found. It is third-party and not tracked; pass it with
--scoper, or fetch the pinned release first:
  curl -L -o /tmp/php-scoper.phar \
    https://github.com/humbug/php-scoper/releases/download/0.18.11/php-scoper.phar
MISSING
	exit 2
fi


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

# A COPY of the directory as it stands — every file in it, tracked or not —
# with only .git and the build's own scratch output left behind.
mkdir -p "$WORK/src"
rsync -a --exclude '.git/' --exclude 'build/' "$SRC/" "$WORK/src/"
rm -rf "$WORK/src/.git"
cp "$SCOPER" "$WORK/src/bin/php-scoper.phar"

( cd "$WORK/src" && SOURCE_DATE_EPOCH="$EPOCH" SOURCE_COMMIT="$COMMIT" SOURCE_TREE="$TREE" \
	PHP="$PHP_BIN" bash bin/build-dist.sh ) > "$WORK/build.log" 2>&1 || {
	echo "  ${SLUG}: the source could not be rebuilt at all:" >&2
	tail -8 "$WORK/build.log" >&2
	exit 1
}
REBUILT="$WORK/$SLUG.zip"
[ -f "$REBUILT" ] || { echo "  ${SLUG}: the rebuild produced no ZIP" >&2; tail -8 "$WORK/build.log" >&2; exit 1; }

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

# COMPARED AS TREES, NOT BY READING diff's PROSE (V88-02). `diff -rq` also emits
#   "File a/x is a regular file while file b/x is a directory"
# and the previous version, which scanned for "Files … differ" and "Only in …",
# saw neither — so a path that changed KIND passed the check while the two
# permitted files differed in the permitted way. Each side is reduced to a map
# of path => kind:exec:hash (or the target, for a symlink) and the maps are
# compared; nothing about the comparison depends on how a tool phrases itself.
compare_trees "$SLUG" "$WORK/a" "$WORK/b" || exit 1

echo "    build-manifest.json           source_dirty: unknown (no git in this source) vs false"
echo "    vendor/composer/installed.php the root package's pretty_version, version, reference"
