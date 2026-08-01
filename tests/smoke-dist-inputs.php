<?php
/**
 * What can get into the package.
 *
 * V69-01 added a promise: source_dirty false means the recorded commit
 * reproduces this ZIP. V70-02 showed the promise did not hold. The clean-tree
 * gate reads `git status --porcelain`, which says NOTHING about files git has
 * been told to ignore, and staging copied the repository root — so a file this
 * repository ignores (.ci/, an editor directory, a scratch file with a machine
 * path or a credential in it) was invisible to the gate and copied into the
 * package all the same.
 *
 * Staging is driven by `git ls-files` now, which cannot see an untracked file at
 * all. These assertions are what keeps that true:
 *
 *   1. The build stages from git ls-files, not from the directory.
 *   2. Every path .gitignore excludes is also excluded by .distignore, so the
 *      no-git fallback — and anyone reading either file — agrees.
 *   3. An ignored sentinel really is absent from git ls-files.
 *   4. The clean-tree gate is still there, and still runs before Composer.
 *
 * Run: php tests/smoke-dist-inputs.php   (also runs for the Pro plugin's copy)
 *
 * @package RaplsPasskey
 */

$pass  = 0;
$failc = 0;
$skips = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}
function skip( $label ) {
	global $skips;
	echo '  SKIP  ' . $label . "\n";
	$skips++;
}

$root = dirname( __DIR__ );

// The distribution carries neither bin/ nor the ignore files; there is nothing
// here to check then, and saying so is better than passing (V62-09, V69-04).
$build = $root . '/bin/build-dist.sh';
if ( ! is_readable( $build ) || ! is_readable( $root . '/.gitignore' ) || ! is_readable( $root . '/.distignore' ) ) {
	skip( 'the build script and both ignore files are needed; not all are here (distribution)' );
	echo "\n  {$pass} passed, {$failc} failed, {$skips} skipped\n";
	exit( 0 );
}

$script     = (string) file_get_contents( $build );
$gitignore  = (string) file_get_contents( $root . '/.gitignore' );
$distignore = (string) file_get_contents( $root . '/.distignore' );

// --- 1. Staging is driven by the index --------------------------------------
check( 'the build stages the plugin tree from git ls-files (V70-02)', false !== strpos( $script, 'ls-files -z' ) && false !== strpos( $script, '--files-from=-' ) );
check( 'and the old copy-the-whole-directory form is only the no-git fallback', 1 === substr_count( $script, 'rsync -a --exclude-from="$ROOT/.distignore" --exclude \'src\' --exclude \'vendor\' "$ROOT/." "$STAGE/"' ) );

// --- 2. The fallback would not ship an ignored file either -------------------
//
// NOT A COMPARISON OF THE TWO PATTERN LANGUAGES. gitignore and .distignore are
// read by different tools, and a hand-written equivalence check between them is
// a guess about rsync's behaviour. This asks rsync, with the real .distignore,
// about the paths this repository REALLY ignores right now — the fallback path
// verbatim, as a dry run.
if ( is_dir( $root . '/.git' ) && function_exists( 'shell_exec' ) ) {
	// PLANTED, NOT FOUND. A fresh checkout has nothing ignored lying about
	// except vendor/, so a check that waits for one has nothing to say there —
	// which is how the first version of this failed CI honestly: it asserted
	// that it had work to do, and on a clean runner it did not. It brings its
	// own now, so it says the same thing everywhere.
	$sentinel_dir = $root . '/.ci';
	$planted      = $sentinel_dir . '/smoke-dist-inputs.sentinel';
	$made_dir     = ! is_dir( $sentinel_dir );
	@mkdir( $sentinel_dir, 0777, true );
	file_put_contents( $planted, "LOCAL_SECRET=should-not-ship\n" );

	$ignored = array_values( array_filter( array_map(
		static function ( $line ) {
			// "!! path/" — the space after the marker has to go too, or every
			// comparison below is against " path" and matches nothing. That was
			// the first version of this, and it passed while the leak was open.
			return trim( substr( trim( $line ), 2 ), " \t\"" );
		},
		preg_split( '/\R/', (string) shell_exec( 'cd ' . escapeshellarg( $root ) . ' && git status --porcelain --ignored 2>/dev/null | grep "^!!"' ) ) ?: array()
	) ) );
	// vendor/ is the one deliberate disagreement: git ignores it because it is
	// installed, and the package SHIPS it (scoped). Named, so the exception is a
	// decision rather than a hole.
	$ignored = array_values( array_filter(
		$ignored,
		static function ( $p ) {
			return '' !== $p && 0 !== strpos( $p, 'vendor/' );
		}
	) );
	$sees_sentinel = false;
	foreach ( $ignored as $p ) {
		if ( 0 === strpos( $p, '.ci' ) ) {
			$sees_sentinel = true;
		}
	}
	check( 'the planted local file is one git ignores, so there is something to check', $sees_sentinel );

	$dry = (string) shell_exec(
		'cd ' . escapeshellarg( $root )
		. ' && rsync -avn --exclude-from=.distignore --exclude src --exclude vendor ./ '
		. escapeshellarg( sys_get_temp_dir() . '/rapls-distinputs-' . getmypid() ) . '/ 2>/dev/null'
	);
	$would_ship = array();
	foreach ( $ignored as $path ) {
		// rsync lists directories with a trailing slash and files without.
		$needle = rtrim( $path, '/' );
		if ( preg_match( '/^' . preg_quote( $needle, '/' ) . '(\/|$)/m', $dry ) ) {
			$would_ship[] = $path;
		}
	}
	check(
		'nothing this repository ignores would be copied into the package' . ( $would_ship ? ' — would ship: ' . implode( ', ', $would_ship ) : '' ),
		array() === $would_ship
	);

	// --- 3. And the index does not carry it either ---------------------------
	$listed = (string) shell_exec( 'cd ' . escapeshellarg( $root ) . ' && git ls-files | grep -c "smoke-dist-inputs.sentinel" 2>/dev/null' );
	$status = (string) shell_exec( 'cd ' . escapeshellarg( $root ) . ' && git status --porcelain | grep -c "smoke-dist-inputs.sentinel" 2>/dev/null' );
	check( 'the planted file is not in git ls-files, so staging cannot copy it (V70-02)', 0 === (int) trim( $listed ) );
	check( 'and the clean-tree gate cannot see it either — which is why staging had to change', 0 === (int) trim( $status ) );

	@unlink( $planted );
	if ( $made_dir ) {
		@rmdir( $sentinel_dir );
	}
} else {
	skip( 'no git checkout here, so what is ignored cannot be asked' );
}
check( 'the .distignore names the local-only paths as well', false !== strpos( $distignore, '/.ci' ) );

// --- 4. The clean-tree gate is intact ---------------------------------------
$gate_at     = strpos( $script, 'refusing to build: the working tree has uncommitted changes' );
$composer_at = strpos( $script, 'install --no-dev --optimize-autoloader' );
check( 'the clean-tree gate is still in the build (V69-01)', false !== $gate_at );
check( 'and it runs before Composer, so it judges the source and not the build', false !== $gate_at && false !== $composer_at && $gate_at < $composer_at );

echo "\n  {$pass} passed, {$failc} failed, {$skips} skipped\n";
exit( $failc === 0 ? 0 : 1 );
