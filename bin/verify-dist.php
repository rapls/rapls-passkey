<?php
/**
 * Final-artifact verification for a namespace-prefixed distribution ZIP (F-12).
 *
 *   php bin/verify-dist.php ../rapls-passkey.zip
 *   php bin/verify-dist.php ../rapls-passkey-pro.zip
 *
 * This is the check that a plain smoke test on the unscoped source CANNOT do: it
 * unpacks the actual shipped ZIP, boots its Composer autoloader, and asserts that
 *   1. the prefixed bundled classes actually resolve (F-43), and
 *   2. no WordPress-core / detected third-party symbol was mis-prefixed into the
 *      private namespace (F-44),
 * plus that non-PHP assets (MDS roots) and third-party LICENSE notices survived.
 *
 * Exit 0 on success, 1 on any failed assertion. Lives in bin/ (never shipped).
 *
 * @package RaplsPasskey
 */

// phpcs:disable

$zip = $argv[1] ?? '';
if ( '' === $zip || ! is_file( $zip ) ) {
	fwrite( STDERR, "usage: php bin/verify-dist.php <path-to-zip>\n" );
	exit( 2 );
}

// A DIRECTORY NOBODY CAN PREDICT, AND A DELETE THAT DOES NOT FOLLOW LINKS
// (V62-08, and this copy was missed the first time — V63-07). The name used to
// be md5( path . mtime ), which anyone on the host can compute, and the first
// thing this did was recursively delete whatever was already there. is_dir() and
// scandir() follow symlinks, so a link planted at that path pointed the delete
// at its target.
//
// Random name, created exclusively, private mode, and the recursion unlinks a
// link instead of walking through it. Kept byte-identical to the Pro copy so the
// two cannot drift again.
$rm = static function ( string $d ) use ( &$rm ) {
	if ( is_link( $d ) ) { @unlink( $d ); return; }
	if ( ! is_dir( $d ) ) { return; }
	foreach ( scandir( $d ) as $e ) {
		if ( '.' === $e || '..' === $e ) { continue; }
		$p = $d . '/' . $e;
		if ( is_link( $p ) ) { @unlink( $p ); continue; }
		is_dir( $p ) ? $rm( $p ) : @unlink( $p );
	}
	@rmdir( $d );
};
$tmp = rtrim( sys_get_temp_dir(), '/' ) . '/rapls-verify-' . bin2hex( random_bytes( 12 ) );
if ( file_exists( $tmp ) || ! @mkdir( $tmp, 0700 ) ) {
	fwrite( STDERR, "cannot create a private working directory\n" );
	exit( 2 );
}

$za = new ZipArchive();
if ( true !== $za->open( $zip ) ) { fwrite( STDERR, "cannot open zip\n" ); exit( 2 ); }
$za->extractTo( $tmp );
$za->close();

$dirs = glob( $tmp . '/*', GLOB_ONLYDIR );
$root = $dirs[0] ?? $tmp;
$slug = basename( $root );
$is_pro = ( 'rapls-passkey-pro' === $slug );

$pass = 0; $fail = 0;
function check( string $label, bool $cond ): void {
	global $pass, $fail;
	echo ( $cond ? "  PASS  " : "  FAIL  " ) . $label . "\n";
	$cond ? $pass++ : $fail++;
}

echo "Verifying: {$slug}\n";

// 0) NOTHING THAT .distignore EXCLUDES IS IN HERE (V71-01).
//
// This is asserted against the FINISHED PACKAGE, because the check that was
// supposed to cover it read the build script's text instead — it confirmed that
// the script said `git ls-files` and `--files-from`, which it did, while rsync
// quietly ignored .distignore for files named that way and the package shipped
// tests/, bin/, .github/, composer.json and, on Pro, the entire licence server.
// A string in a script is not a property of an artifact.
//
// The list is not derived from .distignore: it is written out, so that a
// mistake in .distignore cannot excuse itself here.
$forbidden = array(
	'.github', '.gitignore', '.distignore', '.claude', 'CLAUDE.md', 'README.md',
	'docs', 'tests', 'bin', 'tools', 'node_modules', 'build',
	'composer.json', 'composer.lock', 'scoper.inc.php', 'build-manifest.json.bak',
	'.ci', '.idea', '.vscode', 'Thumbs.db', '.DS_Store',
);
$shipped = array();
foreach ( $forbidden as $name ) {
	if ( file_exists( $root . '/' . $name ) ) {
		$shipped[] = $name;
	}
}
// And anything ANYWHERE in the tree that is obviously not runtime.
$walk = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
foreach ( $walk as $path ) {
	$rel = ltrim( str_replace( $root, '', (string) $path ), '/' );
	if ( 0 === strpos( $rel, 'vendor/' ) ) {
		continue;   // third-party trees carry their own tests and docs; not ours to prune.
	}
	if ( preg_match( '#(^|/)(\.DS_Store|Thumbs\.db|\.gitignore|\.distignore)$#', $rel )
		|| preg_match( '#(^|/)(tests|\.github|\.ci|\.idea|\.vscode)/#', $rel ) ) {
		$shipped[] = $rel;
	}
}
$shipped = array_values( array_unique( $shipped ) );
check( 'the package contains nothing .distignore excludes (V71-01)', array() === $shipped );
foreach ( array_slice( $shipped, 0, 12 ) as $s ) {
	echo "          shipped but must not be: {$s}\n";
}
if ( count( $shipped ) > 12 ) {
	echo '          … and ' . ( count( $shipped ) - 12 ) . " more\n";
}

// 1) Autoloader present, prefixed bundled classes resolve (F-43).
$autoload = $root . '/vendor/scoper-autoload.php';
check( 'vendor/scoper-autoload.php present', is_file( $autoload ) );
if ( is_file( $autoload ) ) {
	require $autoload;
}
if ( $is_pro ) {
	check( "prefixed RaplsPasskeyPro\\Vendor\\BaconQrCode\\Writer autoloads", class_exists( 'RaplsPasskeyPro\\Vendor\\BaconQrCode\\Writer' ) );
} else {
	check( "prefixed RaplsPasskey\\Vendor\\Webauthn\\PublicKeyCredentialSource autoloads", class_exists( 'RaplsPasskey\\Vendor\\Webauthn\\PublicKeyCredentialSource' ) );
	check( "prefixed RaplsPasskey\\Vendor\\Brick\\Math\\BigInteger autoloads", class_exists( 'RaplsPasskey\\Vendor\\Brick\\Math\\BigInteger' ) );
}

// 2) No WordPress-core / detected third-party symbol mis-prefixed in src/ (F-44).
//    Read the same exclude lists the scoper uses and flag any first-segment
//    symbol that appears under the private Vendor\ namespace anywhere in src/.
$load = static function ( string $name ): array {
	$f = __DIR__ . '/scoper-excludes/' . $name;
	return is_readable( $f ) ? (array) json_decode( (string) file_get_contents( $f ), true ) : array();
};
$wp = array();
foreach ( array( 'exclude-wordpress-functions.json', 'exclude-wordpress-classes.json', 'exclude-wordpress-interfaces.json' ) as $j ) {
	foreach ( $load( $j ) as $sym ) { $wp[ strtolower( (string) $sym ) ] = true; }
}
foreach ( array( 'wp_cli', 'wordfencels', 'two_factor_core', 'woocommerce', 'wc' ) as $sym ) { $wp[ $sym ] = true; }

// A first-namespace-segment (or global function) that belongs to the host, not a
// bundled library — WP core, WP-CLI, WooCommerce (WC / wc_* / WC_*), Wordfence.
$is_host_symbol = static function ( string $seg ) use ( $wp ): bool {
	$l = strtolower( $seg );
	return isset( $wp[ $l ] ) || 1 === preg_match( '/^(wc_|wc$|woocommerce|wp_|wordfence)/', $l );
};

$bad = array();
$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root . '/src', FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	if ( 'php' !== strtolower( $f->getExtension() ) ) { continue; }
	$c = (string) file_get_contents( $f->getPathname() );
	if ( preg_match_all( '/RaplsPasskey(?:Pro)?\\\\Vendor\\\\([A-Za-z_][A-Za-z0-9_]*)/', $c, $m ) ) {
		foreach ( array_unique( $m[1] ) as $seg ) {
			if ( $is_host_symbol( $seg ) ) {
				$bad[] = str_replace( $root . '/', '', $f->getPathname() ) . " -> Vendor\\{$seg}";
			}
		}
	}
}
check( 'no WordPress/external symbol mis-prefixed in src/', 0 === count( $bad ) );
foreach ( array_slice( array_unique( $bad ), 0, 8 ) as $b ) { echo "          {$b}\n"; }

// 2b) PHP-Scoper must not emit a GLOBAL function alias that forwards to a prefixed
//     host function (e.g. `function WC() { return \…\Vendor\WC(...); }`). Such an
//     alias breaks host detection and can fatal other plugins. Scan the generated
//     scoper-autoload.php for any global function whose name is a host symbol.
$alias_bad = array();
$sa        = $root . '/vendor/scoper-autoload.php';
if ( is_file( $sa ) ) {
	$c = (string) file_get_contents( $sa );
	if ( preg_match_all( '/\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/', $c, $m ) ) {
		foreach ( array_unique( $m[1] ) as $fn ) {
			if ( $is_host_symbol( $fn ) ) { $alias_bad[] = $fn; }
		}
	}
}
check( 'scoper-autoload.php emits no global alias for a host function', 0 === count( $alias_bad ) );
foreach ( array_slice( $alias_bad, 0, 8 ) as $a ) { echo "          global function {$a}() forwards to a prefixed symbol\n"; }

// 3) Non-PHP assets carried into the ZIP.
if ( $is_pro ) {
	check( 'MDS root certificate present (src/Metadata/fido-mds-roots.pem)', is_file( $root . '/src/Metadata/fido-mds-roots.pem' ) );
}

// 4) Every bundled third-party package retains a license notice (MIT / BSD).
$pkg_dirs = array_filter(
	glob( $root . '/vendor/*/*', GLOB_ONLYDIR ) ?: array(),
	static fn ( $d ) => 'composer' !== basename( dirname( $d ) )
);
$missing = array();
foreach ( $pkg_dirs as $d ) {
	$has = false;
	foreach ( array( 'LICENSE*', 'License*', 'license*', 'COPYING*', 'COPYRIGHT*', 'NOTICE*' ) as $g ) {
		if ( glob( $d . '/' . $g ) ) { $has = true; break; }
	}
	if ( ! $has ) { $missing[] = str_replace( $root . '/', '', $d ); }
}
check( 'every bundled package retains a license notice (' . count( $pkg_dirs ) . ' packages)', 0 === count( $missing ) );
foreach ( array_slice( $missing, 0, 8 ) as $m ) { echo "          missing: {$m}\n"; }

$rm( $tmp );
echo "\n  {$pass} passed, {$fail} failed\n";
exit( 0 === $fail ? 0 : 1 );
