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

$tmp = sys_get_temp_dir() . '/rapls-verify-' . substr( md5( $zip . filemtime( $zip ) ), 0, 8 );
$rm  = static function ( string $d ) use ( &$rm ) {
	if ( ! is_dir( $d ) ) { return; }
	foreach ( scandir( $d ) as $e ) {
		if ( '.' === $e || '..' === $e ) { continue; }
		$p = $d . '/' . $e;
		is_dir( $p ) ? $rm( $p ) : @unlink( $p );
	}
	@rmdir( $d );
};
$rm( $tmp );
mkdir( $tmp, 0777, true );

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
foreach ( array( 'wp_cli', 'wordfencels', 'two_factor_core', 'woocommerce' ) as $sym ) { $wp[ $sym ] = true; }

$bad = array();
$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root . '/src', FilesystemIterator::SKIP_DOTS ) );
foreach ( $it as $f ) {
	if ( 'php' !== strtolower( $f->getExtension() ) ) { continue; }
	$c = (string) file_get_contents( $f->getPathname() );
	if ( preg_match_all( '/RaplsPasskey(?:Pro)?\\\\Vendor\\\\([A-Za-z_][A-Za-z0-9_]*)/', $c, $m ) ) {
		foreach ( array_unique( $m[1] ) as $seg ) {
			if ( isset( $wp[ strtolower( $seg ) ] ) ) {
				$bad[] = str_replace( $root . '/', '', $f->getPathname() ) . " -> Vendor\\{$seg}";
			}
		}
	}
}
check( 'no WordPress/external symbol mis-prefixed in src/', 0 === count( $bad ) );
foreach ( array_slice( array_unique( $bad ), 0, 8 ) as $b ) { echo "          {$b}\n"; }

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
