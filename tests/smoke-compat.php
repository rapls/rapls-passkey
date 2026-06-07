<?php
/**
 * Security-plugin detection (Compat::detect).
 *
 *   php tests/smoke-compat.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['__opt'] = array( 'active_plugins' => array() );
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function is_multisite() { return false; }
function get_site_option( $k, $d = false ) { return $d; }

spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

use RaplsPasskey\Support\Compat;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

check( 'nothing detected on a clean install', Compat::detect() === array() );

// SiteGuard via active_plugins slug.
$GLOBALS['__opt']['active_plugins'] = array( 'siteguard/siteguard.php', 'hello.php' );
check( 'detects SiteGuard by slug', in_array( 'SiteGuard WP Plugin', Compat::detect(), true ) );

// Wordfence via constant.
define( 'WORDFENCE_VERSION', '7.0' );
$detected = Compat::detect();
check( 'detects Wordfence by constant', in_array( 'Wordfence', $detected, true ) );
check( 'still detects SiteGuard alongside', in_array( 'SiteGuard WP Plugin', $detected, true ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
