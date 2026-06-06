<?php
/**
 * Boots the plugin singleton exactly as the `plugins_loaded` callback does, to
 * catch wiring errors (missing `use` imports, type mismatches, fatal hook
 * registration) that linting cannot see. WordPress functions touched during
 * boot are stubbed so the class graph can run standalone.
 *
 *   php tests/smoke-wiring.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'RAPLS_PASSKEY_BASENAME', 'rapls-passkey/rapls-passkey.php' );

// --- Minimal WP stubs used during boot() ---------------------------------
$GLOBALS['__hooks'] = array();

function add_action( $hook, $cb, $priority = 10, $args = 1 ) {
	$GLOBALS['__hooks'][] = array( 'action', $hook );
	return true;
}
function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {
	$GLOBALS['__hooks'][] = array( 'filter', $hook );
	return true;
}

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

use RaplsPasskey\Plugin;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$plugin = Plugin::instance();
check( 'instance() returns the singleton', $plugin === Plugin::instance() );

$plugin->boot();
check( 'boot() registers the init textdomain hook', in_array( array( 'action', 'init' ), $GLOBALS['__hooks'], true ) );
check( 'boot() registers the admin_init schema upgrade hook', in_array( array( 'action', 'admin_init' ), $GLOBALS['__hooks'], true ) );

$count_after_first = count( $GLOBALS['__hooks'] );
$plugin->boot();
check( 'boot() is idempotent (no duplicate hooks on second call)', count( $GLOBALS['__hooks'] ) === $count_after_first );

check( 'webauthn_library_available() is false without Composer deps', $plugin->webauthn_library_available() === false );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
