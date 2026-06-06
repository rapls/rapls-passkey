<?php
/**
 * Boots the plugin singleton exactly as the `plugins_loaded` callback does, with
 * the real web-auth library loaded, to catch wiring errors (missing `use`
 * imports, type mismatches, fatal construction) that linting cannot see. The
 * WordPress functions touched during boot are stubbed.
 *
 *   php tests/smoke-wiring.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'RAPLS_PASSKEY_VERSION', '0.1.0-test' );
define( 'RAPLS_PASSKEY_URL', 'https://example.test/wp-content/plugins/rapls-passkey/' );
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
function home_url( $path = '' ) { return 'https://example.test'; }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function get_bloginfo( $key ) { return 'Example Site'; }
function wp_specialchars_decode( $text, $quotes = null ) { return html_entity_decode( (string) $text, ENT_QUOTES ); }
function is_admin() { return true; }

require dirname( __DIR__ ) . '/vendor/autoload.php';

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
check( 'webauthn library is available (vendor loaded)', $plugin->webauthn_library_available() === true );

$plugin->boot();

$hooked = array_map( function ( $h ) { return $h[1]; }, $GLOBALS['__hooks'] );
check( 'boot() hooks init (textdomain)', in_array( 'init', $hooked, true ) );
check( 'boot() hooks admin_init (schema upgrade)', in_array( 'admin_init', $hooked, true ) );
check( 'boot() hooks rest_api_init (endpoints)', in_array( 'rest_api_init', $hooked, true ) );
check( 'boot() hooks login_form (login button)', in_array( 'login_form', $hooked, true ) );
check( 'boot() hooks login_enqueue_scripts', in_array( 'login_enqueue_scripts', $hooked, true ) );
check( 'boot() hooks show_user_profile (admin)', in_array( 'show_user_profile', $hooked, true ) );

$count_after_first = count( $GLOBALS['__hooks'] );
$plugin->boot();
check( 'boot() is idempotent (no duplicate hooks)', count( $GLOBALS['__hooks'] ) === $count_after_first );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
