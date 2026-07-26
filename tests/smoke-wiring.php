<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
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
$GLOBALS['__init_cbs'] = array();

function add_action( $hook, $cb, $priority = 10, $args = 1 ) {
	$GLOBALS['__hooks'][] = array( 'action', $hook );
	// Keep the `init` callbacks so a test can run them, the way WordPress would.
	if ( 'init' === $hook ) {
		$GLOBALS['__init_cbs'][] = $cb;
	}
	return true;
}
function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {
	$GLOBALS['__hooks'][] = array( 'filter', $hook );
	return true;
}
function add_shortcode( $tag, $cb ) { $GLOBALS['__hooks'][] = array( 'shortcode', $tag ); return true; }
function load_plugin_textdomain( $d, $x = false, $p = '' ) { return true; }
function home_url( $path = '' ) { return 'https://example.test'; }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function get_bloginfo( $key ) { return 'Example Site'; }
function wp_specialchars_decode( $text, $quotes = null ) { return html_entity_decode( (string) $text, ENT_QUOTES ); }
function is_admin() { return true; }
function get_option( $k, $d = false ) { return $d; }
$GLOBALS['__rp_id_filter'] = null;
function add_filter_stub_rp_id( $id ) { $GLOBALS['__rp_id_filter'] = $id; }
function apply_filters( $tag, $value ) {
	// Model the one thing that matters here: a filter registered AFTER boot() must
	// still be in force when the relying party is finally built.
	if ( 'rapls_passkey_rp_id' === $tag && null !== $GLOBALS['__rp_id_filter'] ) {
		$GLOBALS['__rp_id_at_build'] = $GLOBALS['__rp_id_filter'];
		return $GLOBALS['__rp_id_filter'];
	}
	return $value;
}

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
// R20-03: the ceremonies must NOT be built during boot(). Their relying-party ID
// and allowed origins come from filters that other plugins (Pro's shared network
// RP ID, Related Origin Requests) register during plugins_loaded — some of them
// after this plugin. So boot() only schedules the work for `init`, by which time
// every plugin has had its say.
check( 'boot() defers the ceremonies to init, not rest_api_init directly', in_array( 'init', $hooked, true ) && ! in_array( 'rest_api_init', $hooked, true ) );

// Running the init callbacks is what registers the REST routes.
$GLOBALS['__rp_id_at_build'] = null;
add_filter_stub_rp_id( 'shared.example' );
foreach ( $GLOBALS['__init_cbs'] as $cb ) {
	$cb();
}
$hooked_after_init = array_map( function ( $h ) { return $h[1]; }, $GLOBALS['__hooks'] );
check( 'the init callback hooks rest_api_init (endpoints)', in_array( 'rest_api_init', $hooked_after_init, true ) );
check( 'a filter registered after boot() still reaches the relying party (R20-03)', 'shared.example' === $GLOBALS['__rp_id_at_build'] );
check( 'boot() hooks login_form (login button)', in_array( 'login_form', $hooked, true ) );
check( 'boot() hooks login_enqueue_scripts', in_array( 'login_enqueue_scripts', $hooked, true ) );
check( 'boot() hooks show_user_profile (admin)', in_array( 'show_user_profile', $hooked, true ) );

$count_after_first = count( $GLOBALS['__hooks'] );
$plugin->boot();
check( 'boot() is idempotent (no duplicate hooks)', count( $GLOBALS['__hooks'] ) === $count_after_first );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
