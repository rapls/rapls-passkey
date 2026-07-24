<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * WooCommerce integration: prompt rendering, logged-in suppression, filter veto,
 * and the once-per-request guard.
 *
 *   php tests/smoke-woocommerce.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'RAPLS_PASSKEY_URL', 'https://example.test/wp-content/plugins/rapls-passkey/' );
define( 'RAPLS_PASSKEY_VERSION', '0.0-test' );
define( 'ARRAY_A', 'ARRAY_A' );

$GLOBALS['__logged_in']  = false;
$GLOBALS['__filter_wc']  = true;

function is_user_logged_in() { return (bool) $GLOBALS['__logged_in']; }
function get_current_user_id() { return $GLOBALS['__logged_in'] ? 7 : 0; }
function __( $t, $d = null ) { return $t; }
function esc_html__( $t, $d = null ) { return $t; }
function esc_html_e( $t, $d = null ) { echo $t; }
function esc_html( $t ) { return $t; }
function esc_attr( $t ) { return $t; }
function esc_url( $t ) { return $t; }
function esc_url_raw( $t ) { return $t; }
function rest_url( $p = '' ) { return 'https://example.test/wp-json/' . $p; }
function wp_create_nonce( $a ) { return 'nonce-' . $a; }
function add_action() {}
function add_shortcode() {}
function wp_register_script() {}
function wp_register_style() {}
function wp_enqueue_style() {}
function wp_enqueue_script() {}
function wp_localize_script() {}
function apply_filters( $tag, $value ) { return $GLOBALS['__filter_wc']; }
function shortcode_atts( $defaults, $atts, $tag = '' ) {
	$atts = (array) $atts;
	$out = array();
	foreach ( $defaults as $k => $v ) {
		$out[ $k ] = array_key_exists( $k, $atts ) ? $atts[ $k ] : $v;
	}
	return $out;
}

class FakeWpdb {
	public $prefix = 'wp_';
	public function prepare( $q, ...$a ) { return $q; }
	public function get_results( $q, $o = null ) { return array(); }
}
$GLOBALS['wpdb'] = new FakeWpdb();

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

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Frontend\Shortcodes;
use RaplsPasskey\Integrations\WooCommerce;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

function capture( WooCommerce $wc ): string {
	ob_start();
	$wc->render_prompt();
	return (string) ob_get_clean();
}

// Logged out + filter on => renders the prompt with the login button.
$GLOBALS['__logged_in'] = false;
$GLOBALS['__filter_wc'] = true;
$wc = new WooCommerce( new Shortcodes( new CredentialRepository() ) );
$out = capture( $wc );
check( 'renders the passkey login container + button', strpos( $out, 'rapls-pk-fe-login' ) !== false && strpos( $out, 'rapls-pk-fe-btn' ) !== false );
check( 'wraps it in the WooCommerce container', strpos( $out, 'rapls-pk-wc' ) !== false );

// Second call in the same request => guarded, no output.
$out2 = capture( $wc );
check( 'renders only once per request', $out2 === '' );

// Logged in => no prompt.
$GLOBALS['__logged_in'] = true;
$wc2 = new WooCommerce( new Shortcodes( new CredentialRepository() ) );
check( 'no prompt for logged-in users', capture( $wc2 ) === '' );

// Filter veto => no prompt.
$GLOBALS['__logged_in'] = false;
$GLOBALS['__filter_wc'] = false;
$wc3 = new WooCommerce( new Shortcodes( new CredentialRepository() ) );
check( 'filter can veto the prompt', capture( $wc3 ) === '' );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
