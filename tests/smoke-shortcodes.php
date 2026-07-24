<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Shortcodes: logged-out vs logged-in rendering and asset enqueue behaviour.
 *
 *   php tests/smoke-shortcodes.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'RAPLS_PASSKEY_URL', 'https://example.test/wp-content/plugins/rapls-passkey/' );
define( 'RAPLS_PASSKEY_VERSION', '0.0-test' );
define( 'ARRAY_A', 'ARRAY_A' );

$GLOBALS['__logged_in'] = false;
$GLOBALS['__enqueued']  = array();

// WP test doubles.
function is_user_logged_in() { return (bool) $GLOBALS['__logged_in']; }
function get_current_user_id() { return $GLOBALS['__logged_in'] ? 7 : 0; }
function __( $t, $d = null ) { return $t; }
function esc_html__( $t, $d = null ) { return $t; }
function esc_html_e( $t, $d = null ) { echo $t; }
function esc_html( $t ) { return $t; }
function esc_attr( $t ) { return $t; }
function esc_url( $t ) { return $t; }
function esc_url_raw( $t ) { return $t; }
function apply_filters( $tag, $value, ...$args ) { return $value; }
function rest_url( $p = '' ) { return 'https://example.test/wp-json/' . $p; }
function wp_create_nonce( $a ) { return 'nonce-' . $a; }
function add_action() {}
function add_shortcode() {}
function wp_register_script() {}
function wp_register_style() {}
function wp_enqueue_style( $h ) { $GLOBALS['__enqueued'][] = $h; }
function wp_enqueue_script( $h ) { $GLOBALS['__enqueued'][] = $h; }
function wp_localize_script( $h, $o, $d ) { $GLOBALS['__localized'] = $d; }
function shortcode_atts( $defaults, $atts, $tag = '' ) {
	$atts = (array) $atts;
	$out = array();
	foreach ( $defaults as $k => $v ) {
		$out[ $k ] = array_key_exists( $k, $atts ) ? $atts[ $k ] : $v;
	}
	return $out;
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

// Minimal $wpdb so the real (final) CredentialRepository returns no rows.
class FakeWpdb {
	public $prefix = 'wp_';
	public function prepare( $q, ...$a ) { return $q; }
	public function get_results( $q, $o = null ) { return array(); }
}
$GLOBALS['wpdb'] = new FakeWpdb();

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Frontend\Shortcodes;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$sc = new Shortcodes( new CredentialRepository() );

// --- Logged out. ---
$GLOBALS['__logged_in'] = false;
$GLOBALS['__enqueued']  = array();
$login = $sc->render_login( array() );
check( 'login: renders the sign-in container + button', strpos( $login, 'rapls-pk-fe-login' ) !== false && strpos( $login, 'rapls-pk-fe-btn' ) !== false );
check( 'login: username field opts into webauthn autofill', strpos( $login, 'username webauthn' ) !== false );
check( 'login: enqueues frontend assets', in_array( 'rapls-passkey-frontend', $GLOBALS['__enqueued'], true ) );
check( 'login: nonce empty when logged out', isset( $GLOBALS['__localized']['nonce'] ) && $GLOBALS['__localized']['nonce'] === '' );

$reg_out = $sc->render_register( array() );
check( 'register: prompts to log in when logged out', strpos( $reg_out, 'Please sign in' ) !== false );
check( 'register: does not render the register container when logged out', strpos( $reg_out, 'rapls-pk-fe-register' ) === false );

// --- Logged in. --- (fresh instance: assets enqueue once per request.)
$GLOBALS['__logged_in'] = true;
$GLOBALS['__enqueued']  = array();
$sc = new Shortcodes( new CredentialRepository() );
$login_in = $sc->render_login( array() );
check( 'login: shows "already logged in" note', strpos( $login_in, 'already signed in' ) !== false );

$reg_in = $sc->render_register( array() );
check( 'register: renders the register container + button when logged in', strpos( $reg_in, 'rapls-pk-fe-register' ) !== false && strpos( $reg_in, 'rapls-pk-fe-btn' ) !== false );
check( 'register: shows empty-state row with no credentials', strpos( $reg_in, 'No passkeys are registered' ) !== false );
check( 'register: nonce present when logged in', isset( $GLOBALS['__localized']['nonce'] ) && $GLOBALS['__localized']['nonce'] === 'nonce-wp_rest' );

// --- Custom attributes. ---
$custom = $sc->render_login( array( 'redirect' => 'https://example.test/members/', 'label' => 'Login' ) );
$GLOBALS['__logged_in'] = false;
$custom = $sc->render_login( array( 'redirect' => 'https://example.test/members/', 'label' => 'Login' ) );
check( 'login: honours custom redirect attr', strpos( $custom, 'data-redirect="https://example.test/members/"' ) !== false );
check( 'login: honours custom label attr', strpos( $custom, '>Login</button>' ) !== false );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
