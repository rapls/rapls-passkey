<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Front-end login forms that fire login_form (WP-Members, bbPress): the passkey
 * button and the reCAPTCHA field must bring their scripts with them, because
 * login_enqueue_scripts never runs there.
 *
 *   php tests/smoke-login-form-frontend.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'RAPLS_PASSKEY_URL', 'https://example.test/wp-content/plugins/rapls-passkey/' );
define( 'RAPLS_PASSKEY_VERSION', 'test' );

$GLOBALS['__did']      = array();
$GLOBALS['__enqueued'] = array();
$GLOBALS['__localize'] = array();
$GLOBALS['__logged']   = false;

function did_action( $hook ) { return $GLOBALS['__did'][ $hook ] ?? 0; }
function is_user_logged_in() { return $GLOBALS['__logged']; }
function wp_enqueue_script( $handle ) { $GLOBALS['__enqueued'][] = $handle; }
function wp_localize_script( $handle, $name, $data ) { $GLOBALS['__localize'][ $name ] = $data; }
function __( $t, $d = null ) { return $t; }
function esc_html__( $t, $d = null ) { return $t; }
function esc_html_e( $t, $d = null ) { echo $t; }
function esc_attr( $t ) { return $t; }
function esc_url_raw( $u ) { return $u; }
function wp_unslash( $v ) { return $v; }
function rest_url( $p = '' ) { return 'https://example.test/wp-json/' . $p; }
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function apply_filters( $tag, $value ) { return $value; }

spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	if ( 'RaplsPasskey\\Support\\Help' === $class ) {
		eval( 'namespace RaplsPasskey\\Support; final class Help { public static function render( string $v = "details" ): void {} }' );
		return;
	}
	$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

use RaplsPasskey\Login\LoginForm;
use RaplsPasskey\Login\Recaptcha;

$pass  = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}
function reset_state() {
	$GLOBALS['__enqueued'] = array();
	$GLOBALS['__localize'] = array();
}
function capture( callable $fn ) {
	ob_start();
	$fn();
	return (string) ob_get_clean();
}

// ── wp-login.php: login_enqueue_scripts has run, nothing changes ─────────────
$GLOBALS['__did'] = array( 'login_enqueue_scripts' => 1 );
$form = new LoginForm();
$html = capture( array( $form, 'render_button' ) );
check( 'wp-login: button printed', false !== strpos( $html, 'id="rapls-passkey-login-btn"' ) );
check( 'wp-login: render does not enqueue again', array() === $GLOBALS['__enqueued'] );
$form->enqueue();
check( 'wp-login: enqueue loads login.js', in_array( 'rapls-passkey-login', $GLOBALS['__enqueued'], true ) );
check( 'wp-login: frontEnd is off', 0 === $GLOBALS['__localize']['raplsPasskeyLogin']['frontEnd'] );
$html = capture( array( $form, 'render_button' ) );
check( 'wp-login: a second login_form still prints (no front-end guard)', false !== strpos( $html, 'rapls-passkey-login-btn' ) );

// ── Front end (WP-Members): no login_enqueue_scripts ─────────────────────────
reset_state();
$GLOBALS['__did'] = array();
$form = new LoginForm();
$html = capture( array( $form, 'render_button' ) );
check( 'front: button printed', false !== strpos( $html, 'id="rapls-passkey-login-btn"' ) );
check( 'front: webauthn.js enqueued', in_array( 'rapls-passkey-webauthn', $GLOBALS['__enqueued'], true ) );
check( 'front: login.js enqueued', in_array( 'rapls-passkey-login', $GLOBALS['__enqueued'], true ) );
check( 'front: config localized', isset( $GLOBALS['__localize']['raplsPasskeyLogin']['restUrl'] ) );
check( 'front: frontEnd is on (return to the page)', 1 === $GLOBALS['__localize']['raplsPasskeyLogin']['frontEnd'] );
$html = capture( array( $form, 'render_button' ) );
check( 'front: second form on the page gets no duplicate button', '' === $html );

reset_state();
$GLOBALS['__logged'] = true;
$form = new LoginForm();
$html = capture( array( $form, 'render_button' ) );
check( 'front: logged-in visitor gets no button', '' === $html && array() === $GLOBALS['__enqueued'] );
$GLOBALS['__logged'] = false;

// ── reCAPTCHA field ──────────────────────────────────────────────────────────
$GLOBALS['__opt'] = array(
	'rapls_passkey_settings' => array(
		'recaptcha_enabled'    => true,
		'recaptcha_site_key'   => 'SITE',
		'recaptcha_secret_key' => 'SECRET',
	),
);

reset_state();
$GLOBALS['__did'] = array( 'login_enqueue_scripts' => 1 );
$rc   = new Recaptcha();
$html = capture( array( $rc, 'render_field' ) );
check( 'recaptcha wp-login: field printed', false !== strpos( $html, 'name="rapls_passkey_recaptcha_token"' ) );
check( 'recaptcha wp-login: render does not enqueue', array() === $GLOBALS['__enqueued'] );

reset_state();
$GLOBALS['__did'] = array();
$rc   = new Recaptcha();
$html = capture( array( $rc, 'render_field' ) );
check( 'recaptcha front: field printed', false !== strpos( $html, 'name="rapls_passkey_recaptcha_token"' ) );
check( 'recaptcha front: script enqueued', in_array( 'rapls-passkey-recaptcha', $GLOBALS['__enqueued'], true ) );
$count = count( $GLOBALS['__enqueued'] );
$html2 = capture( array( $rc, 'render_field' ) );
check( 'recaptcha front: a second form still gets its own field', false !== strpos( $html2, 'name="rapls_passkey_recaptcha_token"' ) );
check( 'recaptcha front: script loaded only once', count( $GLOBALS['__enqueued'] ) === $count );
check( 'recaptcha: field carries no duplicate id', false === strpos( $html . $html2, 'id="rapls_passkey_recaptcha_token"' ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc ? 1 : 0 );
