<?php
/**
 * AuthSession::login — the shared login chokepoint: LoginGate veto, conservative
 * remember-me (never persistent for admins), the remember filter, and the
 * wp_login / after_login signals.
 *
 *   php tests/smoke-auth-session.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );

	$GLOBALS['login_filter']  = null;
	$GLOBALS['remember_filter'] = null;
	$GLOBALS['admin']  = false;
	$GLOBALS['cookie'] = null; // [uid, remember]
	$GLOBALS['fired']  = array();

	$GLOBALS['__opt'] = array();
	function __( $s, $d = null ) { return $s; }
	function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
	function user_can( $user, $cap ) { return ! empty( $GLOBALS['admin'] ); }
	function wp_set_current_user( $uid ) {}
	function wp_set_auth_cookie( $uid, $remember = false ) { $GLOBALS['cookie'] = array( (int) $uid, (bool) $remember ); }
	function do_action( $hook, ...$args ) { $GLOBALS['fired'][] = $hook; }
	function apply_filters( $tag, $value, ...$args ) {
		if ( 'rapls_passkey/allow_login' === $tag && is_callable( $GLOBALS['login_filter'] ) ) {
			return call_user_func( $GLOBALS['login_filter'], $value, ...$args );
		}
		if ( 'rapls_passkey/login_remember' === $tag && is_callable( $GLOBALS['remember_filter'] ) ) {
			return call_user_func( $GLOBALS['remember_filter'], $value, ...$args );
		}
		return $value;
	}

	class WP_User { public $ID; public $user_login; public function __construct( $id ) { $this->ID = $id; $this->user_login = 'u' . $id; } }
	class WP_Error { public $code; public function __construct( $code = '', $m = '', $d = array() ) { $this->code = $code; } }

	require dirname( __DIR__ ) . '/src/Support/Settings.php';
	require dirname( __DIR__ ) . '/src/Security/LoginGate.php';
	require dirname( __DIR__ ) . '/src/Security/AuthSession.php';

	use RaplsPasskey\Security\AuthSession;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}
	function reset_state() { $GLOBALS['cookie'] = null; $GLOBALS['fired'] = array(); }

	$user = new WP_User( 5 );

	// Normal login, remember requested -> cookie set persistent, hooks fired.
	reset_state(); $GLOBALS['admin'] = false;
	$r = AuthSession::login( $user, 'login', true );
	check( 'allows a normal login', null === $r );
	check( 'sets the cookie with remember=true', $GLOBALS['cookie'] === array( 5, true ) );
	check( 'fires wp_login and after_login', in_array( 'wp_login', $GLOBALS['fired'], true ) && in_array( 'rapls_passkey/after_login', $GLOBALS['fired'], true ) );

	// Administrator never gets a persistent cookie by default.
	reset_state(); $GLOBALS['admin'] = true;
	AuthSession::login( $user, 'login', true );
	check( 'administrator session is never persistent by default', $GLOBALS['cookie'] === array( 5, false ) );

	// ...unless an administrator opts in via the setting.
	reset_state(); $GLOBALS['admin'] = true;
	$GLOBALS['__opt']['rapls_passkey_settings'] = array( 'admin_remember_allowed' => true );
	AuthSession::login( $user, 'login', true );
	check( 'administrator persistent allowed when opted in', $GLOBALS['cookie'] === array( 5, true ) );
	$GLOBALS['__opt'] = array();
	$GLOBALS['admin'] = false;

	// LoginGate veto -> WP_Error, no cookie.
	reset_state();
	$GLOBALS['login_filter'] = function ( $v ) { return false; };
	$r = AuthSession::login( $user, 'login', false );
	check( 'a vetoed login returns WP_Error', $r instanceof WP_Error );
	check( 'a vetoed login sets no cookie', null === $GLOBALS['cookie'] );
	$GLOBALS['login_filter'] = null;

	// remember filter can override.
	reset_state();
	$GLOBALS['remember_filter'] = function ( $v ) { return true; };
	AuthSession::login( $user, 'qr-channel', false );
	check( 'remember filter can force persistence', $GLOBALS['cookie'] === array( 5, true ) );
	$GLOBALS['remember_filter'] = null;

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
