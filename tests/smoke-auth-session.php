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

// SecondFactor::begin() now refuses when its cookie cannot be sent (V49-A06),
// and on the CLI the real setcookie() has nowhere to send one.
namespace RaplsPasskey\Security {
	function headers_sent( &$f = null, &$l = null ) { return ! empty( $GLOBALS['__headers_sent'] ); }
	function setcookie( $name, $value = '', $options = array() ) {
		if ( ! empty( $GLOBALS['__cookie_fails'] ) ) { return false; }
		$GLOBALS['__cookies'][ $name ] = $value;
		return true;
	}
}

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
	$GLOBALS['provider_filter'] = null;
	function apply_filters( $tag, $value, ...$args ) {
		if ( 'rapls_passkey/second_factor_providers' === $tag && is_callable( $GLOBALS['provider_filter'] ) ) {
			return call_user_func( $GLOBALS['provider_filter'], $value );
		}
		if ( 'rapls_passkey/allow_login' === $tag && is_callable( $GLOBALS['login_filter'] ) ) {
			return call_user_func( $GLOBALS['login_filter'], $value, ...$args );
		}
		if ( 'rapls_passkey/login_remember' === $tag && is_callable( $GLOBALS['remember_filter'] ) ) {
			return call_user_func( $GLOBALS['remember_filter'], $value, ...$args );
		}
		return $value;
	}

	class WP_User { public $ID; public $user_login; public function __construct( $id ) { $this->ID = $id; $this->user_login = 'u' . $id; } }
	class WP_Error {
		public $code; public $data;
		public function __construct( $code = '', $m = '', $d = array() ) { $this->code = $code; $this->data = $d; }
	}
	// The parked-login store, with a switch for "the store refuses".
	$GLOBALS['__transients']  = array();
	$GLOBALS['__store_fails'] = false;
	function set_transient( $k, $v, $ttl = 0 ) {
		if ( ! empty( $GLOBALS['__store_fails'] ) ) { return false; }
		$GLOBALS['__transients'][ $k ] = $v;
		return true;
	}
	function get_transient( $k ) { return $GLOBALS['__transients'][ $k ] ?? false; }
	function delete_transient( $k ) { unset( $GLOBALS['__transients'][ $k ] ); return true; }
	function wp_login_url( $redirect = '' ) { return 'https://example.test/wp-login.php'; }
	function add_query_arg( ...$a ) {
		$url = array_pop( $a );
		$q   = is_array( $a[0] ?? null ) ? $a[0] : array( $a[0] => $a[1] );
		return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . http_build_query( $q );
	}
	function wp_unslash( $v ) { return $v; }
	function sanitize_text_field( $v ) { return is_string( $v ) ? trim( $v ) : ''; }
	function esc_url_raw( $u ) { return $u; }
	function wp_validate_redirect( $u, $f = '' ) { return $f; }
	function is_ssl() { return true; }
	function wp_salt( $scheme = 'auth' ) { return 'unit-test-salt'; }
	function admin_url( $p = '' ) { return 'https://example.test/wp-admin/' . ltrim( (string) $p, '/' ); }
	function site_url( $p = '' ) { return 'https://example.test/' . ltrim( (string) $p, '/' ); }
	function home_url( $p = '' ) { return 'https://example.test/' . ltrim( (string) $p, '/' ); }

	require dirname( __DIR__ ) . '/src/Support/Settings.php';
	require dirname( __DIR__ ) . '/src/Security/LoginGate.php';
	// No 2FA plugin is registered here, so the second-factor gate stays open (see
	// tests/smoke-second-factor.php for its own coverage).
	require dirname( __DIR__ ) . '/src/Integrations/SecondFactor/Provider.php';
	require dirname( __DIR__ ) . '/src/Integrations/SecondFactor/TwoFactorCore.php';
	require dirname( __DIR__ ) . '/src/Integrations/SecondFactor/WordfenceLs.php';
	require dirname( __DIR__ ) . '/src/Security/SecondFactor.php';
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

	// --- V26-02: a 2FA challenge that could not be parked ------------------------
	// A weak login (magic link, recovery code) owes a second factor. The first
	// factor is already spent by the time we get here, so if the parked login
	// cannot be stored the user must be told — not redirected to a screen with
	// nothing to complete against.
	$GLOBALS['__opt']['rapls_passkey_settings'] = array( 'alt_login_second_factor' => true );
	$GLOBALS['provider_filter'] = static function ( $providers ) {
		return array(
			new class() implements \RaplsPasskey\Integrations\SecondFactor\Provider {
				public function is_available(): bool { return true; }
				public function label(): string { return 'Test 2FA'; }
				public function enabled_for( \WP_User $user ): bool { return true; }
				public function render( \WP_User $user ): void {}
				public function validate( \WP_User $user ): bool { return true; }
			},
		);
	};

	reset_state();
	$r = AuthSession::login( new WP_User( 5 ), 'magic-link', false );
	check( 'a weak login owing a second factor is held', $r instanceof WP_Error && 'rapls_passkey_2fa_required' === $r->code );
	check( 'and no cookie is set for it', null === $GLOBALS['cookie'] );

	reset_state();
	$GLOBALS['__store_fails'] = true;
	$r = AuthSession::login( new WP_User( 5 ), 'magic-link', false );
	$GLOBALS['__store_fails'] = false;
	check( 'a challenge that could not be parked is refused, not redirected (V26-02)', $r instanceof WP_Error && 'rapls_passkey_2fa_unavailable' === $r->code );
	check( 'and still no cookie is set', null === $GLOBALS['cookie'] );
	$GLOBALS['provider_filter'] = null;
	$GLOBALS['__opt']['rapls_passkey_settings'] = array();

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
