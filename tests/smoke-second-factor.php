<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * SecondFactor: which logins owe a 2FA challenge, and the parked-login handshake.
 *
 *   php tests/smoke-second-factor.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// SecondFactor lives in RaplsPasskey\Security, so PHP resolves an unqualified
// setcookie()/headers_sent() in that namespace before the global one. Declared
// through eval() because a namespace block cannot follow the definitions above.
// What is under test is what the caller does with the ANSWER (V49-A06): on the
// CLI the real setcookie() has nowhere to send anything.
eval( 'namespace RaplsPasskey\\Security;
	function headers_sent( &$f = null, &$l = null ) { return ! empty( $GLOBALS["__headers_sent"] ); }
	function setcookie( $name, $value = "", $options = array() ) {
		if ( ! empty( $GLOBALS["__cookie_fails"] ) ) { return false; }
		$GLOBALS["__cookies"][ $name ] = $value;
		return true;
	}' );

class WP_Error {
	private $code;
	private $message;
	private $data;
	public function __construct( $code = '', $message = '', $data = null ) {
		$this->code    = $code;
		$this->message = $message;
		$this->data    = $data;
	}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
	public function get_error_data() { return $this->data; }
}
function is_wp_error( $t ) { return $t instanceof WP_Error; }

class WP_User {
	public $ID;
	public $user_login;
	public function __construct( $id = 0, $login = '' ) { $this->ID = (int) $id; $this->user_login = $login; }
}

$GLOBALS['__opt']        = array();
$GLOBALS['__transients'] = array();
$GLOBALS['__filters']    = array();
$GLOBALS['__auth']       = null;

function get_option( $k, $d = array() ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function apply_filters( $tag, $value, ...$rest ) {
	if ( isset( $GLOBALS['__filters'][ $tag ] ) ) {
		return call_user_func_array( $GLOBALS['__filters'][ $tag ], array_merge( array( $value ), $rest ) );
	}
	return $value;
}
function __( $s, $d = null ) { return $s; }
function sanitize_text_field( $s ) { return trim( (string) $s ); }
function wp_unslash( $s ) { return $s; }
function wp_salt( $s = 'auth' ) { return 'unit-test-salt'; }
function is_ssl() { return true; }
function get_transient( $k ) { return $GLOBALS['__transients'][ $k ] ?? false; }
$GLOBALS['__store_fails'] = false;
function set_transient( $k, $v, $ttl ) {
	if ( ! empty( $GLOBALS['__store_fails'] ) ) { return false; }
	$GLOBALS['__transients'][ $k ] = $v;
	return true;
}
function delete_transient( $k ) { unset( $GLOBALS['__transients'][ $k ] ); return true; }
function wp_login_url() { return 'https://example.test/wp-login.php'; }
function admin_url( $p = '' ) { return 'https://example.test/wp-admin/' . $p; }
function add_query_arg( $k, $v, $url ) { return $url . ( strpos( $url, '?' ) === false ? '?' : '&' ) . $k . '=' . $v; }
function wp_validate_redirect( $url, $fallback ) { return $url; }
function user_can( $user, $cap ) { return false; }
function wp_set_current_user( $uid ) {}
function wp_set_auth_cookie( $uid, $remember = false ) { $GLOBALS['__auth'] = array( 'uid' => $uid, 'remember' => $remember ); }
function do_action( $hook, ...$a ) {}
function wp_rand( $min = 0, $max = 1 ) { return 1; } // never trigger RateLimit gc in tests

// Shared $wpdb double: option_name is UNIQUE, which is what caps the attempts.
require_once __DIR__ . '/lib/wpdb-options.php';
class WPDB_SF extends WPDB_Options {}
$GLOBALS['wpdb'] = new WPDB_SF();

spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$path = __DIR__ . '/../src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

use RaplsPasskey\Integrations\SecondFactor\Provider;
use RaplsPasskey\Security\AuthSession;
use RaplsPasskey\Security\SecondFactor;

/** A stand-in 2FA plugin: configured for user 1, not for user 2. */
class FakeProvider implements Provider {
	public function is_available(): bool { return true; }
	public function label(): string { return 'Fake 2FA'; }
	public function enabled_for( WP_User $user ): bool { return 1 === $user->ID; }
	public function render( WP_User $user ): void { echo '<input name="fake_code">'; }
	public function validate( WP_User $user ): bool {
		return isset( $_POST['fake_code'] ) && '123456' === $_POST['fake_code'];
	}
}

/** Install / remove the fake 2FA plugin, the way the provider filter would. */
function fake_2fa( bool $installed ): void {
	if ( $installed ) {
		$GLOBALS['__filters']['rapls_passkey/second_factor_providers'] = function () {
			return array( new FakeProvider() );
		};
	} else {
		unset( $GLOBALS['__filters']['rapls_passkey/second_factor_providers'] );
	}
}

$pass  = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$alice = new WP_User( 1, 'alice' ); // Has a second factor.
$bob   = new WP_User( 2, 'bob' );   // Does not.

$GLOBALS['__opt']['rapls_passkey_settings'] = array( 'alt_login_second_factor' => true );

// --- Which contexts are weaker than a passkey? -----------------------------

check( 'magic link is weak', SecondFactor::weak_context( 'magic-link' ) === true );
check( 'recovery code is weak', SecondFactor::weak_context( 'recovery-code' ) === true );
check( 'passkey login is not weak', SecondFactor::weak_context( 'login' ) === false );
check( 'QR cross-device is not weak (the phone signs an assertion)', SecondFactor::weak_context( 'qr-channel' ) === false );
check( 'sign-up is not weak (a passkey is created and verified)', SecondFactor::weak_context( 'signup' ) === false );
check( 'passkey login WITHOUT user verification is weak (F-05)', SecondFactor::weak_context( 'login', false ) === true );
check( 'passkey login WITH user verification is not weak', SecondFactor::weak_context( 'login', true ) === false );

// --- No 2FA plugin installed: nothing changes. ----------------------------

fake_2fa( false );
check( 'no 2FA plugin => no provider', SecondFactor::provider_for( $alice ) === null );
check( 'no 2FA plugin => no challenge', SecondFactor::required( $alice, 'magic-link' ) === false );

$GLOBALS['__auth'] = null;
check( 'magic-link login completes as before', AuthSession::login( $alice, 'magic-link', false ) === null );
check( 'the auth cookie was set', is_array( $GLOBALS['__auth'] ) && 1 === $GLOBALS['__auth']['uid'] );

// --- 2FA plugin installed. ------------------------------------------------

fake_2fa( true );

check( 'provider found for a user with 2FA on', SecondFactor::provider_for( $alice ) instanceof FakeProvider );
check( 'no provider for a user without 2FA', SecondFactor::provider_for( $bob ) === null );

check( 'magic link owes a challenge', SecondFactor::required( $alice, 'magic-link' ) === true );
check( 'recovery code owes a challenge', SecondFactor::required( $alice, 'recovery-code' ) === true );
check( 'passkey login is never challenged', SecondFactor::required( $alice, 'login' ) === false );
check( 'a UV=false passkey login IS challenged (F-05)', SecondFactor::required( $alice, 'login', false ) === true );
check( 'a UV=true passkey login is not challenged', SecondFactor::required( $alice, 'login', true ) === false );
check( 'QR login is never challenged', SecondFactor::required( $alice, 'qr-channel' ) === false );
check( 'a user with no second factor is never challenged', SecondFactor::required( $bob, 'magic-link' ) === false );

// The setting turns the whole gate off.
$GLOBALS['__opt']['rapls_passkey_settings'] = array( 'alt_login_second_factor' => false );
check( 'the setting can turn the gate off', SecondFactor::required( $alice, 'magic-link' ) === false );
$GLOBALS['__opt']['rapls_passkey_settings'] = array( 'alt_login_second_factor' => true );

// --- AuthSession parks the login instead of setting the cookie. -----------

$GLOBALS['__auth'] = null;
$_COOKIE           = array();
$result            = AuthSession::login( $alice, 'magic-link', true );

check( 'a weak login is refused a cookie', $result instanceof WP_Error );
check( 'the refusal names the 2FA gate', $result instanceof WP_Error && 'rapls_passkey_2fa_required' === $result->get_error_code() );
check( 'no auth cookie was set', null === $GLOBALS['__auth'] );

$data = $result instanceof WP_Error ? $result->get_error_data() : array();
check( 'the caller is handed the challenge URL', is_array( $data ) && false !== strpos( (string) ( $data['redirect'] ?? '' ), 'action=rapls_passkey_2fa' ) );
check( 'a pending-login cookie was issued', isset( $_COOKIE[ SecondFactor::COOKIE ] ) );

$pending = SecondFactor::pending();
check( 'the parked login remembers the user', is_array( $pending ) && 1 === $pending['user_id'] );
check( 'the parked login remembers the context', is_array( $pending ) && 'magic-link' === $pending['context'] );
check( 'the parked login remembers "remember me"', is_array( $pending ) && true === $pending['remember'] );

// The raw token must never be what is stored.
$stored_keys = implode( '|', array_keys( $GLOBALS['__transients'] ) );
check( 'the token is stored only as a hash', false === strpos( $stored_keys, $_COOKIE[ SecondFactor::COOKIE ] ) );

// --- Wrong answers are capped, then the parked login is destroyed. ---------

// The attempt is CLAIMED BEFORE the provider is asked (V49-A04): counting the
// failure afterwards bounded how many wrong answers were RECORDED, not how many
// were checked, so simultaneous submissions all had their code validated first.
$slots = array();
for ( $i = 1; $i <= 5; $i++ ) {
	$slots[] = SecondFactor::claim_attempt();
}
check( 'each attempt claims its own slot, in order (V49-A04)', array( 1, 2, 3, 4, 5 ) === $slots );
check( 'the fifth spends the parked login', SecondFactor::pending() === null );
check( 'and there is nothing left to claim', 0 === SecondFactor::claim_attempt() );

// --- Answering the challenge completes the login. -------------------------

$GLOBALS['__auth'] = null;
$_COOKIE           = array();
AuthSession::login( $alice, 'recovery-code', false );
check( 'recovery-code login is parked too', null === $GLOBALS['__auth'] );

// The challenge screen re-enters with $second_factor = true.
check( 'the completed challenge lets the login through', AuthSession::login( $alice, 'recovery-code', false, true ) === null );
check( 'the auth cookie is set only then', is_array( $GLOBALS['__auth'] ) && 1 === $GLOBALS['__auth']['uid'] );

// --- Fail-closed: a 2FA plugin that cannot report its state. --------------

use RaplsPasskey\Integrations\SecondFactor\ProviderUnavailable;

class BrokenProvider implements Provider {
	public function is_available(): bool { return true; }
	public function label(): string { return 'Broken 2FA'; }
	public function enabled_for( WP_User $user ): bool { throw new ProviderUnavailable( 'api changed' ); }
	public function render( WP_User $user ): void {}
	public function validate( WP_User $user ): bool { return false; }
}
$GLOBALS['__filters']['rapls_passkey/second_factor_providers'] = function () {
	return array( new BrokenProvider() );
};

check( 'an unreadable provider makes the gate BLOCK', SecondFactor::evaluate( $alice, 'magic-link' ) === SecondFactor::GATE_BLOCK );
check( 'a BLOCK is not reported as a challenge', SecondFactor::required( $alice, 'magic-link' ) === false );

$GLOBALS['__auth'] = null;
$_COOKIE           = array();
$blocked           = AuthSession::login( $alice, 'magic-link', false );
check( 'a weak login is refused when 2FA cannot be verified', $blocked instanceof WP_Error && 'rapls_passkey_2fa_unavailable' === $blocked->get_error_code() );
check( 'no cookie is set on a fail-closed refusal', null === $GLOBALS['__auth'] );

// A non-weak login (passkey) is unaffected even while the provider is broken.
$GLOBALS['__auth'] = null;
check( 'a passkey login still completes while 2FA is unreadable', AuthSession::login( $alice, 'login', false ) === null );
check( 'the passkey login set its cookie', is_array( $GLOBALS['__auth'] ) && 1 === $GLOBALS['__auth']['uid'] );

fake_2fa( true );

// --- Break-glass: the bypass constant lifts the gate. ---------------------

define( 'RAPLS_PASSKEY_BYPASS', true );
check( 'RAPLS_PASSKEY_BYPASS lifts the challenge (no lockout)', SecondFactor::required( $alice, 'recovery-code' ) === false );

// V26-02: begin() parks the verified-but-incomplete login. The first factor has
// already been spent by the time it runs — a magic link followed, a recovery code
// used up — so a park that cannot be stored must be reported, not papered over
// with a challenge URL that leads to a screen with nothing to complete.
$challenge_url = SecondFactor::begin( $alice, 'magic-link', false );
check( 'begin() returns a challenge URL when the park is stored', is_string( $challenge_url ) && '' !== $challenge_url );

$GLOBALS['__store_fails'] = true;
check( 'begin() returns nothing when the park cannot be stored (V26-02)', '' === SecondFactor::begin( $alice, 'magic-link', false ) );
$GLOBALS['__store_fails'] = false;

// --- V49-A06: a challenge the browser cannot answer is not issued ------------
// The cookie's result was ignored and $_COOKIE written regardless, so the token
// looked present for the rest of THAT request only. By this point the first
// factor is already spent — a magic link consumed, a recovery code used up — so
// the user was sent to a screen they could not complete, with the code gone.
$GLOBALS['__cookie_fails'] = true;
$_COOKIE                   = array();
$GLOBALS['__transients']   = array();
$url = SecondFactor::begin( new WP_User( 21 ), 'login', false );
check( 'a challenge whose cookie cannot be sent is not issued (V49-A06)', '' === $url );
check( 'and no pending record is left behind', array() === $GLOBALS['__transients'] );
check( 'and nothing pretends the browser holds a token', ! isset( $_COOKIE[ SecondFactor::COOKIE ] ) );

// With the cookie going out, the same call works.
$GLOBALS['__cookie_fails'] = false;
$_COOKIE                   = array();
$GLOBALS['__transients']   = array();
$url2 = SecondFactor::begin( new WP_User( 21 ), 'login', false );
check( 'and with a cookie that does go out, the challenge is issued', '' !== $url2 && isset( $_COOKIE[ SecondFactor::COOKIE ] ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );

