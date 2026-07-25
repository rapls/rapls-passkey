<?php
/**
 * RestAccess: re-opens only our namespace, only a genuine 401 authentication-
 * required error, and only when the admin has opted in — never a 403 (WAF / IP /
 * maintenance / capability) and never a foreign route. Dev/CLI-only file; excluded
 * from the distributed plugin.
 *
 *   php tests/smoke-rest-access.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Support {
	// Stub the setting RestAccess consults. Default ON so the positive cases below
	// exercise the 401-vs-403 logic; toggled OFF for the opt-in test.
	class Settings {
		public static function rest_relax_login(): bool { return $GLOBALS['__relax'] ?? true; }
	}
}

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; }
	define( 'ABSPATH', __DIR__ . '/' );

	// Minimal WP test doubles.
	class WP_Error {
		private $code;
		private $data;
		public function __construct( $code = 'rest_not_logged_in', $message = '', $data = array( 'status' => 401 ) ) { $this->code = $code; $this->data = $data; }
		public function get_error_code() { return $this->code; }
		public function get_error_data() { return $this->data; }
	}
	class WP_REST_Request {
		private $route;
		public function __construct( $route ) { $this->route = $route; }
		public function get_route() { return $this->route; }
	}
	function is_wp_error( $thing ) { return $thing instanceof WP_Error; }
	function wp_unslash( $v ) { return $v; }
	function add_filter() {}
	function apply_filters( $tag, $value, ...$rest ) { return $value; }

	require_once dirname( __DIR__ ) . '/src/Security/RestAccess.php';

	use RaplsPasskey\Security\RestAccess;

	$pass = 0;
	$failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$guard = new RestAccess( 'rapls-passkey/v1' );
	$err   = new WP_Error();

	// --- allow_authentication (uses REQUEST_URI / rest_route, no request object). ---
	unset( $GLOBALS['wp'] );
	$_SERVER['REQUEST_URI'] = '/wp-json/rapls-passkey/v1/login/options';
	check( 'auth error cleared for our route', $guard->allow_authentication( $err ) === true );

	$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
	check( 'auth error preserved for foreign route', $guard->allow_authentication( $err ) === $err );

	$_SERVER['REQUEST_URI'] = '/wp-json/rapls-passkey-pro/v1/channel/create';
	check( 'free guard does NOT match pro namespace', $guard->allow_authentication( $err ) === $err );

	$_SERVER['REQUEST_URI'] = '/wp-json/rapls-passkey/v1/login/options';
	check( 'non-error result is left untouched', $guard->allow_authentication( null ) === null );
	check( 'true result is left untouched', $guard->allow_authentication( true ) === true );

	// rest_route query var takes precedence over REQUEST_URI.
	$GLOBALS['wp'] = (object) array( 'query_vars' => array( 'rest_route' => '/rapls-passkey/v1/login/verify' ) );
	$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
	check( 'rest_route query var matched', $guard->allow_authentication( $err ) === true );
	unset( $GLOBALS['wp'] );

	// --- allow_pre_dispatch (request object). ---
	$ours    = new WP_REST_Request( '/rapls-passkey/v1/login/options' );
	$foreign = new WP_REST_Request( '/wp/v2/users' );
	check( 'pre_dispatch clears our route to null', $guard->allow_pre_dispatch( $err, null, $ours ) === null );
	check( 'pre_dispatch preserves foreign error', $guard->allow_pre_dispatch( $err, null, $foreign ) === $err );
	check( 'pre_dispatch leaves null alone', $guard->allow_pre_dispatch( null, null, $ours ) === null );

	// --- allow_before_callbacks (request object). ---
	check( 'before_callbacks clears our route', $guard->allow_before_callbacks( $err, array(), $ours ) === null );
	check( 'before_callbacks preserves foreign', $guard->allow_before_callbacks( $err, array(), $foreign ) === $err );
	$ok = (object) array( 'data' => 1 );
	check( 'before_callbacks passes a real response through', $guard->allow_before_callbacks( $ok, array(), $ours ) === $ok );

	// --- Only a 401 "must be logged in" restriction is cleared; 403s preserved (F-14/R-02). ---
	$waf = new WP_Error( 'waf_blocked', '', array( 'status' => 403 ) ); // a security plugin's own error
	check( 'pre_dispatch does NOT clear a non-auth error on our route', $guard->allow_pre_dispatch( $waf, null, $ours ) === $waf );
	check( 'before_callbacks does NOT clear a non-auth error on our route', $guard->allow_before_callbacks( $waf, array(), $ours ) === $waf );

	// A 403 forbidden (WAF / IP gate / maintenance / capability) is preserved even if
	// it reuses an auth-flavoured code name — the status gate keeps it.
	$forbidden = new WP_Error( 'rest_forbidden', '', array( 'status' => 403 ) );
	check( 'pre_dispatch preserves a 403 forbidden on our route', $guard->allow_pre_dispatch( $forbidden, null, $ours ) === $forbidden );
	$reused = new WP_Error( 'rest_not_logged_in', '', array( 'status' => 403 ) );
	check( 'a 403 that reuses an auth code is still preserved', $guard->allow_pre_dispatch( $reused, null, $ours ) === $reused );

	// A genuine 401 authentication-required block on our route IS cleared (opt-in ON).
	$login_required = new WP_Error( 'rest_login_required', '', array( 'status' => 401 ) );
	check( 'pre_dispatch clears a 401 authentication-required code', $guard->allow_pre_dispatch( $login_required, null, $ours ) === null );

	// --- Opt-in OFF (default): even a 401 auth code is NOT cleared (V11-06). ---
	$GLOBALS['__relax'] = false;
	check( 'a 401 auth error is PRESERVED when the admin opt-in is off', $guard->allow_pre_dispatch( $login_required, null, $ours ) === $login_required );
	check( 'auth hook also preserves when opt-in is off', $guard->allow_authentication( $err ) === $err );
	$GLOBALS['__relax'] = true;

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
