<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * RestAccess: re-opens only our namespace, never touches other routes, and
 * never converts a non-error result.
 *
 *   php tests/smoke-rest-access.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// Minimal WP test doubles.
class WP_Error {}
class WP_REST_Request {
	private $route;
	public function __construct( $route ) { $this->route = $route; }
	public function get_route() { return $this->route; }
}
function is_wp_error( $thing ) { return $thing instanceof WP_Error; }
function wp_unslash( $v ) { return $v; }
function add_filter() {}

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

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
