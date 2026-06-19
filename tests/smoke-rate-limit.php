<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Per-IP login rate limit. The counter is incremented ONLY on a failed assertion
 * (rate_bump) and checked read-only by the gate (rate_limited) — so repeatedly
 * calling /login/options never accumulates. A successful login clears it.
 *
 *   php tests/smoke-rate-limit.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// In-memory transient store + settings.
$GLOBALS['__t']   = array();
$GLOBALS['__opt'] = array();
function get_transient( $k ) { return $GLOBALS['__t'][ $k ] ?? false; }
function set_transient( $k, $v, $ttl ) { $GLOBALS['__t'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['__t'][ $k ] ); return true; }
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function apply_filters( $tag, $value ) { return $value; }
function sanitize_text_field( $s ) { return is_string( $s ) ? trim( $s ) : ''; }
function wp_unslash( $s ) { return $s; }

require dirname( __DIR__ ) . '/src/Support/Settings.php';
require dirname( __DIR__ ) . '/src/Rest/Endpoints.php';

use RaplsPasskey\Rest\Endpoints;

$_SERVER['REMOTE_ADDR'] = '203.0.113.7';

$ep  = ( new ReflectionClass( Endpoints::class ) )->newInstanceWithoutConstructor();
$ref = new ReflectionClass( Endpoints::class );
$limited = $ref->getMethod( 'rate_limited' ); $limited->setAccessible( true );
$bump    = $ref->getMethod( 'rate_bump' );    $bump->setAccessible( true );
$clear   = $ref->getMethod( 'rate_clear' );   $clear->setAccessible( true );
$key     = $ref->getMethod( 'rate_key' );     $key->setAccessible( true );
$is_limited = fn() => $limited->invoke( $ep, 'login' );
$do_bump    = fn() => $bump->invoke( $ep, 'login' );
$do_clear   = fn() => $clear->invoke( $ep, 'login' );

function set_limit( $max, $window = 120 ) {
	$GLOBALS['__opt']['rapls_passkey_settings'] = array(
		'login_rate_max'    => $max,
		'login_rate_window' => $window,
	);
}

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// Limit of 3. Read-only checks never increment.
$GLOBALS['__t'] = array(); set_limit( 3 );
check( 'not limited initially', $is_limited() === false );
check( 'repeated read-only checks never lock out', $is_limited() === false && $is_limited() === false && $is_limited() === false && $is_limited() === false );

// Only failures (bump) count toward the limit.
$do_bump(); check( 'after 1 failure: not limited', $is_limited() === false );
$do_bump(); check( 'after 2 failures: not limited', $is_limited() === false );
$do_bump(); check( 'after 3 failures: limited', $is_limited() === true );
$do_bump(); check( 'stays limited after more failures', $is_limited() === true );

// A successful login clears the counter.
$do_clear();
check( 'cleared after success', $GLOBALS['__t'] === array() && $is_limited() === false );

// Limit of 0 disables it entirely (bumps are no-ops, never limited).
$GLOBALS['__t'] = array(); set_limit( 0 );
$do_bump(); $do_bump(); $do_bump(); $do_bump();
check( 'limit 0 disables the cap', $is_limited() === false && $GLOBALS['__t'] === array() );

// Per-IP key differs by IP.
set_limit( 3 );
$k1 = $key->invoke( $ep, 'login' );
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
$k2 = $key->invoke( $ep, 'login' );
check( 'per-IP key differs by IP', $k1 !== $k2 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
