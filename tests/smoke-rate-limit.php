<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Per-IP login rate limit: the fixed-window counter blocks once the max is
 * reached, and a successful login clears the counter so successes do not
 * accumulate toward the limit.
 *
 *   php tests/smoke-rate-limit.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// In-memory transient store.
$GLOBALS['__t'] = array();
function get_transient( $k ) { return $GLOBALS['__t'][ $k ] ?? false; }
function set_transient( $k, $v, $ttl ) { $GLOBALS['__t'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['__t'][ $k ] ); return true; }
function sanitize_text_field( $s ) { return is_string( $s ) ? trim( $s ) : ''; }
function wp_unslash( $s ) { return $s; }

require dirname( __DIR__ ) . '/src/Rest/Endpoints.php';

use RaplsPasskey\Rest\Endpoints;

$_SERVER['REMOTE_ADDR'] = '203.0.113.7';

$ep  = ( new ReflectionClass( Endpoints::class ) )->newInstanceWithoutConstructor();
$ref = new ReflectionClass( Endpoints::class );
$ok    = $ref->getMethod( 'rate_ok' );    $ok->setAccessible( true );
$clear = $ref->getMethod( 'rate_clear' ); $clear->setAccessible( true );
$key   = $ref->getMethod( 'rate_key' );   $key->setAccessible( true );
$call_ok    = fn( $max, $win ) => $ok->invoke( $ep, 'login', $max, $win );
$call_clear = fn() => $clear->invoke( $ep, 'login' );

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// Fresh: first 3 attempts allowed with a max of 3, 4th blocked.
$GLOBALS['__t'] = array();
check( 'attempt 1 of 3 allowed', $call_ok( 3, 300 ) === true );
check( 'attempt 2 of 3 allowed', $call_ok( 3, 300 ) === true );
check( 'attempt 3 of 3 allowed', $call_ok( 3, 300 ) === true );
check( 'attempt 4 blocked (over limit)', $call_ok( 3, 300 ) === false );
check( 'still blocked on retry',         $call_ok( 3, 300 ) === false );

// A successful login clears the counter, restoring the budget.
$call_clear();
check( 'counter cleared after success', $GLOBALS['__t'] === array() );
check( 'allowed again after clear', $call_ok( 3, 300 ) === true );

// The key is per-IP (different IP keeps an independent budget).
$k1 = $key->invoke( $ep, 'login' );
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
$k2 = $key->invoke( $ep, 'login' );
check( 'per-IP key differs by IP', $k1 !== $k2 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
