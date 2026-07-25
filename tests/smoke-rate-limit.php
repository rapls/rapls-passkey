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

$GLOBALS['__opt'] = array();
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function apply_filters( $tag, $value ) { return $value; }
function sanitize_text_field( $s ) { return is_string( $s ) ? trim( $s ) : ''; }
function wp_unslash( $s ) { return $s; }
function wp_rand( $min = 0, $max = 1 ) { return 1; } // never trigger opportunistic gc in tests

/**
 * Minimal wpdb double emulating the atomic fixed-window counter: option_name is
 * unique, and INSERT ... ON DUPLICATE KEY UPDATE either starts a new window or
 * increments "count:window_end" in place.
 */
class FakeWpdb {
	public $options = 'wp_options';
	public $store   = array();
	public function prepare( $q, ...$a ) {
		foreach ( $a as $x ) {
			$rep = is_int( $x ) ? (string) $x : "'" . str_replace( "'", "''", (string) $x ) . "'";
			$q   = preg_replace( '/%[dsf]/', $rep, $q, 1 );
		}
		return $q;
	}
	public function esc_like( $s ) { return $s; }
	public function query( $q ) {
		if ( false !== strpos( $q, 'ON DUPLICATE KEY UPDATE' ) ) {
			preg_match( "/VALUES \\('([^']*)', '([^']*)', 'no'\\)/", $q, $m );
			preg_match( '/AS UNSIGNED\) < (\d+),/', $q, $n );
			$name = $m[1]; $init = $m[2]; $now = (int) $n[1];
			if ( ! isset( $this->store[ $name ] ) ) {
				$this->store[ $name ] = $init;
			} else {
				list( $c, $e ) = explode( ':', $this->store[ $name ], 2 );
				$this->store[ $name ] = ( (int) $e < $now ) ? $init : ( ( (int) $c + 1 ) . ':' . $e );
			}
			return 1;
		}
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) ) {
			return 0; // gc is stubbed out (wp_rand never triggers it)
		}
		return 0;
	}
	public function get_var( $q ) {
		if ( preg_match( "/option_name = '([^']*)'/", $q, $m ) ) {
			return $this->store[ $m[1] ] ?? null;
		}
		return null;
	}
	public function delete( $table, $where ) {
		$name = $where['option_name'] ?? '';
		unset( $this->store[ $name ] );
		return 1;
	}
}
$GLOBALS['wpdb'] = new FakeWpdb();

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
$GLOBALS['wpdb']->store = array(); set_limit( 3 );
check( 'not limited initially', $is_limited() === false );
check( 'repeated read-only checks never lock out', $is_limited() === false && $is_limited() === false && $is_limited() === false && $is_limited() === false );

// Only failures (bump) count toward the limit.
$do_bump(); check( 'after 1 failure: not limited', $is_limited() === false );
$do_bump(); check( 'after 2 failures: not limited', $is_limited() === false );
$do_bump(); check( 'after 3 failures: limited', $is_limited() === true );
$do_bump(); check( 'stays limited after more failures', $is_limited() === true );

// A successful login clears the counter.
$do_clear();
check( 'cleared after success', $GLOBALS['wpdb']->store === array() && $is_limited() === false );

// Limit of 0 disables it entirely (bumps are no-ops, never limited).
$GLOBALS['wpdb']->store = array(); set_limit( 0 );
$do_bump(); $do_bump(); $do_bump(); $do_bump();
check( 'limit 0 disables the cap', $is_limited() === false && $GLOBALS['wpdb']->store === array() );

// Per-IP key differs by IP.
set_limit( 3 );
$k1 = $key->invoke( $ep, 'login' );
$_SERVER['REMOTE_ADDR'] = '198.51.100.9';
$k2 = $key->invoke( $ep, 'login' );
check( 'per-IP key differs by IP', $k1 !== $k2 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
