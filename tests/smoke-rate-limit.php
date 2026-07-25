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
function wp_rand( $min = 0, $max = 1 ) { return $GLOBALS['__wp_rand'] ?? 1; } // 0 forces the opportunistic gc branch

/**
 * Minimal wpdb double emulating the atomic fixed-window counter: option_name is
 * unique, and INSERT ... ON DUPLICATE KEY UPDATE either starts a new window or
 * increments "count:window_end" in place.
 */
class FakeWpdb {
	public $options       = 'wp_options';
	public $store         = array();
	public $rows_affected = 0;
	public $last_error    = '';
	public $fail_next     = false; // simulate a single DB error on the next query/get_var
	public function prepare( $q, ...$a ) {
		foreach ( $a as $x ) {
			$rep = is_int( $x ) ? (string) $x : "'" . str_replace( "'", "''", (string) $x ) . "'";
			$q   = preg_replace( '/%[dsf]/', $rep, $q, 1 );
		}
		return $q;
	}
	public function esc_like( $s ) { return $s; }
	public function query( $q ) {
		$this->rows_affected = 0;
		$this->last_error    = '';
		if ( $this->fail_next ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return false; // wpdb::query() returns false on a DB error
		}
		// reserve(): ON DUPLICATE with a cap check on the COUNT part (":1") — must be
		// matched BEFORE the plain incr branch, which shares "ON DUPLICATE KEY UPDATE".
		if ( false !== strpos( $q, 'ON DUPLICATE KEY UPDATE' ) && preg_match( "/', 1\\) AS UNSIGNED\\) < (\\d+)/", $q, $cap ) ) {
			preg_match( "/VALUES \\('([^']*)', '([^']*)', 'no'\\)/", $q, $m );
			preg_match( "/', -1\\) AS UNSIGNED\\) < (\\d+)/", $q, $n );
			$name = $m[1]; $init = $m[2]; $now = (int) $n[1]; $capn = (int) $cap[1];
			if ( ! isset( $this->store[ $name ] ) ) {
				$this->store[ $name ] = $init; $this->rows_affected = 1; // inserted
			} else {
				list( $c, $e ) = explode( ':', $this->store[ $name ], 2 );
				if ( (int) $e < $now ) {
					$this->store[ $name ] = $init; $this->rows_affected = 2; // window reset
				} elseif ( (int) $c < $capn ) {
					$this->store[ $name ] = ( (int) $c + 1 ) . ':' . $e; $this->rows_affected = 2; // reserved
				} else {
					$this->rows_affected = 0; // cap reached — unchanged
				}
			}
			return 1;
		}
		if ( false !== strpos( $q, 'ON DUPLICATE KEY UPDATE' ) ) {
			preg_match( "/VALUES \\('([^']*)', '([^']*)', 'no'\\)/", $q, $m );
			preg_match( "/', -1\\) AS UNSIGNED\\) < (\\d+)/", $q, $n );
			$name = $m[1]; $init = $m[2]; $now = (int) $n[1];
			if ( ! isset( $this->store[ $name ] ) ) {
				$this->store[ $name ] = $init;
			} else {
				list( $c, $e ) = explode( ':', $this->store[ $name ], 2 );
				$this->store[ $name ] = ( (int) $e < $now ) ? $init : ( ( (int) $c + 1 ) . ':' . $e );
			}
			$this->rows_affected = 1;
			return 1;
		}
		// release(): UPDATE ... GREATEST(count - 1, 0) scoped to an EXACT window end.
		if ( false !== strpos( $q, 'GREATEST' ) && preg_match( "/option_name = '([^']*)'/", $q, $m ) ) {
			preg_match( "/', -1\\) AS UNSIGNED\\) = (\\d+)/", $q, $n );
			$name = $m[1]; $end = (int) ( $n[1] ?? 0 );
			if ( isset( $this->store[ $name ] ) ) {
				list( $c, $e ) = explode( ':', $this->store[ $name ], 2 );
				if ( (int) $e === $end ) { // only the matching window
					$this->store[ $name ] = max( (int) $c - 1, 0 ) . ':' . $e;
					$this->rows_affected = 1;
				}
			}
			return 1;
		}
		// gc(): DELETE of expired rows. Sets rows_affected so a test can prove reserve()
		// reads its OWN rows_affected and not the GC DELETE's.
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) ) {
			$this->rows_affected = (int) ( $GLOBALS['__gc_deleted'] ?? 0 );
			return $this->rows_affected;
		}
		return 0;
	}
	public function get_var( $q ) {
		$this->last_error = '';
		if ( $this->fail_next ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return null; // get_var() returns null on a DB error
		}
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
require_once dirname( __DIR__ ) . '/src/Support/RateLimit.php';
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

// --- RateLimit primitives: fail-closed + atomic reservation (R-03) ------------
$RL = 'RaplsPasskey\\Support\\RateLimit';

// incr()/count() FAIL CLOSED (return OVERFLOW) on a DB error, so a caller that
// gates on "count > max" blocks instead of silently admitting the request.
$GLOBALS['wpdb']->store = array();
$GLOBALS['wpdb']->fail_next = true;
check( 'incr() returns OVERFLOW on a DB write error (fail closed)', $RL::incr( 'k|x', 60 ) === $RL::OVERFLOW );
$GLOBALS['wpdb']->store = array( 'rapls_passkey_rl_' . md5( 'k|x' ) => '1:' . ( time() + 60 ) );
$GLOBALS['wpdb']->fail_next = true;
check( 'count() returns OVERFLOW on a DB read error (fail closed)', $RL::count( 'k|x' ) === $RL::OVERFLOW );

// reserve() returns the window end (>0) while admitting; 0 once the cap is reached.
// The check-and-act is one atomic statement so concurrent callers cannot overshoot.
$GLOBALS['wpdb']->store = array();
$admitted = 0; $last_end = 0;
for ( $i = 0; $i < 8; $i++ ) { $e = $RL::reserve( 'q|y', 3600, 5 ); if ( $e > 0 ) { $admitted++; $last_end = $e; } }
check( 'reserve() admits exactly the cap and no more', $admitted === 5 && $RL::count( 'q|y' ) === 5 );
check( 'reserve() returns 0 once the cap is reached', $RL::reserve( 'q|y', 3600, 5 ) === 0 );

// release() hands one slot back to the SAME window (floored at 0).
$RL::release( 'q|y', $last_end );
check( 'release() returns one slot', $RL::count( 'q|y' ) === 4 );
check( 'a released slot can be reserved again', $RL::reserve( 'q|y', 3600, 5 ) > 0 && $RL::count( 'q|y' ) === 5 );

// reserve() also fails closed (0) on a DB error, and cap<=0 admits none.
$GLOBALS['wpdb']->fail_next = true;
check( 'reserve() fails closed on a DB error', $RL::reserve( 'q|z', 3600, 5 ) === 0 );
check( 'reserve() with cap 0 admits nothing', $RL::reserve( 'q|z', 3600, 0 ) === 0 );

// V11-02: reserve() must read its OWN rows_affected, not the GC DELETE's, when the
// opportunistic gc runs (wp_rand()===0).
$GLOBALS['__wp_rand'] = 0;
// (a) fresh reservation succeeds even though the GC deletes 0 rows.
$GLOBALS['__gc_deleted'] = 0; $GLOBALS['wpdb']->store = array();
check( 'reserve() still succeeds when gc runs and deletes 0 (no false refusal)', $RL::reserve( 'gc|a', 3600, 5 ) > 0 );
// (b) at-cap reservation still fails even though the GC deletes some rows.
$GLOBALS['__gc_deleted'] = 3;
$GLOBALS['wpdb']->store = array( 'rapls_passkey_rl_' . md5( 'gc|b' ) => '5:' . ( time() + 3600 ) );
check( 'reserve() still refuses at the cap when gc deletes rows (no false admit)', $RL::reserve( 'gc|b', 3600, 5 ) === 0 );
$GLOBALS['__wp_rand'] = 1; $GLOBALS['__gc_deleted'] = 0;

// V11-04: release() is scoped to the exact window it was issued for, so a late
// failure from an old window cannot decrement a newer (reset) window's count.
$end  = time() + 1000;
$name = 'rapls_passkey_rl_' . md5( 'w|k' );
$GLOBALS['wpdb']->store[ $name ] = '3:' . $end;
$RL::release( 'w|k', $end - 1 ); // a different (older) window end
check( 'release for a different window is a no-op (V11-04)', $GLOBALS['wpdb']->store[ $name ] === '3:' . $end );
$RL::release( 'w|k', $end ); // the matching window
check( 'release for the matching window decrements (V11-04)', $GLOBALS['wpdb']->store[ $name ] === '2:' . $end );
check( 'release with window_end 0 is a no-op', ( $RL::release( 'w|k', 0 ) ) === null && $GLOBALS['wpdb']->store[ $name ] === '2:' . $end );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
