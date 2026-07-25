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
function wp_generate_password( $len = 12, $special = true, $extra = false ) {
	// Each reservation must get a distinct token, so this must be genuinely unique.
	return substr( str_replace( '.', '', uniqid( '', true ) ) . bin2hex( random_bytes( 8 ) ), 0, $len );
}
function __( $s, $d = null ) { return $s; }

class WP_Error {
	private $code; private $message; private $data;
	public function __construct( $code = '', $message = '', $data = array() ) {
		$this->code = $code; $this->message = $message; $this->data = $data;
	}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
	public function get_error_data() { return $this->data; }
}

/**
 * Minimal wpdb double emulating the atomic fixed-window counter: option_name is
 * unique, and INSERT ... ON DUPLICATE KEY UPDATE either starts a new window or
 * increments "count:window_end" in place.
 */
class FakeWpdb {
	public $options       = 'wp_options';
	public $prefix        = 'wp_';
	public $store         = array();
	public $rows_affected = 0;
	public $last_error    = '';
	public $fail_next     = false; // simulate a single DB error on the next query/get_var
	public $fail_all      = false; // simulate a database that is down for every query
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
		if ( $this->fail_next || $this->fail_all ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return false; // wpdb::query() returns false on a DB error
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
		// reserve(): a PLAIN insert of one reservation slot. option_name is unique, so
		// a second request for the same slot must FAIL rather than overwrite — that
		// database constraint is what makes the quota exact.
		if ( 0 === strpos( ltrim( $q ), 'INSERT INTO' )
			&& preg_match( "/VALUES \\('([^']*)', '([^']*)', 'no'\\)/", $q, $m ) ) {
			if ( isset( $this->store[ $m[1] ] ) ) {
				$this->last_error = 'Duplicate entry';
				return false; // unique index rejects it
			}
			$this->store[ $m[1] ] = $m[2];
			$this->rows_affected  = 1;
			return 1;
		}
		// release(): token-scoped DELETE (name AND value must both match).
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) && preg_match( "/option_name = '([^']*)' AND option_value = '([^']*)'/", $q, $m ) ) {
			if ( ( $this->store[ $m[1] ] ?? null ) === $m[2] ) {
				unset( $this->store[ $m[1] ] );
				$this->rows_affected = 1;
				return 1;
			}
			return 0;
		}
		// gc(): DELETE of expired rows. Sets rows_affected so a test can prove a
		// reservation result is not confused with the GC DELETE's row count.
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) ) {
			$this->rows_affected = (int) ( $GLOBALS['__gc_deleted'] ?? 0 );
			return $this->rows_affected;
		}
		return 0;
	}
	public function get_var( $q ) {
		$this->last_error = '';
		if ( $this->fail_next || $this->fail_all ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return null; // get_var() returns null on a DB error
		}
		// reserved_count(): COUNT(*) ... LIKE '<prefix>%'
		if ( false !== strpos( $q, 'COUNT(*)' ) && preg_match( "/LIKE '([^']*)%'/", $q, $m ) ) {
			$n = 0;
			foreach ( $this->store as $name => $_ ) {
				if ( 0 === strpos( $name, $m[1] ) ) { $n++; }
			}
			return (string) $n;
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
$admit   = $ref->getMethod( 'rate_admit' );   $admit->setAccessible( true );
$clear   = $ref->getMethod( 'rate_clear' );   $clear->setAccessible( true );
$key     = $ref->getMethod( 'rate_logical_key' ); $key->setAccessible( true );
$is_limited = fn() => $limited->invoke( $ep, 'login' );
// rate_admit() consumes one attempt and returns null (admitted) or a 429 WP_Error.
$do_admit   = fn() => $admit->invoke( $ep, 'login' );
$admitted   = fn() => null === $admit->invoke( $ep, 'login' );
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

// V14-03: admission CONSUMES an attempt up front, so exactly `max` verifications
// can ever start — not "everyone who read an under-limit count".
check( 'attempt 1 admitted', $admitted() === true );
check( 'attempt 2 admitted', $admitted() === true );
check( 'attempt 3 admitted (the last one)', $admitted() === true );
check( 'attempt 4 refused', $admitted() === false );
check( 'refusal is a 429', $do_admit()->get_error_data()['status'] === 429 );
check( 'gate also reports limited', $is_limited() === true );

// The batch case the review called out: with the counter one below the limit, N
// simultaneous requests must NOT all be admitted — exactly one may be.
$GLOBALS['wpdb']->store = array(); set_limit( 5 );
$admitted() && $admitted() && $admitted() && $admitted(); // count = 4 of 5
$batch = 0;
for ( $i = 0; $i < 20; $i++ ) { if ( $admitted() ) { $batch++; } }
check( 'count=max-1: only ONE of 20 concurrent attempts is admitted (V14-03)', $batch === 1 );

// At the cap, none are admitted.
$batch = 0;
for ( $i = 0; $i < 20; $i++ ) { if ( $admitted() ) { $batch++; } }
check( 'count=max: none of 20 attempts admitted (V14-03)', $batch === 0 );

// A DB error must not admit anyone (incr returns OVERFLOW).
$GLOBALS['wpdb']->store = array(); set_limit( 5 );
$GLOBALS['wpdb']->fail_next = true;
check( 'DB error admits nobody (fail closed)', $admitted() === false );

// A successful login clears the counter.
$GLOBALS['wpdb']->store = array(); set_limit( 3 );
$admitted();
$do_clear();
check( 'cleared after success', $GLOBALS['wpdb']->store === array() && $is_limited() === false );

// Limit of 0 disables it entirely (admission is a no-op, never limited).
$GLOBALS['wpdb']->store = array(); set_limit( 0 );
check( 'limit 0 admits everything', $admitted() && $admitted() && $admitted() && $admitted() );
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

// --- Quota reservation: unique slot rows, token-scoped release (V14-01/V14-05) ---
// reserve() claims a NUMBERED row whose uniqueness the database enforces, so the
// cap holds without any lock and without reading affected-row counts.
$GLOBALS['wpdb']->store = array();
$tokens = array();
for ( $i = 0; $i < 8; $i++ ) {
	$t = $RL::reserve( 'q|y', 3600, 5 );
	if ( '' !== $t ) { $tokens[] = $t; }
}
check( 'reserve() admits exactly the cap and no more', count( $tokens ) === 5 && $RL::reserved_count( 'q|y', 3600 ) === 5 );
check( 'reserve() returns "" once the cap is reached', $RL::reserve( 'q|y', 3600, 5 ) === '' );
check( 'each reservation got a distinct token', count( array_unique( $tokens ) ) === 5 );

// release() removes EXACTLY the row its token identifies.
$RL::release( 'q|y', $tokens[2] );
check( 'release() frees one slot', $RL::reserved_count( 'q|y', 3600 ) === 4 );
check( 'a released slot can be reserved again', '' !== $RL::reserve( 'q|y', 3600, 5 ) && $RL::reserved_count( 'q|y', 3600 ) === 5 );

// V14-05: a second release of the same token is a no-op — it cannot free somebody
// else's slot, so a double release cannot inflate or deflate the quota.
$before = $RL::reserved_count( 'q|y', 3600 );
$RL::release( 'q|y', $tokens[2] );
check( 'releasing an already-released token is a no-op (V14-05)', $RL::reserved_count( 'q|y', 3600 ) === $before );
$RL::release( 'q|y', '9999|1|forged-nonce' );
check( 'releasing with a forged token frees nothing (V14-05)', $RL::reserved_count( 'q|y', 3600 ) === $before );
check( 'release with an empty token is a no-op', null === $RL::release( 'q|y', '' ) && $RL::reserved_count( 'q|y', 3600 ) === $before );

// reserve() fails closed ('') when ownership cannot be confirmed, and cap<=0 admits none.
$GLOBALS['wpdb']->store = array();
$GLOBALS['wpdb']->fail_all = true;
check( 'reserve() fails closed when the database is down', $RL::reserve( 'q|z', 3600, 5 ) === '' );
$GLOBALS['wpdb']->fail_all = false;
// A single transient error is not fatal: the slot is simply not claimed and the
// next one is tried, so a blip costs an attempt but can never exceed the cap.
$GLOBALS['wpdb']->store = array();
$GLOBALS['wpdb']->fail_next = true;
$after_blip = $RL::reserve( 'q|blip', 3600, 5 );
check( 'a transient error never over-admits (one slot claimed at most)', '' === $after_blip || $RL::reserved_count( 'q|blip', 3600 ) === 1 );
check( 'reserve() with cap 0 admits nothing', $RL::reserve( 'q|z', 3600, 0 ) === '' );
check( 'reserved_count() fails closed on a DB read error', ( function () use ( $RL ) {
	$GLOBALS['wpdb']->fail_next = true;
	return $RL::reserved_count( 'q|z', 3600 ) === $RL::OVERFLOW;
} )() );

// The opportunistic GC must not disturb a reservation's own result.
$GLOBALS['__wp_rand'] = 0;
$GLOBALS['__gc_deleted'] = 3; $GLOBALS['wpdb']->store = array();
check( 'reserve() succeeds while gc runs (no false refusal)', '' !== $RL::reserve( 'gc|a', 3600, 5 ) );
$GLOBALS['__wp_rand'] = 1; $GLOBALS['__gc_deleted'] = 0;

// A reservation belongs to ONE window: a token from an expired window cannot free
// a slot in the current one (the option name embeds the window end).
$GLOBALS['wpdb']->store = array();
$live = $RL::reserve( 'w|k', 3600, 3 );
list( $w_end, $w_slot, $w_nonce ) = explode( '|', $live );
$RL::release( 'w|k', ( (int) $w_end - 3600 ) . '|' . $w_slot . '|' . $w_nonce );
check( 'a token from another window frees nothing', $RL::reserved_count( 'w|k', 3600 ) === 1 );
$RL::release( 'w|k', $live );
check( 'the matching token frees its slot', $RL::reserved_count( 'w|k', 3600 ) === 0 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
