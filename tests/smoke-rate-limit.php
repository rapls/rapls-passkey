<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Per-IP login rate limit. An attempt is CLAIMED before the assertion is verified
 * (rate_admit), so only `max` verifications per window can ever start; the gate's
 * read (rate_limited) is advisory. A successful login gives the budget back.
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
 * Minimal wpdb double. The one behaviour that matters is that option_name is
 * UNIQUE: a second INSERT of the same slot row fails instead of overwriting,
 * which is exactly what makes a cap hold under concurrency.
 */
class FakeWpdb {
	public $options       = 'wp_options';
	public $prefix        = 'wp_';
	public $store         = array();
	public $rows_affected = 0;
	public $last_error    = '';
	public $fail_next     = false; // simulate a single DB error on the next query/get_var
	public $fail_all      = false; // simulate a database that is down for every query
	/** Every suppress_errors() argument, so a test can prove the pair is balanced. */
	public $suppress_calls = array();
	public function suppress_errors( $s = null ) {
		$this->suppress_calls[] = $s;
		return false;   // the previous state
	}
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
		// A claim: a PLAIN insert of one slot row. option_name is unique, so a second
		// request for the same slot must FAIL rather than overwrite — that database
		// constraint is the whole enforcement mechanism.
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
		// clear(): DELETE ... WHERE option_name LIKE '<key prefix>%'
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) && preg_match( "/option_name LIKE '([^']*)%'$/", trim( $q ), $m ) ) {
			$gone = 0;
			foreach ( array_keys( $this->store ) as $name ) {
				if ( 0 === strpos( $name, $m[1] ) ) { unset( $this->store[ $name ] ); $gone++; }
			}
			$this->rows_affected = $gone;
			return $gone;
		}
		// gc(): DELETE of rows whose window has passed.
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) ) {
			$this->rows_affected = (int) ( $GLOBALS['__gc_deleted'] ?? 0 );
			return $this->rows_affected;
		}
		return 0;
	}
	/** When set, every option_value read answers with this stale value (a replica). */
	public $stale_read = null;

	public function get_var( $q ) {
		$this->last_error = '';
		if ( $this->fail_next || $this->fail_all ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return null; // get_var() returns null on a DB error
		}
		if ( null !== $this->stale_read && false !== strpos( $q, 'option_value' ) && false === strpos( $q, 'COUNT(*)' ) ) {
			return $this->stale_read;
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

// A database that cannot confirm the claim must not admit anyone.
$GLOBALS['wpdb']->store = array(); set_limit( 5 );
$GLOBALS['wpdb']->fail_all = true;
check( 'DB error admits nobody (fail closed)', $admitted() === false );
$GLOBALS['wpdb']->fail_all = false;

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

// --- Attempt slots: admission decided by a constraint, never by a count -------
$RL = 'RaplsPasskey\\Support\\RateLimit';

// admit() returns the caller's OWN slot number, from a row only it can hold, so a
// caller that must act on the Nth attempt (2FA, QR code tries) can rely on it
// without reading a shared total.
$GLOBALS['wpdb']->store = array();
$slots = array();
for ( $i = 0; $i < 7; $i++ ) { $slots[] = $RL::admit( 'a|k', 3600, 4 ); }
check( 'admit() hands out 1,2,3,4 then refuses with 0', array( 1, 2, 3, 4, 0, 0, 0 ) === $slots );
check( 'used() reports the slots held (advisory)', $RL::used( 'a|k', 3600 ) === 4 );
check( 'clear() gives the whole budget back', ( function () use ( $RL ) {
	$RL::clear( 'a|k' );
	return 0 === $RL::used( 'a|k', 3600 ) && 1 === $RL::admit( 'a|k', 3600, 4 );
} )() );

// V15-02: the window boundary must not be a hole. A window ending exactly at
// "now" has already passed, so admissions land in the NEXT window — and every
// concurrent caller agrees on that, rather than one seeing "expired, count 0"
// while another keeps adding to the old window.
$GLOBALS['wpdb']->store = array();
$boundary = ( intdiv( time(), 60 ) + 1 ) * 60;   // the window end admit() will use
for ( $i = 0; $i < 3; $i++ ) { $RL::admit( 'b|k', 60, 3 ); }
$names = array_keys( $GLOBALS['wpdb']->store );
check( 'slots are stamped with the half-open window end', 3 === count( array_filter(
	$names,
	static fn( $n ) => false !== strpos( $n, '_' . $boundary . '_' )
) ) );
check( 'at the cap the window admits nobody, boundary or not', $RL::admit( 'b|k', 60, 3 ) === 0 );
// A row left over from a window that ended exactly now must not be reusable as
// budget: the next window has its own, separate slot names.
$GLOBALS['wpdb']->store = array( 'rapls_passkey_ra_' . md5( 'c|k' ) . '_' . time() . '_1' => time() . ':stale' );
check( 'a slot from the just-ended window does not consume the new one', $RL::admit( 'c|k', 60, 1 ) === 1 );

// V16-02 / P3-01: a request that is refused must leave NOTHING behind, whatever a
// reader says. The reader here is deliberately hostile — it answers every read
// with a stale token from slots that were released long ago — because claiming
// must not consult a reader at all.
$GLOBALS['wpdb']->store = array();
$GLOBALS['wpdb']->stale_read = '999999999:someone-elses-old-token';
$before = count( $GLOBALS['wpdb']->store );
$slot   = $RL::admit( 'stale|k', 3600, 5 );
check( 'a stale reader does not change the outcome of a claim', 1 === $slot );
check( 'one admitted claim writes exactly one row', 1 === count( $GLOBALS['wpdb']->store ) );

// Now fill the window so every slot is genuinely taken, and let the hostile
// reader answer while a fresh request is refused. The refused request must leave
// no rows of its own.
for ( $i = 0; $i < 4; $i++ ) { $RL::admit( 'stale|k', 3600, 5 ); }
$full = count( $GLOBALS['wpdb']->store );
check( 'the window fills to exactly the cap', 5 === $full );
$refused = $RL::admit( 'stale|k', 3600, 5 );
check( 'the next request is refused', 0 === $refused );
check( 'a refused request leaves ZERO extra rows (V16-02)', $full === count( $GLOBALS['wpdb']->store ) );
$GLOBALS['wpdb']->stale_read = null;

// admit() fails closed when ownership cannot be confirmed.
$GLOBALS['wpdb']->store = array();
$GLOBALS['wpdb']->fail_all = true;
check( 'admit() fails closed when the database is down', $RL::admit( 'd|k', 3600, 5 ) === 0 );
$GLOBALS['wpdb']->fail_all = false;
check( 'admit() with max 0 admits nothing', $RL::admit( 'd|k', 3600, 0 ) === 0 );

// --- Quota reservation: unique slot rows, token-scoped release (V14-01/V14-05) ---
// reserve() claims a NUMBERED row whose uniqueness the database enforces, so the
// cap holds without any lock and without reading affected-row counts.
$GLOBALS['wpdb']->store = array();
$tokens = array();
for ( $i = 0; $i < 8; $i++ ) {
	$t = $RL::reserve( 'q|y', 3600, 5 );
	if ( '' !== $t ) { $tokens[] = $t; }
}
check( 'reserve() admits exactly the cap and no more', count( $tokens ) === 5 && $RL::used( 'q|y', 3600, true ) === 5 );
check( 'reserve() returns "" once the cap is reached', $RL::reserve( 'q|y', 3600, 5 ) === '' );
check( 'each reservation got a distinct token', count( array_unique( $tokens ) ) === 5 );

// release() removes EXACTLY the row its token identifies.
$RL::release( 'q|y', $tokens[2] );
check( 'release() frees one slot', $RL::used( 'q|y', 3600, true ) === 4 );
check( 'a released slot can be reserved again', '' !== $RL::reserve( 'q|y', 3600, 5 ) && $RL::used( 'q|y', 3600, true ) === 5 );

// V14-05: a second release of the same token is a no-op — it cannot free somebody
// else's slot, so a double release cannot inflate or deflate the quota.
$before = $RL::used( 'q|y', 3600, true );
$RL::release( 'q|y', $tokens[2] );
check( 'releasing an already-released token is a no-op (V14-05)', $RL::used( 'q|y', 3600, true ) === $before );
$RL::release( 'q|y', '9999|1|forged-nonce' );
check( 'releasing with a forged token frees nothing (V14-05)', $RL::used( 'q|y', 3600, true ) === $before );
check( 'release with an empty token is a no-op', null === $RL::release( 'q|y', '' ) && $RL::used( 'q|y', 3600, true ) === $before );

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
check( 'a transient error never over-admits (one slot claimed at most)', '' === $after_blip || $RL::used( 'q|blip', 3600, true ) === 1 );
check( 'reserve() with cap 0 admits nothing', $RL::reserve( 'q|z', 3600, 0 ) === '' );
check( 'used() reports 0 rather than a guess when the read fails', ( function () use ( $RL ) {
	$GLOBALS['wpdb']->fail_next = true;
	// used() is advisory only — admission never consults it — so an unreadable
	// count reports 0 instead of pretending to know.
	return $RL::used( 'q|z', 3600, true ) === 0;
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
check( 'a token from another window frees nothing', $RL::used( 'w|k', 3600, true ) === 1 );
$RL::release( 'w|k', $live );
check( 'the matching token frees its slot', $RL::used( 'w|k', 3600, true ) === 0 );

// V24-02 / V25-03: losing a slot to somebody else is the normal outcome here, so
// the duplicate it produces must not be logged as a database error — and the
// suppression must be put back exactly as it was found.
$GLOBALS['wpdb']->suppress_calls = array();
$RL::admit( 'suppress|key', 3600, 2 );
check( 'the slot claim suppresses errors and restores the previous state (V25-03)', array( true, false ) === $GLOBALS['wpdb']->suppress_calls );

$GLOBALS['wpdb']->suppress_calls = array();
$RL::admit( 'suppress|key', 3600, 2 );   // second claimant: slot 1 is taken, slot 2 free
check( 'and does so once per slot it tries', 0 === count( $GLOBALS['wpdb']->suppress_calls ) % 2 && count( $GLOBALS['wpdb']->suppress_calls ) >= 2 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
