<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * UserHandle: one handle per user, and never a second one.
 *
 * A first use DERIVES the handle from the user id and the site salt and claims
 * the account's one handle row — an insert the database either accepts or
 * refuses, so concurrent first uses and retries all settle on the same value
 * (F-19, R21-04). A stored handle always wins. And when the account provably has
 * a handle that this request cannot see — a replica behind the writer — the
 * answer is null, never a freshly derived second identity (V22-02).
 *
 *   php tests/smoke-user-handle.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['__m'] = array();

function wp_salt( $scheme = 'auth' ) { return 'unit-test-salt'; }
function get_user_meta( $id, $key, $single = false ) {
	// A replica that has not applied recent writes answers with nothing.
	if ( ! empty( $GLOBALS['__meta_writes_are_invisible'] ) ) {
		return '';
	}
	return $GLOBALS['__m'][ "$id:$key" ] ?? '';
}
function update_user_meta( $id, $key, $val ) {
	if ( ! empty( $GLOBALS['__meta_write_fails'] ) ) {
		return false;
	}
	$GLOBALS['__m'][ "$id:$key" ] = $val;
	return 123; // wpdb returns the new meta_id for a first write
}
function wp_cache_delete( $id, $group = '' ) { return true; }

/**
 * Minimal wpdb double: option_name is unique-indexed, so a second INSERT of the
 * same name fails — the property UserHandle relies on for atomic first creation.
 */
class FakeWpdb {
	public $options = 'wp_options';
	public $store   = array();
	public $last_error = '';
	/** Set true to model an options table that cannot be read (a lagging replica). */
	public $blind_reads = false;
	/** Set true to model a database that refuses writes for a reason other than a duplicate. */
	public $writes_fail = false;
	public function suppress_errors( $s = null ) { return false; }
	public function prepare( $q, ...$a ) {
		foreach ( $a as $x ) {
			$rep = is_int( $x ) ? (string) $x : "'" . str_replace( "'", "''", (string) $x ) . "'";
			$q   = preg_replace( '/%[dsf]/', $rep, $q, 1 );
		}
		return $q;
	}
	public function query( $q ) {
		if ( preg_match( "/INSERT INTO .*VALUES \\('([^']*)', '([^']*)'/", $q, $m ) ) {
			if ( $this->writes_fail ) {
				$this->last_error = 'MySQL server has gone away';
				return false;
			}
			if ( array_key_exists( $m[1], $this->store ) ) {
				// What the driver actually says, because the code has to tell this
				// apart from any other failure.
				$this->last_error = "Duplicate entry '{$m[1]}' for key 'wp_options.option_name'";
				return false;
			}
			$this->last_error = '';
			$this->store[ $m[1] ] = $m[2];
			return 1;
		}
		return 0;
	}
	public function get_var( $q ) {
		if ( $this->blind_reads ) {
			return null;
		}
		if ( preg_match( "/option_name = '([^']*)'/", $q, $m ) ) {
			return $this->store[ $m[1] ] ?? null;
		}
		return null;
	}
}
$GLOBALS['wpdb'] = new FakeWpdb();

// Schema stand-in: UserHandle refuses to mint a handle until the migration that
// back-fills every existing account's claim row has completed.
eval( 'namespace RaplsPasskey\\Credentials; class Schema { public static $current = true; public static function is_current(): bool { return self::$current; } }' );

require dirname( __DIR__ ) . '/src/Credentials/UserHandle.php';

use RaplsPasskey\Credentials\UserHandle;

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// --- first use: the handle is DERIVED, and the account's claim row records it --
$h1 = UserHandle::get( 7 );
check( 'get() returns a non-empty handle', is_string( $h1 ) && '' !== $h1 );
check( 'the claim row is written, holding that handle', ( $GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 7 ] ?? null ) === $h1 );
check( 'and the handle is mirrored into user meta', ( $GLOBALS['__m'][ '7:' . UserHandle::META ] ?? null ) === $h1 );
check( 'no legacy lock row is written any more', ! isset( $GLOBALS['wpdb']->store[ UserHandle::LOCK_PREFIX . 7 ] ) );

check( 'handle is stable across calls', $h1 === UserHandle::get( 7 ) );
check( 'raw() is 32 bytes', strlen( UserHandle::raw( 7 ) ) === 32 );
check( 'different users get different handles', UserHandle::get( 7 ) !== UserHandle::get( 8 ) );

// --- V22-02: a reader that cannot see the stored handle must never invent one --
// The account above provably has a handle (its claim row exists). A replica that
// has not caught up answers the meta read with nothing — and deriving on that
// basis is precisely how one account's credentials end up split across two
// WebAuthn identities. The claim row is written once and never changed, so it can
// be used to recover the SAME handle; the one thing that must never happen is a
// different one.
$GLOBALS['__meta_writes_are_invisible'] = true;
$blind = UserHandle::get( 7 );
check( 'a stale reader never yields a second handle (V22-02)', $h1 === $blind || null === $blind );
check( 'and raw() is either the same bytes or empty', UserHandle::raw( 7 ) === ( null === $blind ? '' : UserHandle::raw( 7 ) ) );
$GLOBALS['__meta_writes_are_invisible'] = false;
check( 'once the reader catches up, the original handle is back', $h1 === UserHandle::get( 7 ) );

// A LEGACY account — random handle in meta, claim row back-filled by the
// migration — behaves the same way: visible means use it, invisible means refuse.
$GLOBALS['__m'][ '9:' . UserHandle::META ]                = 'LEGACY-RANDOM-HANDLE';
$GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 9 ]   = 'LEGACY-RANDOM-HANDLE';
check( 'a stored handle takes precedence over the derived one', UserHandle::get( 9 ) === 'LEGACY-RANDOM-HANDLE' );
$GLOBALS['__meta_writes_are_invisible'] = true;
check( 'a legacy handle hidden by a stale reader is recovered, not replaced (V22-02)', 'LEGACY-RANDOM-HANDLE' === UserHandle::get( 9 ) );
$GLOBALS['wpdb']->blind_reads = true;   // now the claim row is unreadable too
check( 'and with nothing readable at all the answer is null', null === UserHandle::get( 9 ) );
$GLOBALS['wpdb']->blind_reads = false;
$GLOBALS['__meta_writes_are_invisible'] = false;

// An id with nothing at all is still served: the claim decides, not the reader.
check( 'an account with no handle anywhere still gets one', is_string( UserHandle::get( 21 ) ) );

// --- adopt(): sign-up hands the account the handle its ceremony already used ---
check( 'adopt() stores the ceremony handle', UserHandle::adopt( 11, 'CEREMONY-HANDLE' ) === true );
check( 'adopt() claims the row too', ( $GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 11 ] ?? null ) === 'CEREMONY-HANDLE' );
check( 'and get() returns it from then on', UserHandle::get( 11 ) === 'CEREMONY-HANDLE' );
check( 'adopt() rejects an empty handle', UserHandle::adopt( 12, '' ) === false );
check( 'adopt() rejects a bad user id', UserHandle::adopt( 0, 'X' ) === false );
check( 'adopt() refuses when the account already has a handle', UserHandle::adopt( 11, 'SECOND-HANDLE' ) === false );

// R21-04: adopt() must NOT read the value back. A reader that has not caught up
// would report failure and make the caller undo a sign-up that actually worked.
$GLOBALS['__meta_writes_are_invisible'] = true;
check( 'adopt() succeeds even when reads cannot see the write yet (R21-04)', UserHandle::adopt( 13, 'WRITTEN-BUT-UNREADABLE' ) === true );
$GLOBALS['__meta_writes_are_invisible'] = false;

// A genuine write failure is still reported.
$GLOBALS['__meta_write_fails'] = true;
check( 'adopt() reports a real write failure', UserHandle::adopt( 14, 'NOPE' ) === false );
$GLOBALS['__meta_write_fails'] = false;

// --- V23-01: a legacy handle seen through the meta gets its claim row ---------
// The account has a handle from an older version and NO claim row (the migration
// has not run, or its back-fill failed). Simply returning the handle would leave
// a later stale read free to derive a second one.
$GLOBALS['__m'] = array();
$GLOBALS['wpdb']->store = array();
$GLOBALS['__m'][ '31:' . UserHandle::META ] = 'LEGACY-H1';
$legacy = UserHandle::get( 31 );
check( 'a legacy handle is returned as it is', 'LEGACY-H1' === $legacy );
check( 'and seeing it establishes the claim row (V23-01)', ( $GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 31 ] ?? null ) === 'LEGACY-H1' );

// Now the stale read that used to split the account.
$GLOBALS['__meta_writes_are_invisible'] = true;
$after = UserHandle::get( 31 );
$GLOBALS['__meta_writes_are_invisible'] = false;
check( 'a later stale read cannot derive a second identity (V23-01)', 'LEGACY-H1' === $after || null === $after );
check( 'and nothing else was written under that account', ( $GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 31 ] ?? null ) === 'LEGACY-H1' );

// If the claim row cannot be established at all, the handle is withheld rather
// than handed out with the gap still open.
$GLOBALS['__m'][ '32:' . UserHandle::META ] = 'LEGACY-H2';
$GLOBALS['wpdb']->writes_fail = true;
check( 'a handle whose claim row cannot be written is withheld (V23-01)', null === UserHandle::get( 32 ) );
$GLOBALS['wpdb']->writes_fail = false;
check( 'and it is returned again once the database recovers', 'LEGACY-H2' === UserHandle::get( 32 ) );

// --- V23-01: nothing is minted while the migration is outstanding ------------
\RaplsPasskey\Credentials\Schema::$current = false;
check( 'no handle is minted before the migration completes (V23-01)', null === UserHandle::get( 41 ) );
check( 'and no claim row is written for it', ! isset( $GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 41 ] ) );
check( 'an account that already has one is still served', 'LEGACY-H1' === UserHandle::get( 31 ) );
\RaplsPasskey\Credentials\Schema::$current = true;
check( 'and minting resumes once the migration has completed', is_string( UserHandle::get( 41 ) ) );

// --- V23-02: a claim that succeeded but whose meta write failed --------------
// The account has its identity (the claim row holds it); losing the mirror must
// not leave it permanently unable to register.
$GLOBALS['__m'] = array();
$GLOBALS['wpdb']->store = array();
$GLOBALS['__meta_write_fails'] = true;
$first = UserHandle::get( 51 );
$GLOBALS['__meta_write_fails'] = false;
check( 'a handle is still returned when its mirror write fails (V23-02)', is_string( $first ) && '' !== $first );
check( 'and the claim row holds it', ( $GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 51 ] ?? null ) === $first );
$again = UserHandle::get( 51 );
check( 'a later request recovers the same handle from that row (V23-02)', $first === $again );
check( 'and repairs the mirror', ( $GLOBALS['__m'][ '51:' . UserHandle::META ] ?? null ) === $first );

// The recovery is a read, so it can come back empty — and then the answer is
// "cannot establish", never a second handle.
$GLOBALS['__m'] = array();
$GLOBALS['wpdb']->blind_reads = true;
check( 'an unreadable claim row yields null, not a new identity (V23-02)', null === UserHandle::get( 51 ) );
$GLOBALS['wpdb']->blind_reads = false;
check( 'and the same handle comes back when the row can be read again', $first === UserHandle::get( 51 ) );

// --- V23-02: two calls in one request must agree -----------------------------
// register/options used to resolve the handle twice; between the two calls the
// first can create it while a lagging reader makes the second see nothing.
$GLOBALS['__m'] = array();
$GLOBALS['wpdb']->store = array();
$call1 = UserHandle::raw( 61 );
$GLOBALS['__meta_writes_are_invisible'] = true;
$call2 = UserHandle::raw( 61 );
$GLOBALS['__meta_writes_are_invisible'] = false;
check( 'the first call establishes a usable handle', 32 === strlen( $call1 ) );
check( 'a second call in the same request never contradicts it (V23-02)', $call2 === $call1 || '' === $call2 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
