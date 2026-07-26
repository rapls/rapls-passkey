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
			if ( array_key_exists( $m[1], $this->store ) ) { return false; } // unique violation
			$this->store[ $m[1] ] = $m[2];
			return 1;
		}
		return 0;
	}
	public function get_var( $q ) {
		if ( preg_match( "/option_name = '([^']*)'/", $q, $m ) ) {
			return $this->store[ $m[1] ] ?? null;
		}
		return null;
	}
}
$GLOBALS['wpdb'] = new FakeWpdb();

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

// --- V22-02: a reader that cannot see the stored handle must REFUSE ------------
// The account above provably has a handle (its claim row exists). A replica that
// has not caught up answers the meta read with nothing — and deriving on that
// basis is precisely how one account's credentials end up split across two
// WebAuthn identities. The only safe answer is "cannot establish it".
$GLOBALS['__meta_writes_are_invisible'] = true;
$blind = UserHandle::get( 7 );
check( 'a stale reader gets null, not a second handle (V22-02)', null === $blind );
check( 'and raw() reports it as unusable, so the caller refuses', '' === UserHandle::raw( 7 ) );
$GLOBALS['__meta_writes_are_invisible'] = false;
check( 'once the reader catches up, the original handle is back', $h1 === UserHandle::get( 7 ) );

// A LEGACY account — random handle in meta, claim row back-filled by the
// migration — behaves the same way: visible means use it, invisible means refuse.
$GLOBALS['__m'][ '9:' . UserHandle::META ]                = 'LEGACY-RANDOM-HANDLE';
$GLOBALS['wpdb']->store[ UserHandle::CLAIM_PREFIX . 9 ]   = 'LEGACY-RANDOM-HANDLE';
check( 'a stored handle takes precedence over the derived one', UserHandle::get( 9 ) === 'LEGACY-RANDOM-HANDLE' );
$GLOBALS['__meta_writes_are_invisible'] = true;
check( 'a legacy handle hidden by a stale reader yields null (V22-02)', null === UserHandle::get( 9 ) );
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

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
