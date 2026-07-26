<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * UserHandle: one stable handle per user. It is DERIVED from the user id and the
 * site salt rather than minted and stored, so concurrent first uses, retries and
 * readers that lag behind all arrive at the same value (F-19, R21-04). A handle
 * already stored — a passwordless sign-up adopting the one its ceremony used —
 * always wins.
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

require dirname( __DIR__ ) . '/vendor/autoload.php';
require dirname( __DIR__ ) . '/src/Credentials/UserHandle.php';

use RaplsPasskey\Credentials\UserHandle;

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// R21-04: with nothing stored, the handle is DERIVED — a pure function of the
// user id and the site salt. No lock row, no insert, nothing read back.
$h1 = UserHandle::get( 7 );
check( 'get() returns a non-empty handle', is_string( $h1 ) && '' !== $h1 );
check( 'no lock row is written any more', ! isset( $GLOBALS['wpdb']->store[ UserHandle::LOCK_PREFIX . 7 ] ) );
check( 'nothing is written to user meta either', ! isset( $GLOBALS['__m'][ '7:' . UserHandle::META ] ) );

// Stable across calls, and — the point of the change — stable across
// CONCURRENT first uses and retries, because it is computed, not minted.
check( 'handle is stable across calls', $h1 === UserHandle::get( 7 ) );
check( 'raw() is 32 bytes', strlen( UserHandle::raw( 7 ) ) === 32 );
check( 'different users get different handles', UserHandle::get( 7 ) !== UserHandle::get( 8 ) );

// A hostile reader that answers every meta read with '' (a replica that has not
// caught up) must not produce a NEW handle — that is exactly how one account's
// credentials used to end up split across two WebAuthn identities.
$GLOBALS['__m'] = array();
$under_stale_reads = UserHandle::get( 7 );
check( 'a stale reader still yields the same handle (R21-04)', $under_stale_reads === $h1 );

// An account that already carries a stored handle keeps it: the stored value
// always wins over the derived one.
$GLOBALS['__m'][ '9:' . UserHandle::META ] = 'STORED-HANDLE';
check( 'a stored handle takes precedence over the derived one', UserHandle::get( 9 ) === 'STORED-HANDLE' );

// adopt(): sign-up hands the account the handle its ceremony already used.
check( 'adopt() stores the ceremony handle', UserHandle::adopt( 11, 'CEREMONY-HANDLE' ) === true );
check( 'and get() returns it from then on', UserHandle::get( 11 ) === 'CEREMONY-HANDLE' );
check( 'adopt() rejects an empty handle', UserHandle::adopt( 12, '' ) === false );
check( 'adopt() rejects a bad user id', UserHandle::adopt( 0, 'X' ) === false );

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
