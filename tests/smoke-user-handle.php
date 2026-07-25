<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * UserHandle: stable per-user handle, created atomically on first use so a
 * concurrent first registration cannot mint two different handles (F-19).
 *
 *   php tests/smoke-user-handle.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['__m'] = array();

function get_user_meta( $id, $key, $single = false ) {
	return $GLOBALS['__m'][ "$id:$key" ] ?? '';
}
function update_user_meta( $id, $key, $val ) { $GLOBALS['__m'][ "$id:$key" ] = $val; return true; }
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

// First use mints a handle via the atomic lock insert.
$h1 = UserHandle::get( 7 );
check( 'get() returns a non-empty handle', is_string( $h1 ) && '' !== $h1 );
check( 'first use took the atomic lock', isset( $GLOBALS['wpdb']->store[ UserHandle::LOCK_PREFIX . 7 ] ) );
check( 'the handle was stored in user meta', ( $GLOBALS['__m'][ '7:' . UserHandle::META ] ?? '' ) === $h1 );

// Stable across calls (no second insert; served from meta).
$h2 = UserHandle::get( 7 );
check( 'handle is stable across calls', $h1 === $h2 );

// raw() decodes to 32 bytes.
check( 'raw() is 32 bytes', strlen( UserHandle::raw( 7 ) ) === 32 );

// Race: a concurrent request already took the lock for user 9 and wrote its
// handle there. Our INSERT loses (unique violation), so get() must return the
// winner's handle from the lock row, not a fresh one.
$winner = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded( str_repeat( "\x41", 32 ) );
$GLOBALS['wpdb']->store[ UserHandle::LOCK_PREFIX . 9 ] = $winner; // Winner already holds the lock.
$h = UserHandle::get( 9 );
check( 'the race loser returns the winner\'s handle, not a fresh one', $h === $winner );
check( 'the loser mirrors the winner handle into user meta', ( $GLOBALS['__m'][ '9:' . UserHandle::META ] ?? '' ) === $winner );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
