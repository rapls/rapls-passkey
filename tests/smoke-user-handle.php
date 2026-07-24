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

$GLOBALS['__m']       = array();
$GLOBALS['__add_log'] = 0;

function get_user_meta( $id, $key, $single = false ) {
	// One-shot: hide the value on the first read to simulate the race window
	// where our read missed but a concurrent writer then wrote the winner.
	if ( isset( $GLOBALS['__hide_once'] ) && $GLOBALS['__hide_once'] === "$id:$key" ) {
		unset( $GLOBALS['__hide_once'] );
		return '';
	}
	return $GLOBALS['__m'][ "$id:$key" ] ?? '';
}
function update_user_meta( $id, $key, $val ) { $GLOBALS['__m'][ "$id:$key" ] = $val; return true; }
function add_user_meta( $id, $key, $val, $unique = false ) {
	$GLOBALS['__add_log']++;
	if ( $unique && isset( $GLOBALS['__m'][ "$id:$key" ] ) ) { return false; } // Unique insert loses the race.
	$GLOBALS['__m'][ "$id:$key" ] = $val;
	return true;
}
function wp_cache_delete( $id, $group = '' ) { return true; }

require dirname( __DIR__ ) . '/vendor/autoload.php';
require dirname( __DIR__ ) . '/src/Credentials/UserHandle.php';

use RaplsPasskey\Credentials\UserHandle;

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// First use creates a handle via a unique insert.
$h1 = UserHandle::get( 7 );
check( 'get() returns a non-empty handle', is_string( $h1 ) && '' !== $h1 );
check( 'first use used a unique add_user_meta', $GLOBALS['__add_log'] === 1 );

// Stable across calls (no second insert).
$before = $GLOBALS['__add_log'];
$h2 = UserHandle::get( 7 );
check( 'handle is stable across calls', $h1 === $h2 );
check( 'a stored handle is not re-inserted', $GLOBALS['__add_log'] === $before );

// raw() decodes to 32 bytes.
check( 'raw() is 32 bytes', strlen( UserHandle::raw( 7 ) ) === 32 );

// Race: another request already wrote the winner's handle between our read and
// insert. add_user_meta(unique) returns false, so get() re-reads the winner's
// value instead of returning a second, different handle.
$winner = \ParagonIE\ConstantTime\Base64UrlSafe::encodeUnpadded( str_repeat( "\x41", 32 ) );
$GLOBALS['__m']['9:' . UserHandle::META] = $winner;   // The winner already wrote it.
$GLOBALS['__hide_once']                  = '9:' . UserHandle::META; // Our first read misses.
$h = UserHandle::get( 9 );
check( 'the race loser returns the winner\'s handle, not a fresh one', $h === $winner );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
