<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Support\OneTimeStore: the short-lived state a login ceremony depends on.
 *
 * Two properties are the whole point of the class and are asserted here:
 *
 *  - it never touches the transient API, because a transient goes to the object
 *    cache when one is installed, and an object cache is not guaranteed to hand
 *    the next request what this one wrote. A ceremony stored while answering
 *    login/options was then not there for login/verify, and a correct passkey
 *    was refused as expired;
 *  - take() is single use, decided by the DELETE and not by a read, so of two
 *    requests presenting the same challenge exactly one is answered.
 *
 *   php tests/smoke-one-time-store.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// If any of these is ever called, the class has gone back to a store the next
// request may not be able to read. They fail the test rather than the site.
$GLOBALS['__transient_calls'] = array();
function set_transient( $k, $v, $t = 0 ) { $GLOBALS['__transient_calls'][] = 'set:' . $k; return true; }
function get_transient( $k ) { $GLOBALS['__transient_calls'][] = 'get:' . $k; return false; }
function delete_transient( $k ) { $GLOBALS['__transient_calls'][] = 'del:' . $k; return true; }
function get_option( $k, $d = false ) { $GLOBALS['__transient_calls'][] = 'opt:' . $k; return $d; }
function update_option( $k, $v, $a = null ) { $GLOBALS['__transient_calls'][] = 'opt:' . $k; return true; }

// 0 forces the opportunistic sweep; anything else skips it.
$GLOBALS['__wp_rand'] = 1;
function wp_rand( $min = 0, $max = 1 ) { return $GLOBALS['__wp_rand']; }

require_once __DIR__ . '/lib/wpdb-options.php';
$GLOBALS['wpdb'] = new WPDB_Options();

require dirname( __DIR__ ) . '/src/Support/OneTimeStore.php';

use RaplsPasskey\Support\OneTimeStore;

$pass  = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}
function rows() {
	return $GLOBALS['wpdb']->store;
}
function reset_store() {
	$GLOBALS['wpdb']->store     = array();
	$GLOBALS['wpdb']->fail_next = false;
	$GLOBALS['wpdb']->fail_all  = false;
}

// --- Round trip -----------------------------------------------------------

check( 'a payload can be stored', true === OneTimeStore::put( 'abc123', 'hello', 600 ) );
check( 'and read back unchanged', 'hello' === OneTimeStore::peek( 'abc123' ) );
check( 'peeking does not consume it', 'hello' === OneTimeStore::peek( 'abc123' ) );

$names = array_keys( rows() );
check( 'exactly one row was written', 1 === count( $names ) );
check( 'the row is namespaced to this class', 0 === strpos( (string) $names[0], 'rapls_pk_ot_' ) );
check( 'the key is part of the row name', false !== strpos( (string) $names[0], 'abc123' ) );

// A payload containing the separator must survive: option values are arbitrary.
OneTimeStore::put( 'sep', 'a|b|c', 600 );
check( 'a payload containing the separator round-trips', 'a|b|c' === OneTimeStore::peek( 'sep' ) );

// JSON is what the callers actually store.
$json = (string) json_encode( array( 'user_id' => 7, 'remember' => true ) );
OneTimeStore::put( 'json', $json, 600 );
check( 'a JSON payload round-trips', $json === OneTimeStore::peek( 'json' ) );

// --- Single use -----------------------------------------------------------

reset_store();
OneTimeStore::put( 'once', 'payload', 600 );
$first  = OneTimeStore::take( 'once' );
$second = OneTimeStore::take( 'once' );
check( 'the first take() is answered', 'payload' === $first );
check( 'the second take() is not', null === $second );
check( 'and the row is gone', array() === rows() );

// Two callers racing for the same challenge: the read can hand both of them the
// payload, so the DELETE has to be what decides. Exactly one may be answered —
// otherwise one challenge signs in twice.
reset_store();
OneTimeStore::put( 'race', 'payload', 600 );
$answers = array_filter( array( OneTimeStore::take( 'race' ), OneTimeStore::take( 'race' ), OneTimeStore::take( 'race' ) ) );
check( 'of three simultaneous claims exactly one is answered', 1 === count( $answers ) );

// --- Expiry ---------------------------------------------------------------

reset_store();
OneTimeStore::put( 'stale', 'payload', 1 );
// Rewrite the row's stamp into the past rather than sleeping.
$name                            = array_keys( rows() )[0];
$GLOBALS['wpdb']->store[ $name ] = ( time() - 5 ) . '|payload';
check( 'an expired entry is invisible to peek()', null === OneTimeStore::peek( 'stale' ) );
check( 'and is cleared away as it is found', array() === rows() );

reset_store();
OneTimeStore::put( 'stale2', 'payload', 1 );
$name                            = array_keys( rows() )[0];
$GLOBALS['wpdb']->store[ $name ] = ( time() - 5 ) . '|payload';
check( 'an expired entry cannot be taken', null === OneTimeStore::take( 'stale2' ) );

check( 'a zero lifetime is refused', false === OneTimeStore::put( 'zero', 'x', 0 ) );
check( 'a negative lifetime is refused', false === OneTimeStore::put( 'neg', 'x', -60 ) );

// --- Keys -----------------------------------------------------------------

reset_store();
check( 'an empty key is refused', false === OneTimeStore::put( '', 'x', 600 ) );
check( 'a key with a quote is refused', false === OneTimeStore::put( "a'b", 'x', 600 ) );
check( 'a key with a percent is refused', false === OneTimeStore::put( 'a%b', 'x', 600 ) );
check( 'an over-long key is refused', false === OneTimeStore::put( str_repeat( 'a', 151 ), 'x', 600 ) );
check( 'nothing was written for any of them', array() === rows() );
check( 'a rejected key reads back as absent', null === OneTimeStore::peek( "a'b" ) );

$ok = str_repeat( 'a', 150 );
check( 'a key at the limit is accepted', true === OneTimeStore::put( $ok, 'x', 600 ) );

// --- A store that refuses --------------------------------------------------

reset_store();
$GLOBALS['wpdb']->fail_all = true;
check( 'a failed write is reported, not swallowed', false === OneTimeStore::put( 'dbdown', 'x', 600 ) );
$GLOBALS['wpdb']->fail_all = false;

// A DELETE that errors must not be read as "you won the race": that would let
// the same challenge be spent twice.
reset_store();
OneTimeStore::put( 'claimfail', 'payload', 600 );
$GLOBALS['wpdb']->fail_next = true; // the SELECT
check( 'a read error is treated as absent', null === OneTimeStore::take( 'claimfail' ) );

// --- Housekeeping ----------------------------------------------------------

reset_store();
OneTimeStore::put( 'live', 'a', 600 );
OneTimeStore::put( 'dead1', 'b', 600 );
OneTimeStore::put( 'dead2', 'c', 600 );
foreach ( array( 'dead1', 'dead2' ) as $k ) {
	$GLOBALS['wpdb']->store[ 'rapls_pk_ot_' . $k ] = ( time() - 60 ) . '|x';
}
$GLOBALS['wpdb']->store['unrelated_option'] = 'keep me';

$gone = OneTimeStore::prune();
check( 'prune removes the expired rows', 2 === $gone );
check( 'and leaves the live one', 'a' === OneTimeStore::peek( 'live' ) );
check( 'and does not touch other options', 'keep me' === ( rows()['unrelated_option'] ?? null ) );

reset_store();
foreach ( array( 'a', 'b', 'c' ) as $k ) {
	OneTimeStore::put( $k, 'x', 600 );
	$GLOBALS['wpdb']->store[ 'rapls_pk_ot_' . $k ] = ( time() - 60 ) . '|x';
}
check( 'prune honours its cap', 2 === OneTimeStore::prune( 2 ) );

reset_store();
OneTimeStore::put( 'x1', 'a', 600 );
OneTimeStore::put( 'x2', 'b', 600 );
$GLOBALS['wpdb']->store['unrelated_option'] = 'keep me';
check( 'drop_all removes every row this class owns', 2 === OneTimeStore::drop_all() );
check( 'and nothing else', array( 'unrelated_option' => 'keep me' ) === rows() );

// --- The occasional sweep --------------------------------------------------

// Nothing expires these rows on our behalf, so writes sweep now and then. It
// must never take a live ceremony with it.
reset_store();
$GLOBALS['__wp_rand'] = 1; // no sweep
OneTimeStore::put( 'keep', 'a', 600 );
$GLOBALS['wpdb']->store['rapls_pk_ot_old'] = ( time() - 60 ) . '|x';
OneTimeStore::put( 'keep2', 'b', 600 );
check( 'without the sweep, an abandoned row stays', isset( rows()['rapls_pk_ot_old'] ) );

$GLOBALS['__wp_rand'] = 0; // sweep on this write
OneTimeStore::put( 'keep3', 'c', 600 );
check( 'the sweep clears the abandoned row', ! isset( rows()['rapls_pk_ot_old'] ) );
check( 'and leaves the live ceremonies alone', 'a' === OneTimeStore::peek( 'keep' ) && 'c' === OneTimeStore::peek( 'keep3' ) );
$GLOBALS['__wp_rand'] = 1;

// --- The whole point -------------------------------------------------------

check(
	'the transient API was never used (it can be invisible to the next worker)',
	array() === $GLOBALS['__transient_calls']
);

/**
 * The CODE of a file, with comments and docblocks removed. These files explain
 * at length why they avoid the object cache, so a plain search would match the
 * explanation and pass whatever the code did.
 *
 * @param string $path Absolute path.
 * @return string
 */
function code_of( $path ) {
	$out = '';
	foreach ( token_get_all( (string) file_get_contents( $path ) ) as $t ) {
		if ( is_array( $t ) && in_array( $t[0], array( T_COMMENT, T_DOC_COMMENT ), true ) ) {
			continue;
		}
		$out .= is_array( $t ) ? $t[1] : $t;
	}
	return $out;
}

$store = code_of( dirname( __DIR__ ) . '/src/Support/OneTimeStore.php' );
check( 'the store never reaches for the object cache', false === strpos( $store, 'wp_cache_' ) );
check( 'nor decides anything on whether one is installed', false === strpos( $store, 'wp_using_ext_object_cache' ) );
check( 'nor goes through the option cache', false === strpos( $store, 'get_option' ) && false === strpos( $store, 'update_option' ) );

$challenge = code_of( dirname( __DIR__ ) . '/src/WebAuthn/ChallengeStore.php' );
check( 'the challenge store no longer branches on the object cache', false === strpos( $challenge, 'wp_using_ext_object_cache' ) );
check( 'and no longer stores challenges as transients', false === strpos( $challenge, 'set_transient' ) );

$second_factor = code_of( dirname( __DIR__ ) . '/src/Security/SecondFactor.php' );
check( 'a parked second-factor login is not a transient either', false === strpos( $second_factor, 'set_transient' ) );
check( 'and is not read back through one', false === strpos( $second_factor, 'get_transient' ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( 0 === $failc ? 0 : 1 );
