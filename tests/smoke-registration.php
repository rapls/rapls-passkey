<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Registration ceremony: creation-options generation, challenge storage, and
 * JSON round-tripping through web-auth. Uses the real library; WordPress
 * transient / user-meta functions are stubbed in memory.
 *
 *   php tests/smoke-registration.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// --- WP stubs -------------------------------------------------------------
$GLOBALS['__store_fails'] = false;

$GLOBALS['__m'] = array();
function wp_salt( $scheme = 'auth' ) { return 'unit-test-salt'; }
function get_user_meta( $id, $key, $single = false ) { return $GLOBALS['__m'][ "$id:$key" ] ?? ''; }
function update_user_meta( $id, $key, $val ) { $GLOBALS['__m'][ "$id:$key" ] = $val; return true; }
function add_user_meta( $id, $key, $val, $unique = false ) {
	if ( $unique && isset( $GLOBALS['__m'][ "$id:$key" ] ) ) { return false; }
	$GLOBALS['__m'][ "$id:$key" ] = $val;
	return true;
}
function wp_cache_delete( $id, $group = '' ) { return true; }
function get_option( $k, $d = false ) {
	if ( 'rapls_passkey_settings' === $k ) { return array( 'webauthn_hints' => array( 'hybrid', 'security-key' ) ); }
	return $d;
}
function apply_filters( $tag, $value ) { return $value; }

// One $wpdb double for both wp_options users here: UserHandle mints the handle
// under an atomic insert, and Support\OneTimeStore holds the ceremony. The
// ceremony is deliberately not a transient — see Support\OneTimeStore.
require_once __DIR__ . '/lib/wpdb-options.php';
class WPDB_Reg extends WPDB_Options {
	public function suppress_errors( $s = null ) { return false; }
	/** Let a test make the ceremony write fail, as a store that refuses would. */
	public function query( $q ) {
		if ( ! empty( $GLOBALS['__store_fails'] ) && false !== strpos( $q, 'rapls_pk_ot_' ) ) {
			return false;
		}
		return parent::query( $q );
	}
}
$GLOBALS['wpdb'] = new WPDB_Reg();

require dirname( __DIR__ ) . '/vendor/autoload.php';
spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

use RaplsPasskey\WebAuthn\Ceremonies;
use RaplsPasskey\WebAuthn\ChallengeStore;
use RaplsPasskey\WebAuthn\Codec;
use RaplsPasskey\WebAuthn\RegistrationManager;
use RaplsPasskey\WebAuthn\RelyingParty;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$rp         = new RelyingParty( 'example.test', 'Example Site', 'https://example.test' );
$codec      = new Codec();
$challenges = new ChallengeStore();
$ceremonies = new Ceremonies( $rp );
$manager    = new RegistrationManager( $rp, $codec, $challenges, $ceremonies );

// The handle is established once by the caller and passed in — create_options()
// must not go looking for it a second time (V23-02).
$handle = str_repeat( "\x41", 32 );
$result = $manager->create_options( 1, 'alice', 'Alice Example', array(), $handle );
$pk     = $result['publicKey'];

$threw = false;
try {
	$manager->create_options( 1, 'alice', 'Alice Example', array(), '' );
} catch ( \RuntimeException $e ) {
	$threw = true;
}
check( 'create_options refuses without an established handle (V23-02)', $threw );

check( 'returns a state id', ! empty( $result['state'] ) );
check( 'publicKey has a challenge', ! empty( $pk['challenge'] ) );
check( 'rp.id matches the RP', isset( $pk['rp']['id'] ) && $pk['rp']['id'] === 'example.test' );
check( 'user.name is the username', isset( $pk['user']['name'] ) && $pk['user']['name'] === 'alice' );
check( 'pubKeyCredParams advertises ES256 (-7)', isset( $pk['pubKeyCredParams'][0]['alg'] ) && $pk['pubKeyCredParams'][0]['alg'] === -7 );
check( 'attestation is none', ( $pk['attestation'] ?? null ) === 'none' );
check( 'residentKey is preferred', ( $pk['authenticatorSelection']['residentKey'] ?? null ) === 'preferred' );
check( 'userVerification reflects the setting (preferred)', ( $pk['authenticatorSelection']['userVerification'] ?? null ) === 'preferred' );
check( 'timeout reflects the setting (60000ms)', ( $pk['timeout'] ?? null ) === 60000 );
check( 'hints injected into the options', ( $pk['hints'] ?? null ) === array( 'hybrid', 'security-key' ) );

// user.id is stable per user (UserHandle cached in meta).
$result2 = $manager->create_options( 1, 'alice', 'Alice Example', array(), $handle );
check( 'user.id is stable across ceremonies', $pk['user']['id'] === $result2['publicKey']['user']['id'] );

// The challenge was stored and is retrievable + deserialisable.
$stored = $challenges->take( $result['state'] );
check( 'challenge state was stored', is_string( $stored ) );
$options = $codec->creation_options_from_json( $stored );
check( 'stored options deserialise back', $options->rp->id === 'example.test' );
check( 'take() is single-use', $challenges->take( $result['state'] ) === null );

// --- passwordless sign-up options (userless) ------------------------------
$signup = $manager->create_signup_options( 'newuser', 'New User' );
$spk    = $signup['publicKey'];
check( 'signup returns a state id', ! empty( $signup['state'] ) );
check( 'signup user.name is the requested name', ( $spk['user']['name'] ?? null ) === 'newuser' );
check( 'signup has a challenge', ! empty( $spk['challenge'] ) );
check( 'signup excludes nothing (new account)', empty( $spk['excludeCredentials'] ) );
check( 'signup user.id differs from the existing user handle', ( $spk['user']['id'] ?? '' ) !== ( $pk['user']['id'] ?? '' ) );

// V26-02: options whose ceremony could not be stored must never be handed out.
// The browser would create a credential on the authenticator that this server
// can never verify — an orphan passkey the user has to find and delete.
$GLOBALS['__store_fails'] = true;
$threw_store = false;
try {
	$manager->create_options( 1, 'alice', 'Alice Example', array(), $handle );
} catch ( \RuntimeException $e ) {
	$threw_store = true;
}
check( 'a ceremony that could not be stored is refused, not returned (V26-02)', $threw_store );

$threw_signup = false;
try {
	$manager->create_signup_options( 'newbie', 'newbie' );
} catch ( \RuntimeException $e ) {
	$threw_signup = true;
}
check( 'the same for a sign-up ceremony (V26-02)', $threw_signup );
$GLOBALS['__store_fails'] = false;

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
