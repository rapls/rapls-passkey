<?php
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
$GLOBALS['__t'] = array();
function set_transient( $k, $v, $ttl ) { $GLOBALS['__t'][ $k ] = $v; return true; }
function get_transient( $k ) { return $GLOBALS['__t'][ $k ] ?? false; }
function delete_transient( $k ) { unset( $GLOBALS['__t'][ $k ] ); return true; }

$GLOBALS['__m'] = array();
function get_user_meta( $id, $key, $single = false ) { return $GLOBALS['__m'][ "$id:$key" ] ?? ''; }
function update_user_meta( $id, $key, $val ) { $GLOBALS['__m'][ "$id:$key" ] = $val; return true; }
function get_option( $k, $d = false ) { return $d; } // Settings falls back to defaults.
function apply_filters( $tag, $value ) { return $value; }

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

$result = $manager->create_options( 1, 'alice', 'Alice Example', array() );
$pk     = $result['publicKey'];

check( 'returns a state id', ! empty( $result['state'] ) );
check( 'publicKey has a challenge', ! empty( $pk['challenge'] ) );
check( 'rp.id matches the RP', isset( $pk['rp']['id'] ) && $pk['rp']['id'] === 'example.test' );
check( 'user.name is the username', isset( $pk['user']['name'] ) && $pk['user']['name'] === 'alice' );
check( 'pubKeyCredParams advertises ES256 (-7)', isset( $pk['pubKeyCredParams'][0]['alg'] ) && $pk['pubKeyCredParams'][0]['alg'] === -7 );
check( 'attestation is none', ( $pk['attestation'] ?? null ) === 'none' );
check( 'residentKey is preferred', ( $pk['authenticatorSelection']['residentKey'] ?? null ) === 'preferred' );
check( 'userVerification reflects the setting (preferred)', ( $pk['authenticatorSelection']['userVerification'] ?? null ) === 'preferred' );
check( 'timeout reflects the setting (60000ms)', ( $pk['timeout'] ?? null ) === 60000 );

// user.id is stable per user (UserHandle cached in meta).
$result2 = $manager->create_options( 1, 'alice', 'Alice Example', array() );
check( 'user.id is stable across ceremonies', $pk['user']['id'] === $result2['publicKey']['user']['id'] );

// The challenge was stored and is retrievable + deserialisable.
$stored = $challenges->take( $result['state'] );
check( 'challenge state was stored', is_string( $stored ) );
$options = $codec->creation_options_from_json( $stored );
check( 'stored options deserialise back', $options->rp->id === 'example.test' );
check( 'take() is single-use', $challenges->take( $result['state'] ) === null );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
