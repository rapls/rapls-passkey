<?php
/**
 * Authentication ceremony: request-options generation plus the CredentialRecord
 * storage round-trip (serialise -> deserialise) that backs assertion checks.
 * Uses the real library; transient functions are stubbed in memory.
 *
 *   php tests/smoke-assertion.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['__t'] = array();
function set_transient( $k, $v, $ttl ) { $GLOBALS['__t'][ $k ] = $v; return true; }
function get_transient( $k ) { return $GLOBALS['__t'][ $k ] ?? false; }
function delete_transient( $k ) { unset( $GLOBALS['__t'][ $k ] ); return true; }
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

use RaplsPasskey\WebAuthn\AssertionManager;
use RaplsPasskey\WebAuthn\Ceremonies;
use RaplsPasskey\WebAuthn\ChallengeStore;
use RaplsPasskey\WebAuthn\Codec;
use RaplsPasskey\WebAuthn\RelyingParty;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

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
$manager    = new AssertionManager( $rp, $codec, $challenges, $ceremonies );

// --- request options (usernameless: empty allow list) --------------------
$result = $manager->create_options( array() );
$pk     = $result['publicKey'];
check( 'returns a state id', ! empty( $result['state'] ) );
check( 'publicKey has a challenge', ! empty( $pk['challenge'] ) );
check( 'rpId matches the RP', ( $pk['rpId'] ?? null ) === 'example.test' );
check( 'userVerification is preferred', ( $pk['userVerification'] ?? null ) === 'preferred' );
check( 'timeout reflects the setting (60000ms)', ( $pk['timeout'] ?? null ) === 60000 );

$stored = $challenges->take( $result['state'] );
check( 'challenge state was stored', is_string( $stored ) );
$options = $codec->request_options_from_json( $stored );
check( 'stored request options deserialise back', $options->rpId === 'example.test' );

// --- CredentialRecord storage round-trip (the storage source of truth) ----
$record = CredentialRecord::create(
	'raw-credential-id-bytes',
	'public-key',
	array( 'internal', 'hybrid' ),
	'none',
	EmptyTrustPath::create(),
	Uuid::fromString( '00000000-0000-0000-0000-000000000000' ),
	'cose-public-key-bytes',
	'user-handle-bytes',
	42
);
$json    = $codec->record_to_json( $record );
$back    = $codec->record_from_json( $json );
check( 'record round-trips publicKeyCredentialId', $back->publicKeyCredentialId === 'raw-credential-id-bytes' );
check( 'record round-trips counter', $back->counter === 42 );
check( 'record round-trips userHandle', $back->userHandle === 'user-handle-bytes' );
check( 'record round-trips transports', $back->transports === array( 'internal', 'hybrid' ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
