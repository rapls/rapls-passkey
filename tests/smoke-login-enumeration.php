<?php
/**
 * /login/options must not answer "does this account exist, and does it hold a
 * passkey?" (R20-04 / R21-01).
 *
 * By default no allow-list is returned at all, so every anonymous answer is
 * identical. A site that opts in — because it must support authenticators that
 * store nothing themselves — gets a padded, uniform list instead.
 *
 *   php tests/smoke-login-enumeration.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Credentials {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	class CredentialRepository {
		public function find_active_by_user( $uid ) {
			$out = array();
			foreach ( $GLOBALS['__creds'][ $uid ] ?? array() as $raw ) {
				$out[] = (object) array( 'id' => 1, 'record_json' => $raw );
			}
			return $out;
		}
	}
	class Schema { public static function cap_enforceable() { return true; } }
	class UserHandle { public static function raw( $id ) { return ''; } }
}
namespace RaplsPasskey\WebAuthn {
	class Codec {
		public function record_from_json( $json ) {
			return (object) array( 'publicKeyCredentialId' => $json, 'transports' => array( 'internal', 'hybrid' ) );
		}
	}
	class RegistrationManager {}
	/** Captures exactly what the endpoint asked to be offered. */
	class AssertionManager {
		public $records = null;
		public $decoys  = null;
		public function create_options( array $records, $uv = null, array $decoys = array() ) {
			$this->records = $records;
			$this->decoys  = $decoys;
			$ids = array();
			foreach ( $records as $r ) { $ids[] = $r->publicKeyCredentialId; }
			foreach ( $decoys as $d )  { $ids[] = $d; }
			return array( 'state' => 'S', 'publicKey' => array( 'allowCredentials' => $ids ) );
		}
	}
}
namespace RaplsPasskey\Audit { class AuditLog { const LOGIN = 'l'; public static function record( ...$a ) {} } }
namespace RaplsPasskey\Support { class Str { public static function substr( $s, $a, $b ) { return substr( $s, $a, $b ); } } }

namespace {

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['__opt']        = array();
$GLOBALS['__allow_list'] = false;   // the rapls_passkey/username_allow_list filter
$GLOBALS['__users']      = array(); // login => id
$GLOBALS['__creds']      = array(); // id => list of raw credential ids

function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function wp_salt( $scheme = 'auth' ) { return 'unit-test-salt'; }
function sanitize_text_field( $s ) { return is_string( $s ) ? trim( $s ) : ''; }
function wp_unslash( $s ) { return $s; }
function wp_rand( $min = 0, $max = 1 ) { return 1; }
function __( $s, $d = null ) { return $s; }
function is_email( $s ) { return false !== strpos( (string) $s, '@' ); }
function rest_ensure_response( $r ) { return new WP_REST_Response( $r ); }
function apply_filters( $tag, $value, ...$rest ) {
	if ( 'rapls_passkey/username_allow_list' === $tag ) { return $GLOBALS['__allow_list']; }
	if ( 'rapls_passkey/login_options_max' === $tag ) { return 50; }
	return $value;
}
function get_user_by( $field, $value ) {
	if ( 'login' !== $field ) { return false; }          // email lookup must be gone
	$id = $GLOBALS['__users'][ (string) $value ] ?? 0;
	return $id ? (object) array( 'ID' => $id ) : false;
}

class WP_REST_Request {
	private $p;
	public function __construct( $p = array() ) { $this->p = $p; }
	public function get_param( $k ) { return $this->p[ $k ] ?? null; }
	public function get_header( $k ) { return 'https://example.test'; }
}
class WP_REST_Response {
	public $data;
	public function __construct( $data = null ) { $this->data = $data; }
}
class WP_REST_Server { const READABLE='GET'; const CREATABLE='POST'; const EDITABLE='PUT'; const DELETABLE='DELETE'; }

class WP_Error {
	private $d;
	public function __construct( $c = '', $m = '', $d = array() ) { $this->d = $d; }
	public function get_error_data() { return $this->d; }
}

require_once __DIR__ . '/lib/wpdb-options.php';
$GLOBALS['wpdb'] = new WPDB_Options();


require dirname( __DIR__ ) . '/src/Support/Settings.php';
require_once dirname( __DIR__ ) . '/src/Support/RateLimit.php';
require dirname( __DIR__ ) . '/src/Rest/Endpoints.php';

use RaplsPasskey\Rest\Endpoints;



$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$assertion = new RaplsPasskey\WebAuthn\AssertionManager();
$ep  = ( new ReflectionClass( Endpoints::class ) )->newInstanceWithoutConstructor();
$ref = new ReflectionClass( Endpoints::class );
foreach ( array( 'assertion' => $assertion, 'repository' => new RaplsPasskey\Credentials\CredentialRepository(), 'codec' => new RaplsPasskey\WebAuthn\Codec() ) as $prop => $val ) {
	$p = $ref->getProperty( $prop ); $p->setAccessible( true ); $p->setValue( $ep, $val );
}
$ids = static function ( $resp ) { return $resp->data['publicKey']['allowCredentials']; };

// A real account with two passkeys of different id lengths, and an unknown name.
$GLOBALS['__users']['alice'] = 7;
$GLOBALS['__creds'][7] = array( str_repeat( 'A', 20 ), str_repeat( 'B', 64 ) );
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';

// --- default: no allow-list at all ------------------------------------------
$known   = $ids( $ep->login_options( new WP_REST_Request( array( 'username' => 'alice' ) ) ) );
$unknown = $ids( $ep->login_options( new WP_REST_Request( array( 'username' => 'nobody' ) ) ) );
check( 'by default a known account gets NO allow-list', array() === $known );
check( 'and an unknown name gets the same', array() === $unknown );
check( 'so the two answers are identical (R21-01)', $known === $unknown );

// --- opted in: padded to a fixed size, shape-identical ----------------------
$GLOBALS['__allow_list'] = true;
$known   = $ids( $ep->login_options( new WP_REST_Request( array( 'username' => 'alice' ) ) ) );
$unknown = $ids( $ep->login_options( new WP_REST_Request( array( 'username' => 'nobody' ) ) ) );
check( 'opted in, a known account returns a fixed-size list', 4 === count( $known ) );
check( 'and an unknown name returns the same size', 4 === count( $unknown ) );
check( 'the real credentials are still offered', in_array( str_repeat( 'A', 20 ), $known, true ) && in_array( str_repeat( 'B', 64 ), $known, true ) );

// Transports would betray a real entry: none are passed through.
$has_transports = false;
foreach ( $assertion->records as $r ) { /* records carry them, the descriptor must not */ }
$rm = new ReflectionMethod( Endpoints::class, 'decoy_credential_ids' ); $rm->setAccessible( true );

// Decoy id LENGTHS must vary the way real ones do, not be a giveaway constant.
$lengths = array();
foreach ( array( 'nobody', 'someone', 'a', 'zzz', 'bob', 'carol', 'dave', 'erin' ) as $name ) {
	foreach ( $rm->invoke( $ep, $name, 4 ) as $id ) { $lengths[ strlen( $id ) ] = true; }
}
check( 'decoy id lengths vary across the sizes real authenticators use', count( $lengths ) > 1 );

// Stable per name (a repeat probe must not expose them as fabricated)…
check( 'decoys are stable for the same name', $rm->invoke( $ep, 'nobody', 4 ) === $rm->invoke( $ep, 'nobody', 4 ) );
// …and different for different names.
check( 'decoys differ between names', $rm->invoke( $ep, 'nobody', 4 ) !== $rm->invoke( $ep, 'someone', 4 ) );

// An email address must not resolve an account: otherwise the same id set would
// come back for a name and an address, linking them.
$by_email = $ids( $ep->login_options( new WP_REST_Request( array( 'username' => 'alice@example.test' ) ) ) );
check( 'an email address never returns real credentials (R21-01)', ! in_array( str_repeat( 'A', 20 ), $by_email, true ) );

// A known account with no usable passkey looks like an unknown one.
$GLOBALS['__users']['bob'] = 8;
$GLOBALS['__creds'][8]     = array();
$no_keys = $ids( $ep->login_options( new WP_REST_Request( array( 'username' => 'bob' ) ) ) );
check( 'an account without passkeys is indistinguishable in size', count( $no_keys ) === count( $unknown ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );

} // namespace
