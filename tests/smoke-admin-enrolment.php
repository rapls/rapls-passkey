<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Endpoints::enrolment_target(): who a passkey may be registered for.
 *
 *   php tests/smoke-admin-enrolment.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

class WP_Error {
	private $code;
	private $data;
	public function __construct( $code = '', $message = '', $data = null ) {
		$this->code = $code;
		$this->data = $data;
	}
	public function get_error_code() { return $this->code; }
	public function get_error_data() { return $this->data; }
}
function is_wp_error( $t ) { return $t instanceof WP_Error; }

class WP_User {
	public $ID;
	public $user_login;
	public function __construct( $id = 0, $login = '' ) { $this->ID = (int) $id; $this->user_login = $login; }
}

/** Just enough of WP_REST_Request for get_param(). */
class WP_REST_Request {
	private $params;
	public function __construct( array $params = array() ) { $this->params = $params; }
	public function get_param( $key ) { return $this->params[ $key ] ?? null; }
}
class WP_REST_Response {}
class WP_REST_Server { const CREATABLE = 'POST'; const EDITABLE = 'POST, PUT, PATCH'; const DELETABLE = 'DELETE'; }

$GLOBALS['__current'] = 1;
$GLOBALS['__users']   = array();
$GLOBALS['__caps']    = array(); // "actor:target" pairs the actor may edit.
$GLOBALS['__enrol']   = false;

function wp_get_current_user() { return $GLOBALS['__users'][ $GLOBALS['__current'] ]; }
function get_user_by( $field, $value ) { return $GLOBALS['__users'][ (int) $value ] ?? false; }
function current_user_can( $cap, $target = 0 ) {
	return in_array( $GLOBALS['__current'] . ':' . (int) $target, $GLOBALS['__caps'], true );
}
function apply_filters( $tag, $value, ...$rest ) {
	if ( 'rapls_passkey/allow_admin_enrolment' === $tag ) {
		return $GLOBALS['__enrol'];
	}
	return $value;
}
function __( $s, $d = null ) { return $s; }

// Endpoints pulls in a lot; only the class body is under test, so load it without
// its collaborators and reach the private method by reflection.
require dirname( __DIR__ ) . '/src/Rest/Endpoints.php';

use RaplsPasskey\Rest\Endpoints;

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$GLOBALS['__users'][1] = new WP_User( 1, 'admin' );
$GLOBALS['__users'][2] = new WP_User( 2, 'alice' );
$GLOBALS['__users'][3] = new WP_User( 3, 'bob' );

$endpoints = ( new ReflectionClass( Endpoints::class ) )->newInstanceWithoutConstructor();
$target    = new ReflectionMethod( Endpoints::class, 'enrolment_target' );
$target->setAccessible( true );

/** @return WP_User|WP_Error */
function resolve( $endpoints, $target, array $params ) {
	return $target->invoke( $endpoints, new WP_REST_Request( $params ) );
}

// --- Yourself: always allowed, feature or no feature. ---
$GLOBALS['__enrol'] = false;

$r = resolve( $endpoints, $target, array() );
check( 'no user param => yourself', $r instanceof WP_User && 1 === $r->ID );

$r = resolve( $endpoints, $target, array( 'user' => 1 ) );
check( 'your own id => yourself', $r instanceof WP_User && 1 === $r->ID );

// --- Someone else, feature off. ---
$GLOBALS['__caps'] = array( '1:2', '1:3' ); // The admin could edit both.

$r = resolve( $endpoints, $target, array( 'user' => 2 ) );
check( 'another user is refused while the feature is off', $r instanceof WP_Error );
check( 'and the refusal is a 403', $r instanceof WP_Error && 403 === $r->get_error_data()['status'] );

// --- Someone else, feature on. ---
$GLOBALS['__enrol'] = true;

$r = resolve( $endpoints, $target, array( 'user' => 2 ) );
check( 'an admin who can edit them may enrol for them', $r instanceof WP_User && 2 === $r->ID );

$GLOBALS['__caps'] = array( '1:3' ); // No longer allowed to edit alice.
$r = resolve( $endpoints, $target, array( 'user' => 2 ) );
check( 'without edit_user for that specific user, refused', $r instanceof WP_Error );

$GLOBALS['__caps'] = array( '1:9' );
$r = resolve( $endpoints, $target, array( 'user' => 9 ) );
check( 'a user that does not exist is a 404', $r instanceof WP_Error && 404 === $r->get_error_data()['status'] );

// --- A non-admin cannot enrol for anyone, even with the feature on. ---
$GLOBALS['__current'] = 2; // alice
$GLOBALS['__caps']    = array(); // can edit nobody

$r = resolve( $endpoints, $target, array( 'user' => 3 ) );
check( 'a regular user cannot enrol for someone else', $r instanceof WP_Error );

$r = resolve( $endpoints, $target, array( 'user' => 2 ) );
check( 'but can still register for themselves', $r instanceof WP_User && 2 === $r->ID );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
