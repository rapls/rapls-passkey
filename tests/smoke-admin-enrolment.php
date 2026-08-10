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
		// null means "no filter on this site": hand back the default the source
		// actually passes, so the shipped default is under test and not the stub.
		return null === $GLOBALS['__enrol'] ? $value : $GLOBALS['__enrol'];
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

// --- Someone else, NOTHING filtering: the shipped default decides. ------------
//
// WordPress.org pended this plugin because the feature was implemented here and
// switched on by the Pro add-on's licence check. It is on by default now, and
// this case is the one that says so: no filter, no licence, no Pro. The stub
// above returns the source's own default when __enrol is null, so flipping that
// default back to false fails here rather than passing quietly — which is what
// happened before, when the stub answered for it.
$GLOBALS['__enrol'] = null;
$GLOBALS['__caps']  = array( '1:2' );

$r = resolve( $endpoints, $target, array( 'user' => 2 ) );
check( 'with no filter at all, an admin who can edit them may enrol for them', $r instanceof WP_User && 2 === $r->ID );

$GLOBALS['__caps'] = array(); // Cannot edit anyone.
$r = resolve( $endpoints, $target, array( 'user' => 2 ) );
check( 'and the capability is still the bound, default or not', $r instanceof WP_Error );

// --- Someone else, a site that filtered the feature off. ---
$GLOBALS['__enrol'] = false;
$GLOBALS['__caps']  = array( '1:2', '1:3' ); // The admin could edit both.

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

// --- The other call site, and what the source says about it. -----------------
$root = dirname( __DIR__ );
foreach ( array( 'src/Rest/Endpoints.php', 'src/Admin/ProfileUi.php' ) as $rel ) {
	$src = (string) file_get_contents( $root . '/' . $rel );
	check(
		$rel . ' passes true as the default',
		(bool) preg_match( "#allow_admin_enrolment',\s*true\s*\)#", $src )
	);
	check(
		$rel . ' does not tie the feature to the paid add-on',
		! preg_match( '#Pro\s+(turns|enables|unlocks)#i', $src )
	);
}

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
