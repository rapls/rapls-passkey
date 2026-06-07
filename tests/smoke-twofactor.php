<?php
/**
 * TwoFactor coexistence: marks the just-created session as 2FA-verified, honours
 * the disable filter, and no-ops without a captured token.
 *
 *   php tests/smoke-twofactor.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// --- Two-Factor + session token test doubles -----------------------------
class Two_Factor_Core {}

class FakeSessionManager {
	public static $store = array();   // token => session array
	public static $instances = array();
	private $uid;
	private function __construct( $uid ) { $this->uid = $uid; }
	public static function get_instance( $uid ) {
		if ( ! isset( self::$instances[ $uid ] ) ) {
			self::$instances[ $uid ] = new self( $uid );
		}
		return self::$instances[ $uid ];
	}
	public function get( $token ) { return self::$store[ $token ] ?? false; }
	public function update( $token, $session ) { self::$store[ $token ] = $session; }
}
class_alias( 'FakeSessionManager', 'WP_Session_Tokens' );

class WP_User {
	public $ID;
	public function __construct( $id ) { $this->ID = $id; }
}

$GLOBALS['__filter_2fa'] = true;
function apply_filters( $tag, $value, ...$rest ) {
	if ( 'rapls_passkey_satisfies_2fa' === $tag ) {
		return $GLOBALS['__filter_2fa'];
	}
	return $value;
}
function add_action() {}

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

use RaplsPasskey\Integrations\TwoFactor;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$user = new WP_User( 21 );

// No captured token => no-op.
FakeSessionManager::$store = array( 'tok' => array( 'login' => 1 ) );
$tf = new TwoFactor();
$tf->mark_session( $user, 'login' );
check( 'no-op without a captured token', ! isset( FakeSessionManager::$store['tok']['two-factor-login'] ) );

// Capture token + mark.
FakeSessionManager::$store = array( 'tok' => array( 'login' => 1 ) );
$tf = new TwoFactor();
$tf->capture_token( 'cookie', 0, 0, 21, 'logged_in', 'tok' );
$tf->mark_session( $user, 'login' );
check( 'marks session two-factor-login', ! empty( FakeSessionManager::$store['tok']['two-factor-login'] ) );
check( 'records the passkey provider', FakeSessionManager::$store['tok']['two-factor-provider'] === 'RaplsPasskey_WebAuthn' );

// Unknown token => no crash, nothing added.
FakeSessionManager::$store = array();
$tf2 = new TwoFactor();
$tf2->capture_token( 'cookie', 0, 0, 21, 'logged_in', 'missing' );
$tf2->mark_session( $user, 'login' );
check( 'no session created for an unknown token', FakeSessionManager::$store === array() );

// Filter veto.
FakeSessionManager::$store = array( 'tok' => array( 'login' => 1 ) );
$GLOBALS['__filter_2fa'] = false;
$tf3 = new TwoFactor();
$tf3->capture_token( 'cookie', 0, 0, 21, 'logged_in', 'tok' );
$tf3->mark_session( $user, 'login' );
check( 'filter can veto session marking', ! isset( FakeSessionManager::$store['tok']['two-factor-login'] ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
