<?php
/**
 * reCAPTCHA verify(): gating on interactive password login and token outcomes.
 *
 *   php tests/smoke-recaptcha.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

class WP_Error {
	public $code;
	public function __construct( $code = '', $msg = '', $data = null ) { $this->code = $code; }
}
class WP_User {
	public $ID = 5;
}
function is_wp_error( $thing ) { return $thing instanceof WP_Error; }
function __( $t, $d = null ) { return $t; }
function sanitize_text_field( $v ) { return is_string( $v ) ? trim( $v ) : ''; }
function wp_unslash( $v ) { return $v; }
function apply_filters( $tag, $value ) { return $value; }

$GLOBALS['__opt'] = array(
	'rapls_passkey_settings' => array(
		'recaptcha_enabled'    => true,
		'recaptcha_site_key'   => 'SITE',
		'recaptcha_secret_key' => 'SECRET',
		'recaptcha_threshold'  => 0.5,
	),
);
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }

// Stubbed Google verification: $GLOBALS['__rc'] drives the response.
function wp_remote_post( $url, $args ) {
	return $GLOBALS['__rc'];
}
function wp_remote_retrieve_body( $r ) { return is_array( $r ) ? ( $r['body'] ?? '' ) : ''; }

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

use RaplsPasskey\Login\Recaptcha;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$rc   = new Recaptcha();
$user = new WP_User();

// Pass-through cases.
$_POST = array();
check( 'no log/pwd -> pass through', $rc->verify( $user, 'a', 'b' ) === $user );
check( 'existing WP_Error -> returned unchanged', $rc->verify( new WP_Error( 'x' ), 'a', 'b' ) instanceof WP_Error );

// Interactive login from here on.
$_POST = array( 'log' => 'admin', 'pwd' => 'secret' );

$_POST['rapls_passkey_recaptcha_token'] = '';
check( 'missing token -> WP_Error', $rc->verify( $user, 'admin', 'secret' ) instanceof WP_Error );

$_POST['rapls_passkey_recaptcha_token'] = 'tok';
$GLOBALS['__rc'] = array( 'body' => json_encode( array( 'success' => true, 'action' => 'login', 'score' => 0.9 ) ) );
check( 'valid high-score token -> pass', $rc->verify( $user, 'admin', 'secret' ) === $user );

$GLOBALS['__rc'] = array( 'body' => json_encode( array( 'success' => true, 'action' => 'login', 'score' => 0.1 ) ) );
check( 'low score -> WP_Error', $rc->verify( $user, 'admin', 'secret' ) instanceof WP_Error );

$GLOBALS['__rc'] = array( 'body' => json_encode( array( 'success' => false ) ) );
check( 'success=false -> WP_Error', $rc->verify( $user, 'admin', 'secret' ) instanceof WP_Error );

$GLOBALS['__rc'] = array( 'body' => json_encode( array( 'success' => true, 'action' => 'other', 'score' => 0.9 ) ) );
check( 'wrong action -> WP_Error', $rc->verify( $user, 'admin', 'secret' ) instanceof WP_Error );

$GLOBALS['__rc'] = new WP_Error( 'http_request_failed' );
check( 'transport error -> fail open (pass)', $rc->verify( $user, 'admin', 'secret' ) === $user );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
