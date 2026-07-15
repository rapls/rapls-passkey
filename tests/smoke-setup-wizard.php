<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * SetupWizard: when the first-run notice appears, and when it stops.
 *
 *   php tests/smoke-setup-wizard.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
define( 'RAPLS_PASSKEY_URL', 'https://example.test/wp-content/plugins/rapls-passkey/' );
define( 'RAPLS_PASSKEY_VERSION', 'test' );

$GLOBALS['__opt']  = array();
$GLOBALS['__caps'] = true;
$GLOBALS['__out']  = '';

function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function update_option( $k, $v, $autoload = null ) { $GLOBALS['__opt'][ $k ] = $v; return true; }
function current_user_can( $cap, $t = null ) { return $GLOBALS['__caps']; }
function admin_url( $p = '' ) { return 'https://example.test/wp-admin/' . $p; }
function wp_nonce_url( $url, $action ) { return $url . '&_wpnonce=x'; }
function esc_url( $s ) { return $s; }
function esc_html( $s ) { return $s; }
function esc_html_e( $s, $d = null ) { echo $s; }
function esc_html__( $s, $d = null ) { return $s; }
function __( $s, $d = null ) { return $s; }
function add_action( ...$a ) {}
function add_submenu_page( ...$a ) {}
function remove_submenu_page( ...$a ) {}
function get_current_screen() { return null; }
function is_ssl() { return true; }
function home_url() { return 'https://example.test'; }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }

// The wizard reads find_active_by_user() and stats() off the repository. The
// property is typed, so alias the fake onto the real class name before anything
// autoloads the real one.
class FakeRepo {
	public $keys  = array();
	public $total = 0;
	public function find_active_by_user( $uid ) { return $this->keys; }
	public function stats() { return array( 'total' => $this->total, 'users' => 0 ); }
}
class_alias( FakeRepo::class, 'RaplsPasskey\\Credentials\\CredentialRepository' );

spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$path = __DIR__ . '/../src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

require __DIR__ . '/../src/Admin/SetupWizard.php';

use RaplsPasskey\Admin\SetupWizard;

$pass = 0; $failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// The constructor's type hint is on the real repository, so build without it and
// slide the fake in by reflection.
$repo   = new FakeRepo();
$wizard = ( new ReflectionClass( SetupWizard::class ) )->newInstanceWithoutConstructor();
$prop   = new ReflectionProperty( SetupWizard::class, 'repository' );
$prop->setAccessible( true );
$prop->setValue( $wizard, $repo );

/** Capture what render_notice() prints. */
function notice_html( $wizard ) {
	ob_start();
	$wizard->render_notice();
	return (string) ob_get_clean();
}

// --- A fresh install is nudged. ---
$GLOBALS['__opt'] = array();
check( 'a fresh install has not done setup', SetupWizard::done() === false );
check( 'and is shown the notice', false !== strpos( notice_html( $wizard ), 'Start setup' ) );

// --- Dismissing sticks. ---
$dismiss = new ReflectionMethod( SetupWizard::class, 'handle_dismiss' );
$GLOBALS['__opt']['rapls_passkey_setup_done'] = true;

check( 'once done, done() says so', SetupWizard::done() === true );
check( 'and the notice is gone', '' === notice_html( $wizard ) );

// --- Someone who cannot configure the plugin is never nagged. ---
$GLOBALS['__opt']  = array();
$GLOBALS['__caps'] = false;
check( 'a user without manage_options sees nothing', '' === notice_html( $wizard ) );
$GLOBALS['__caps'] = true;

// --- The wizard is reachable from a stable URL. ---
check( 'the wizard has a settings-page URL', false !== strpos( SetupWizard::url(), 'page=rapls-passkey-setup' ) );

// --- A site that upgraded with passkeys already in use is not nagged. ---
$GLOBALS['__opt'] = array();
$repo->total      = 3;
check( 'an already-working site gets no notice', '' === notice_html( $wizard ) );
check( 'and is marked done so the check never re-runs', SetupWizard::done() === true );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
