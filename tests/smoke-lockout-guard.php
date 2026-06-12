<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Exercises the lockout-prevention helpers and the emergency bypass switch
 * against an in-memory $wpdb and stubbed user functions.
 *
 *   php tests/smoke-lockout-guard.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
if ( ! defined( 'OBJECT' ) ) { define( 'OBJECT', 'OBJECT' ); }
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }

// --- In-memory $wpdb (insert + find_by_user) ------------------------------
class WPDB_Guard {
	public $prefix = 'wp_';
	public $insert_id = 0;
	public $rows = array();
	private $auto = 0;
	public function insert( $table, $data, $formats ) {
		$data['id'] = ++$this->auto;
		$this->rows[ $data['id'] ] = $data;
		$this->insert_id = $data['id'];
		return 1;
	}
	public function prepare( $query, ...$args ) {
		return array( 'q' => $query, 'args' => $args );
	}
	public function get_results( $prepared, $output = OBJECT ) {
		$uid = (int) $prepared['args'][0];
		$out = array();
		foreach ( $this->rows as $row ) {
			if ( (int) $row['user_id'] === $uid ) {
				$out[] = array(
					'id'              => $row['id'],
					'user_id'         => $row['user_id'],
					'credential_id'   => $row['credential_id'],
					'credential_data' => $row['credential_data'],
					'sign_count'      => $row['sign_count'],
					'label'           => $row['label'] ?? null,
					'created_at'      => $row['created_at'],
					'last_used_at'    => $row['last_used_at'] ?? null,
				);
			}
		}
		return $out;
	}
}
$GLOBALS['wpdb'] = new WPDB_Guard();

// --- User function stubs --------------------------------------------------
$GLOBALS['__users'] = array(
	1 => (object) array( 'ID' => 1, 'roles' => array( 'administrator' ) ),
	2 => (object) array( 'ID' => 2, 'roles' => array( 'administrator' ) ),
	3 => (object) array( 'ID' => 3, 'roles' => array( 'subscriber' ) ),
);
$GLOBALS['__admin_count'] = 2;
function get_userdata( $id ) { return $GLOBALS['__users'][ $id ] ?? false; }
function get_users( $args ) {
	// Honour 'number' => 2 cap used by the guard.
	$n = $GLOBALS['__admin_count'];
	$ids = array();
	for ( $i = 1; $i <= $n; $i++ ) { $ids[] = $i; }
	return array_slice( $ids, 0, $args['number'] ?? $n );
}

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

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Recovery\Bypass;
use RaplsPasskey\Recovery\LockoutGuard;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$repo  = new CredentialRepository();
$guard = new LockoutGuard( $repo );

// User 1 has a passkey; user 2 does not.
$repo->insert( 1, 'credA', '{"r":1}', 0, 'Mac' );

check( 'user_has_passkey true when registered', $guard->user_has_passkey( 1 ) === true );
check( 'user_has_passkey false when none', $guard->user_has_passkey( 2 ) === false );
check( 'can_enforce_for_user true with a passkey', $guard->can_enforce_for_user( 1 ) === true );
check( 'can_enforce_for_user false without a passkey', $guard->can_enforce_for_user( 2 ) === false );

// Last-admin protection.
check( 'admin is not last when two admins exist', $guard->is_last_administrator( 1 ) === false );
check( 'non-admin is never "last administrator"', $guard->is_last_administrator( 3 ) === false );
$GLOBALS['__admin_count'] = 1;
check( 'admin is last when only one remains', $guard->is_last_administrator( 1 ) === true );

// Bypass switch.
check( 'Bypass inactive when constant undefined', Bypass::active() === false );
define( 'RAPLS_PASSKEY_BYPASS', true );
check( 'Bypass active when constant defined truthy', Bypass::active() === true );
check( 'can_enforce_for_user false while bypass active', $guard->can_enforce_for_user( 1 ) === false );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
