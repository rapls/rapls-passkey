<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Exercises CredentialRepository CRUD against an in-memory $wpdb stub.
 *
 *   php tests/smoke-credential-repo.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// --- In-memory $wpdb ------------------------------------------------------
class WPDB_Mem {
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
	public function update( $table, $data, $where, $f = null, $wf = null ) {
		$id = (int) $where['id'];
		if ( ! isset( $this->rows[ $id ] ) ) {
			return 0;
		}
		$this->rows[ $id ] = array_merge( $this->rows[ $id ], $data );
		return 1;
	}
	public function delete( $table, $where, $f = null ) {
		foreach ( $this->rows as $id => $row ) {
			$id_ok   = (int) $id === (int) $where['id'];
			// delete_by_id() omits user_id; owner-scoped delete() includes it.
			$user_ok = ! isset( $where['user_id'] ) || (int) $row['user_id'] === (int) $where['user_id'];
			if ( $id_ok && $user_ok ) {
				unset( $this->rows[ $id ] );
				return 1;
			}
		}
		return 0;
	}
	public function prepare( $query, ...$args ) {
		return array( 'q' => $query, 'args' => $args );
	}
	public function get_row( $prepared, $output = OBJECT ) {
		$arg    = $prepared['args'][0];
		$by_id  = is_string( $prepared['q'] ) && strpos( $prepared['q'], 'WHERE id =' ) !== false;
		foreach ( $this->rows as $row ) {
			if ( $by_id ) {
				if ( (int) $row['id'] === (int) $arg ) {
					return $this->cols( $row );
				}
			} elseif ( (string) $row['credential_id'] === (string) $arg ) {
				return $this->cols( $row );
			}
		}
		return null;
	}
	public function get_results( $prepared, $output = OBJECT ) {
		$uid = (int) $prepared['args'][0];
		$out = array();
		foreach ( array_reverse( $this->rows, true ) as $row ) {
			if ( (int) $row['user_id'] === $uid ) {
				$out[] = $this->cols( $row );
			}
		}
		return $out;
	}
	private function cols( $row ) {
		return array(
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
if ( ! defined( 'OBJECT' ) ) { define( 'OBJECT', 'OBJECT' ); }
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }
$GLOBALS['wpdb'] = new WPDB_Mem();

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

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$repo = new CredentialRepository();

$id1 = $repo->insert( 7, 'credAAA', '{"r":1}', 0, 'MacBook' );
$id2 = $repo->insert( 7, 'credBBB', '{"r":2}', 5, null );
$id3 = $repo->insert( 9, 'credCCC', '{"r":3}', 0, 'Phone' );
check( 'insert returns ids', $id1 > 0 && $id2 > 0 && $id3 > 0 );

$found = $repo->find_by_credential_id( 'credBBB' );
check( 'find_by_credential_id returns the right row', $found && $found->user_id === 7 && $found->sign_count === 5 );
check( 'find_by_credential_id maps record_json', $found && $found->record_json === '{"r":2}' );
check( 'find_by_credential_id null when missing', $repo->find_by_credential_id( 'nope' ) === null );

$mine = $repo->find_by_user( 7 );
check( 'find_by_user returns only that user, newest first', count( $mine ) === 2 && $mine[0]->credential_id === 'credBBB' );

$repo->touch( $id2, '{"r":2,"u":1}', 6 );
$after = $repo->find_by_credential_id( 'credBBB' );
check( 'touch updates record + counter', $after->sign_count === 6 && $after->record_json === '{"r":2,"u":1}' );
check( 'touch sets last_used_at', ! empty( $after->last_used_at ) );

// find_by_id (used by admin delete path).
$by_id = $repo->find_by_id( $id3 );
check( 'find_by_id returns the right row', $by_id && $by_id->user_id === 9 && $by_id->credential_id === 'credCCC' );
check( 'find_by_id null when missing', $repo->find_by_id( 99999 ) === null );

check( 'delete scoped to owner fails for wrong user', $repo->delete( $id1, 9 ) === false );
check( 'delete works for owner', $repo->delete( $id1, 7 ) === true );
check( 'deleted row is gone', $repo->find_by_credential_id( 'credAAA' ) === null );

// delete_by_id (admin/CLI path) ignores ownership.
check( 'delete_by_id removes another user\'s row', $repo->delete_by_id( $id3 ) === true );
check( 'delete_by_id row is gone', $repo->find_by_id( $id3 ) === null );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
