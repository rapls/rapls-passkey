<?php
/**
 * PersonalData: the GDPR exporter/eraser registration, export shape, and that
 * erase / user-deletion purge credentials, audit rows, and meta.
 *
 *   php tests/smoke-privacy.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	define( 'ABSPATH', __DIR__ . '/' );
	if ( ! defined( 'ARRAY_A' ) ) {
		define( 'ARRAY_A', 'ARRAY_A' );
	}

	$GLOBALS['__meta'] = array(); // uid => [key => value]

	function __( $s, $d = null ) { return $s; }
	function get_user_by( $field, $value ) { return $GLOBALS['__users_by_email'][ (string) $value ] ?? false; }
	function delete_user_meta( $uid, $key ) {
		if ( isset( $GLOBALS['__meta'][ $uid ][ $key ] ) ) {
			unset( $GLOBALS['__meta'][ $uid ][ $key ] );
			return true;
		}
		return false;
	}

	/**
	 * Minimal $wpdb over two in-memory tables (credentials, audit).
	 */
	class FakeWpdb {
		public $prefix = 'wp_';
		public $insert_id = 0;
		public $credentials = array(); // rows
		public $audit = array();       // rows

		public function prepare( $sql, ...$args ) {
			// Return a marker the query methods can dispatch on, plus the bound id.
			foreach ( $args as $a ) {
				$sql = preg_replace( '/%d|%s/', is_int( $a ) ? (string) $a : "'" . $a . "'", $sql, 1 );
			}
			return $sql;
		}

		public function get_results( $sql, $output = ARRAY_A ) {
			if ( false !== strpos( $sql, 'rapls_passkey_credentials' ) ) {
				return $this->filter_by_user( $this->credentials, $sql );
			}
			if ( false !== strpos( $sql, 'rapls_passkey_audit' ) ) {
				return $this->filter_by_user( $this->audit, $sql );
			}
			return array();
		}

		public function get_row( $sql, $output = ARRAY_A ) {
			$rows = $this->get_results( $sql, $output );
			return $rows[0] ?? null;
		}

		public function delete( $table, $where, $formats ) {
			$key = false !== strpos( $table, 'audit' ) ? 'audit' : 'credentials';
			$before = count( $this->$key );
			$uid = (int) ( $where['user_id'] ?? -999 );
			$id  = isset( $where['id'] ) ? (int) $where['id'] : null;
			$this->$key = array_values( array_filter(
				$this->$key,
				function ( $r ) use ( $uid, $id, $where ) {
					if ( isset( $where['user_id'] ) && (int) $r['user_id'] !== $uid ) { return true; }
					if ( null !== $id && (int) $r['id'] !== $id ) { return true; }
					return false; // matches => drop
				}
			) );
			return $before - count( $this->$key );
		}

		private function filter_by_user( $rows, $sql ) {
			if ( preg_match( "/user_id = (\d+)/", $sql, $m ) ) {
				$uid = (int) $m[1];
				$rows = array_values( array_filter( $rows, fn( $r ) => (int) $r['user_id'] === $uid ) );
			}
			return $rows;
		}
	}

	$GLOBALS['wpdb'] = new FakeWpdb();

	require dirname( __DIR__ ) . '/src/Credentials/Schema.php';
	require dirname( __DIR__ ) . '/src/Credentials/Credential.php';
	require dirname( __DIR__ ) . '/src/Credentials/CredentialRepository.php';
	require dirname( __DIR__ ) . '/src/Credentials/UserHandle.php';
	require dirname( __DIR__ ) . '/src/Audit/AuditLog.php';
	require dirname( __DIR__ ) . '/src/Security/Notifications.php';
	require dirname( __DIR__ ) . '/src/Privacy/PersonalData.php';

	use RaplsPasskey\Credentials\CredentialRepository;
	use RaplsPasskey\Credentials\UserHandle;
	use RaplsPasskey\Privacy\PersonalData;
	use RaplsPasskey\Security\Notifications;

	class WP_User { public $ID; public function __construct( $id ) { $this->ID = $id; } }

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	// Seed data for user 5.
	$wpdb = $GLOBALS['wpdb'];
	$wpdb->credentials = array(
		array( 'id' => 1, 'user_id' => 5, 'credential_id' => 'AAA', 'credential_data' => '{}', 'sign_count' => 0, 'label' => 'Phone', 'created_at' => '2026-01-01 00:00:00', 'last_used_at' => '2026-02-01 00:00:00' ),
		array( 'id' => 2, 'user_id' => 5, 'credential_id' => 'BBB', 'credential_data' => '{}', 'sign_count' => 0, 'label' => null, 'created_at' => '2026-01-02 00:00:00', 'last_used_at' => null ),
		array( 'id' => 3, 'user_id' => 9, 'credential_id' => 'CCC', 'credential_data' => '{}', 'sign_count' => 0, 'label' => 'Other', 'created_at' => '2026-01-03 00:00:00', 'last_used_at' => null ),
	);
	$wpdb->audit = array(
		array( 'id' => 1, 'user_id' => 5, 'event' => 'registered', 'detail' => 'id=1', 'ip' => '203.0.113.1', 'created_at' => '2026-01-01 00:00:00' ),
		array( 'id' => 2, 'user_id' => 5, 'event' => 'login', 'detail' => 'cred=1', 'ip' => '203.0.113.2', 'created_at' => '2026-02-01 00:00:00' ),
		array( 'id' => 3, 'user_id' => 9, 'event' => 'login', 'detail' => 'cred=3', 'ip' => '203.0.113.9', 'created_at' => '2026-02-02 00:00:00' ),
	);
	$GLOBALS['__meta'][5] = array(
		Notifications::SEEN_META => array( 'hash1' ),
		UserHandle::META        => 'handle-5',
	);

	$alice = new WP_User( 5 );
	$GLOBALS['__users_by_email'] = array( 'alice@example.test' => $alice );

	$pd = new PersonalData( new CredentialRepository() );

	// --- registration ----------------------------------------------------------
	$ex = $pd->register_exporter( array() );
	check( 'exporter registered', isset( $ex['rapls-passkey']['callback'] ) );
	$er = $pd->register_eraser( array() );
	check( 'eraser registered', isset( $er['rapls-passkey']['callback'] ) );

	// --- export ----------------------------------------------------------------
	$out = $pd->export( 'alice@example.test' );
	check( 'export is done', true === $out['done'] );
	$creds = array_filter( $out['data'], fn( $d ) => 'rapls-passkey-credentials' === $d['group_id'] );
	$audit = array_filter( $out['data'], fn( $d ) => 'rapls-passkey-audit' === $d['group_id'] );
	check( 'exports the user\'s two passkeys', count( $creds ) === 2 );
	check( 'exports the user\'s two audit rows', count( $audit ) === 2 );
	check( 'unlabeled passkey shows a placeholder', false !== strpos( json_encode( $out['data'] ), '—' ) || false !== strpos( json_encode( $out['data'], JSON_UNESCAPED_UNICODE ), '—' ) );

	// Unknown email exports nothing but is still done.
	$none = $pd->export( 'nobody@example.test' );
	check( 'unknown email exports no data', array() === $none['data'] && true === $none['done'] );

	// --- erase -----------------------------------------------------------------
	$res = $pd->erase( 'alice@example.test' );
	check( 'erase reports items removed', true === $res['items_removed'] );
	check( 'erase is done', true === $res['done'] );
	check( 'user 5 credentials gone', array() === ( new CredentialRepository() )->find_by_user( 5 ) );
	check( 'user 9 credentials untouched', count( ( new CredentialRepository() )->find_by_user( 9 ) ) === 1 );
	check( 'user 5 audit gone', array() === \RaplsPasskey\Audit\AuditLog::for_user( 5 ) );
	check( 'user 9 audit untouched', count( \RaplsPasskey\Audit\AuditLog::for_user( 9 ) ) === 1 );
	check( 'seen-devices meta removed', ! isset( $GLOBALS['__meta'][5][ Notifications::SEEN_META ] ) );
	check( 'user-handle meta removed', ! isset( $GLOBALS['__meta'][5][ UserHandle::META ] ) );

	// --- purge guard -----------------------------------------------------------
	check( 'purge_user(0) is a no-op', false === $pd->purge_user( 0 ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
