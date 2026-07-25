<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Verifies the credential Schema composes its table name from $wpdb->prefix and
 * builds a dbDelta statement with the expected columns and keys. Runs standalone
 * with a stubbed $wpdb (no database needed).
 *
 *   php tests/smoke-schema.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// --- Minimal $wpdb stub ---------------------------------------------------
class WPDB_Stub {
	public $prefix = 'wp_';
	public $dropped = array();
	public $last_error = '';
	/** Set to the index name once the migration's ALTER TABLE has "created" it. */
	public $slot_index = null;
	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
	}
	public function query( $sql ) {
		$this->dropped[] = $sql;
		if ( false !== strpos( $sql, 'ADD UNIQUE KEY user_slot' ) ) {
			$this->slot_index = 'user_slot';
		}
		return true;
	}
	public function prepare( $query, ...$args ) {
		foreach ( $args as $a ) {
			$rep   = is_int( $a ) ? (string) $a : "'" . (string) $a . "'";
			$query = preg_replace( '/%[dsf]/', $rep, $query, 1 );
		}
		return $query;
	}
	// The slot back-fill reads rows needing a number; nothing pre-exists here.
	public function get_results( $sql, $output = null ) {
		return array();
	}
	public function get_var( $sql ) {
		// SHOW INDEX ... WHERE Key_name = 'user_slot'
		if ( false !== strpos( $sql, 'SHOW INDEX' ) ) {
			return $this->slot_index;
		}
		return null;
	}
}
$GLOBALS['wpdb'] = new WPDB_Stub();
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }

// Capture the SQL dbDelta receives instead of touching a real database.
$GLOBALS['__dbdelta_sql'] = array();
function dbDelta( $sql ) {
	$GLOBALS['__dbdelta_sql'][] = $sql;
	return array();
}

$GLOBALS['__options'] = array();
$GLOBALS['__deleted_options'] = array();
function update_option( $k, $v, $autoload = null ) { $GLOBALS['__options'][ $k ] = $v; return true; }
function get_option( $k, $default = false ) { return $GLOBALS['__options'][ $k ] ?? $default; }
function delete_option( $k ) {
	$GLOBALS['__deleted_options'][] = $k;
	unset( $GLOBALS['__options'][ $k ] );
	return true;
}

// upgrade.php (which defines dbDelta in WP) is required by install(); provide
// an empty stand-in so the require_once succeeds.
@mkdir( __DIR__ . '/wp-admin/includes', 0777, true );
if ( ! file_exists( __DIR__ . '/wp-admin/includes/upgrade.php' ) ) {
	file_put_contents( __DIR__ . '/wp-admin/includes/upgrade.php', "<?php\n" );
}

require dirname( __DIR__ ) . '/src/Credentials/Schema.php';

use RaplsPasskey\Credentials\Schema;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

check( 'table name uses the wpdb prefix', Schema::credentials_table() === 'wp_rapls_passkey_credentials' );

Schema::install();
$sql      = $GLOBALS['__dbdelta_sql'][0] ?? '';
$auditSql = $GLOBALS['__dbdelta_sql'][1] ?? '';

check( 'install() issues two dbDelta statements', count( $GLOBALS['__dbdelta_sql'] ) === 2 );
check( 'CREATE TABLE targets the credentials table', strpos( $sql, 'CREATE TABLE wp_rapls_passkey_credentials' ) !== false );
foreach ( array( 'user_id', 'credential_id', 'credential_data', 'sign_count', 'label', 'last_used_at' ) as $col ) {
	check( "column {$col} is defined", strpos( $sql, $col ) !== false );
}
check( 'credential_id has a UNIQUE key', strpos( $sql, 'UNIQUE KEY credential_id' ) !== false );
check( 'user_id has an index', strpos( $sql, 'KEY user_id' ) !== false );

check( 'audit table name uses the wpdb prefix', Schema::audit_table() === 'wp_rapls_passkey_audit' );
check( 'CREATE TABLE targets the audit table', strpos( $auditSql, 'CREATE TABLE wp_rapls_passkey_audit' ) !== false );
foreach ( array( 'event', 'detail', 'ip', 'created_at' ) as $col ) {
	check( "audit column {$col} is defined", strpos( $auditSql, $col ) !== false );
}

// The per-user cap is enforced by a UNIQUE (user_id, slot_no) index, so the
// migration must create it and record that it exists — the registration path
// refuses to enforce a cap it cannot rely on (V14-01).
check( 'slot_no column is defined', strpos( $sql, 'slot_no' ) !== false );
check( 'migration adds the UNIQUE (user_id, slot_no) index', (bool) array_filter(
	$GLOBALS['wpdb']->dropped,
	static fn( $q ) => false !== strpos( $q, 'ADD UNIQUE KEY user_slot (user_id, slot_no)' )
) );
check( 'the slot index is recorded as present', Schema::cap_enforceable() === true );

// Drop must short-circuit on $wpdb and remove the table.
$GLOBALS['__deleted_options'] = array();
Schema::drop();
check( 'drop() issues DROP TABLE IF EXISTS', (bool) array_filter(
	$GLOBALS['wpdb']->dropped,
	static fn( $q ) => false !== strpos( $q, 'DROP TABLE IF EXISTS wp_rapls_passkey_credentials' )
) );

// --- cleanup the temporary upgrade.php stub ------------------------------
@unlink( __DIR__ . '/wp-admin/includes/upgrade.php' );
@rmdir( __DIR__ . '/wp-admin/includes' );
@rmdir( __DIR__ . '/wp-admin' );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
