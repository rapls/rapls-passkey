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
	public $options  = 'wp_options';
	public $usermeta = 'wp_usermeta';
	public $dropped = array();
	public $last_error = '';
	/** Set to the index name once the migration's ALTER TABLE has "created" it. */
	public $slot_index = null;
	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
	}
	public function esc_like( $s ) { return $s; }
	/** Set false to model a writer that does NOT enforce the unique slot index. */
	public $writer_enforces = true;
	/** Set true to model a database that cannot delete the probe's own rows. */
	public $fail_probe_cleanup = false;
	/** Probe rows the writer currently holds, keyed by "user_id:slot_no". */
	private $probe = array();

	/** Migration back-off rows this "database" holds, by option_name. */
	public $lock_rows = array();
	/** Handle-claim back-fill statements seen. */
	public $claim_backfills = array();

	public function query( $sql ) {
		$this->dropped[] = $sql;
		// The handle-claim back-fill: one INSERT … SELECT from the usermeta table.
		if ( false !== strpos( $sql, 'INSERT IGNORE INTO' ) && false !== strpos( $sql, 'usermeta' ) ) {
			$this->claim_backfills[] = $sql;
			return 1;
		}
		// The migration back-off row: unique option_name, so the second attempt in
		// the same window is refused by the database.
		if ( false !== strpos( $sql, 'rapls_passkey_migrate_' ) && 0 === strpos( ltrim( $sql ), 'INSERT INTO' ) ) {
			if ( preg_match( "/VALUES \('([^']+)'/", $sql, $m ) ) {
				if ( isset( $this->lock_rows[ $m[1] ] ) ) { return false; }
				$this->lock_rows[ $m[1] ] = true;
				return 1;
			}
		}
		if ( false !== strpos( $sql, 'ADD UNIQUE KEY user_slot' ) ) {
			$this->slot_index = 'user_slot';
		}
		// The writer probe: two rows claiming the same (user_id, slot_no). With the
		// constraint in place the second INSERT must fail.
		if ( false !== strpos( $sql, 'INSERT INTO' ) && preg_match( '/VALUES \(0, (\d+),/', $sql, $m ) ) {
			$key = '0:' . $m[1];
			if ( $this->writer_enforces && isset( $this->probe[ $key ] ) ) {
				return false; // duplicate key
			}
			$this->probe[ $key ] = true;
			return 1;
		}
		if ( 0 === strpos( ltrim( $sql ), 'DELETE' ) && preg_match( '/slot_no = (\d+)/', $sql, $m ) ) {
			if ( $this->fail_probe_cleanup ) {
				return false;
			}
			unset( $this->probe[ '0:' . $m[1] ] );
			return 1;
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
	/** Shape reported for the slot index; overridden in the tests below. */
	public $index_rows = null;

	public function get_results( $sql, $output = null ) {
		// SHOW INDEX must report the index's SHAPE, not just its name: a non-unique
		// index, or one over other columns, enforces nothing.
		if ( false !== strpos( $sql, 'SHOW INDEX' ) ) {
			if ( null === $this->slot_index ) {
				return array();
			}
			return null !== $this->index_rows ? $this->index_rows : array(
				array( 'Key_name' => 'user_slot', 'Non_unique' => '0', 'Seq_in_index' => '1', 'Column_name' => 'user_id' ),
				array( 'Key_name' => 'user_slot', 'Non_unique' => '0', 'Seq_in_index' => '2', 'Column_name' => 'slot_no' ),
			);
		}
		// The slot back-fill reads rows needing a number; nothing pre-exists here.
		return array();
	}
	public function get_var( $sql ) {
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
function wp_rand( $min = 0, $max = 1 ) { return random_int( $min, $max ); }
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

require dirname( __DIR__ ) . '/src/Credentials/UserHandle.php';
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

// V16-01: the cap may only be trusted when the index has the RIGHT SHAPE and the
// WRITER actually refuses a duplicate. Either alone is not enough — a read can be
// answered by a replica whose schema differs from the writer's.
$wpdb = $GLOBALS['wpdb'];

Schema::flush_cap_cache();
$wpdb->index_rows = array(
	array( 'Key_name' => 'user_slot', 'Non_unique' => '1', 'Seq_in_index' => '1', 'Column_name' => 'user_id' ),
	array( 'Key_name' => 'user_slot', 'Non_unique' => '1', 'Seq_in_index' => '2', 'Column_name' => 'slot_no' ),
);
check( 'a same-named NON-UNIQUE index does not count (V16-01)', Schema::cap_enforceable() === false );

Schema::flush_cap_cache();
$wpdb->index_rows = array(
	array( 'Key_name' => 'user_slot', 'Non_unique' => '0', 'Seq_in_index' => '1', 'Column_name' => 'user_id' ),
	array( 'Key_name' => 'user_slot', 'Non_unique' => '0', 'Seq_in_index' => '2', 'Column_name' => 'label' ),
);
check( 'a unique index over the WRONG columns does not count (V16-01)', Schema::cap_enforceable() === false );

Schema::flush_cap_cache();
$wpdb->index_rows = array(
	array( 'Key_name' => 'user_slot', 'Non_unique' => '0', 'Seq_in_index' => '1', 'Column_name' => 'slot_no' ),
	array( 'Key_name' => 'user_slot', 'Non_unique' => '0', 'Seq_in_index' => '2', 'Column_name' => 'user_id' ),
);
check( 'the columns must be in the right order (V16-01)', Schema::cap_enforceable() === false );

// The reader may still show a perfect index while the WRITER has lost it.
Schema::flush_cap_cache();
$wpdb->index_rows      = null;   // reader reports the correct index
$wpdb->writer_enforces = false;  // but the writer accepts a duplicate
check( 'a writer that accepts a duplicate slot does not count (V16-01)', Schema::cap_enforceable() === false );

Schema::flush_cap_cache();
$wpdb->writer_enforces = true;
check( 'index shape + writer both good is enforceable again', Schema::cap_enforceable() === true );

// V18-01: a probe that cannot remove its own rows must not report success — that
// would call a database that leaves debris a healthy one.
Schema::flush_cap_cache();
$wpdb->fail_probe_cleanup = true;
check( 'a probe whose cleanup keeps failing reports NOT enforceable (V18-01)', Schema::cap_enforceable() === false );
$wpdb->fail_probe_cleanup = false;
Schema::flush_cap_cache();
check( 'and it recovers once cleanup works again', Schema::cap_enforceable() === true );

// Drop must short-circuit on $wpdb and remove the table.
$GLOBALS['__deleted_options'] = array();
Schema::drop();
check( 'drop() issues DROP TABLE IF EXISTS', (bool) array_filter(
	$GLOBALS['wpdb']->dropped,
	static fn( $q ) => false !== strpos( $q, 'DROP TABLE IF EXISTS wp_rapls_passkey_credentials' )
) );

// --- V22-02: the migration gives existing handles their claim row -------------
$GLOBALS['wpdb']->claim_backfills = array();
Schema::install();
check( 'the migration back-fills a claim row for every stored handle (V22-02)', 1 === count( $GLOBALS['wpdb']->claim_backfills ) );
$backfill = $GLOBALS['wpdb']->claim_backfills[0] ?? '';
check( 'it names the handle meta key as its source', false !== strpos( $backfill, 'rapls_passkey_user_handle' ) );
check( 'it writes rows under the claim prefix', false !== strpos( $backfill, 'rapls_pk_handle_' ) );
check( 'and it is an INSERT IGNORE, so running it again is safe', 0 === strpos( ltrim( $backfill ), 'INSERT IGNORE' ) );

// --- V22-06: a non-admin request may run the migration once per window --------
// rest_pre_dispatch runs before any permission callback, so an anonymous caller
// must not be able to re-run a failing migration on every request.
$GLOBALS['__options'] = array();                 // stored version: absent -> behind
$GLOBALS['wpdb']->lock_rows      = array();
$GLOBALS['wpdb']->claim_backfills = array();
Schema::maybe_upgrade_throttled( 300 );
$first_attempt = count( $GLOBALS['wpdb']->claim_backfills );
check( 'the first ceremony request in a window runs the migration (V22-06)', $first_attempt >= 1 );
check( 'and claims the window with one row', 1 === count( $GLOBALS['wpdb']->lock_rows ) );

$GLOBALS['__options'] = array();                 // still behind: the migration "failed"
$GLOBALS['wpdb']->claim_backfills = array();
Schema::maybe_upgrade_throttled( 300 );
Schema::maybe_upgrade_throttled( 300 );
Schema::maybe_upgrade_throttled( 300 );
check( 'further requests in the same window do NOT re-run it (V22-06)', 0 === count( $GLOBALS['wpdb']->claim_backfills ) );
check( 'and no second row is claimed for that window', 1 === count( $GLOBALS['wpdb']->lock_rows ) );

// Once the schema is current, the throttled path does nothing at all.
$GLOBALS['__options'][ 'rapls_passkey_schema_version' ] = Schema::current_version();
$GLOBALS['wpdb']->lock_rows = array();
Schema::maybe_upgrade_throttled( 300 );
check( 'an up-to-date site claims nothing and does nothing', array() === $GLOBALS['wpdb']->lock_rows );

// --- cleanup the temporary upgrade.php stub ------------------------------
@unlink( __DIR__ . '/wp-admin/includes/upgrade.php' );
@rmdir( __DIR__ . '/wp-admin/includes' );
@rmdir( __DIR__ . '/wp-admin' );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
