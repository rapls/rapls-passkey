<?php
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
	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
	}
	public function query( $sql ) {
		$this->dropped[] = $sql;
		return true;
	}
}
$GLOBALS['wpdb'] = new WPDB_Stub();

// Capture the SQL dbDelta receives instead of touching a real database.
$GLOBALS['__dbdelta_sql'] = array();
function dbDelta( $sql ) {
	$GLOBALS['__dbdelta_sql'][] = $sql;
	return array();
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
$sql = $GLOBALS['__dbdelta_sql'][0] ?? '';

check( 'install() issues one dbDelta statement', count( $GLOBALS['__dbdelta_sql'] ) === 1 );
check( 'CREATE TABLE targets the credentials table', strpos( $sql, 'CREATE TABLE wp_rapls_passkey_credentials' ) !== false );
foreach ( array( 'user_id', 'credential_id', 'public_key', 'sign_count', 'aaguid', 'attestation_type', 'label' ) as $col ) {
	check( "column {$col} is defined", strpos( $sql, $col ) !== false );
}
check( 'credential_id has a UNIQUE key', strpos( $sql, 'UNIQUE KEY credential_id' ) !== false );
check( 'user_id has an index', strpos( $sql, 'KEY user_id' ) !== false );

// Drop must short-circuit on $wpdb and remove the table.
$GLOBALS['__deleted_options'] = array();
function delete_option( $name ) {
	$GLOBALS['__deleted_options'][] = $name;
	return true;
}
Schema::drop();
check( 'drop() issues DROP TABLE IF EXISTS', strpos( $GLOBALS['wpdb']->dropped[0] ?? '', 'DROP TABLE IF EXISTS wp_rapls_passkey_credentials' ) !== false );

// --- cleanup the temporary upgrade.php stub ------------------------------
@unlink( __DIR__ . '/wp-admin/includes/upgrade.php' );
@rmdir( __DIR__ . '/wp-admin/includes' );
@rmdir( __DIR__ . '/wp-admin' );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
