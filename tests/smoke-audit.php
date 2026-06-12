<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Audit log: records events when enabled, no-ops when disabled, reads back.
 *
 *   php tests/smoke-audit.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }
if ( ! defined( 'OBJECT' ) ) { define( 'OBJECT', 'OBJECT' ); }

$GLOBALS['__opt'] = array( 'rapls_passkey_settings' => array( 'audit_enabled' => true ) );
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }
function apply_filters( $tag, $value ) { return $value; }
function sanitize_text_field( $v ) { return is_string( $v ) ? trim( $v ) : ''; }
function wp_unslash( $v ) { return $v; }
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';

class WPDB_Audit {
	public $prefix = 'wp_';
	public $rows = array();
	private $auto = 0;
	public function insert( $table, $data, $formats ) {
		$data['id'] = ++$this->auto;
		$this->rows[] = $data;
		return 1;
	}
	public function prepare( $q, ...$a ) { return array( 'q' => $q, 'args' => $a ); }
	public function get_results( $prepared, $output = OBJECT ) {
		$limit = (int) $prepared['args'][0];
		$rows = array_reverse( $this->rows );
		return array_slice( $rows, 0, $limit );
	}
}
$GLOBALS['wpdb'] = new WPDB_Audit();

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

use RaplsPasskey\Audit\AuditLog;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

AuditLog::record( AuditLog::REGISTERED, 14, 'id=3' );
AuditLog::record( AuditLog::LOGIN, 14, 'cred=3' );
check( 'records are inserted when enabled', count( $GLOBALS['wpdb']->rows ) === 2 );
check( 'event + user stored', $GLOBALS['wpdb']->rows[0]['event'] === 'registered' && $GLOBALS['wpdb']->rows[0]['user_id'] === 14 );
check( 'client ip captured', $GLOBALS['wpdb']->rows[0]['ip'] === '203.0.113.7' );

$recent = AuditLog::recent( 10 );
check( 'recent() returns newest first', $recent[0]['event'] === 'login' );

// Disable auditing -> no more rows.
$GLOBALS['__opt']['rapls_passkey_settings']['audit_enabled'] = false;
AuditLog::record( AuditLog::REMOVED, 14, 'id=3' );
check( 'no record when audit disabled', count( $GLOBALS['wpdb']->rows ) === 2 );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
