<?php
/**
 * AuditExport::to_csv — header row, one line per event, and CSV escaping of
 * fields containing commas/quotes.
 *
 *   php tests/smoke-audit-export.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Audit {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	// Minimal stand-in so AuditExport's require resolves without the DB layer.
	class AuditLog {
		public static function recent( $limit = 50 ) { return array(); }
	}
}

namespace {
	define( 'ABSPATH', __DIR__ . '/' );

	function __( $s, $d = null ) { return $s; }
	function add_action() {}

	require dirname( __DIR__ ) . '/src/Admin/AuditExport.php';

	use RaplsPasskey\Admin\AuditExport;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$export = new AuditExport();

	$rows = array(
		array( 'created_at' => '2026-06-10 09:00:00', 'event' => 'registered', 'user_id' => 5, 'user_login' => 'alice', 'detail' => 'id=1', 'ip' => '203.0.113.1' ),
		array( 'created_at' => '2026-06-10 10:00:00', 'event' => 'login', 'user_id' => 5, 'user_login' => 'alice', 'detail' => 'cred=1, note="x"', 'ip' => '203.0.113.2' ),
	);

	$csv   = $export->to_csv( $rows );
	$lines = array_values( array_filter( explode( "\n", trim( $csv ) ) ) );

	check( 'has a header plus two data lines', count( $lines ) === 3 );
	check( 'header lists the columns', false !== strpos( $lines[0], 'Event' ) && false !== strpos( $lines[0], 'IP' ) );
	check( 'a data row includes the username', false !== strpos( $csv, 'alice' ) );
	check( 'a data row includes the event', false !== strpos( $csv, 'registered' ) );
	// A field with a comma + quote must be CSV-quoted.
	check( 'escapes commas/quotes in a field', false !== strpos( $csv, '"cred=1, note=""x"""' ) );

	// Empty input still yields a header line.
	$empty = $export->to_csv( array() );
	check( 'empty export still has the header', false !== strpos( $empty, 'Event' ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
