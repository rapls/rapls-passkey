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

	// Formula-injection neutralisation: a login starting with = / @ / - / + is
	// prefixed with an apostrophe so spreadsheets do not execute it.
	$evil = $export->to_csv( array(
		array( 'created_at' => '2026-06-10 09:00:00', 'event' => 'login', 'user_id' => 9, 'user_login' => '=cmd|calc', 'detail' => '@SUM(1)', 'ip' => '203.0.113.9' ),
	) );
	check( 'neutralises a formula-leading username', false !== strpos( $evil, "'=cmd|calc" ) && false === strpos( $evil, ',=cmd|calc' ) );
	check( 'neutralises a formula-leading detail', false !== strpos( $evil, "'@SUM(1)" ) );

	// AND WHEN SOMETHING HARMLESS COMES FIRST (V83-02). A spreadsheet skips
	// leading whitespace before deciding whether a cell is a formula; the check
	// looked at the first BYTE, so a space, a tab, a non-breaking space or a
	// byte-order mark in front of it was enough to get through. Every
	// combination of a leading character and a formula character, one row each.
	$leaders = array(
		'a space'              => ' ',
		'a tab'                => "\t",
		'a carriage return'    => "\r",
		'a non-breaking space' => "\xC2\xA0",
		'a byte-order mark'    => "\xEF\xBB\xBF",
		'an en quad'           => "\xE2\x80\x80",
		'a narrow no-break'    => "\xE2\x80\xAF",
		'an ideographic space' => "\xE3\x80\x80",
		'a zero-width space'   => "\xE2\x80\x8B",
		'two spaces and a tab' => "  \t",
	);
	$leaks = array();
	foreach ( $leaders as $what => $lead ) {
		foreach ( array( '=', '+', '-', '@' ) as $op ) {
			$payload = $lead . $op . '1+1';
			$out     = $export->to_csv( array(
				array( 'created_at' => '2026-06-10 09:00:00', 'event' => 'login', 'user_id' => 9, 'user_login' => $payload, 'detail' => '-cmd', 'ip' => '203.0.113.9' ),
			) );
			// The guarded form is the apostrophe immediately before the value,
			// with the leading characters preserved after it.
			if ( false === strpos( $out, "'" . $payload ) ) {
				$leaks[] = $what . ' + ' . $op;
			}
		}
	}
	check( 'a formula behind leading whitespace is still neutralised (V83-02)' . ( $leaks ? ' — through: ' . implode( ', ', $leaks ) : '' ), array() === $leaks );

	// And the guard does not fire on ordinary values, or the export becomes
	// apostrophes.
	$plain = $export->to_csv( array(
		array( 'created_at' => '2026-06-10 09:00:00', 'event' => 'login', 'user_id' => 9, 'user_login' => 'alice', 'detail' => 'ok', 'ip' => '203.0.113.9' ),
	) );
	check( 'an ordinary value is left alone', false === strpos( $plain, "'alice" ) && false !== strpos( $plain, 'alice' ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
