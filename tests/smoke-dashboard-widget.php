<?php
/**
 * DashboardWidget: registration is gated on manage_options, and the body shows
 * adoption totals, the share of all users, recent-30-day activity, and links.
 *
 *   php tests/smoke-dashboard-widget.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );
	define( 'ARRAY_A', 'ARRAY_A' );
	define( 'DAY_IN_SECONDS', 86400 );

	$GLOBALS['cap']     = true;
	$GLOBALS['widgets'] = array();

	function __( $s, $d = null ) { return $s; }
	function esc_html( $s ) { return $s; }
	function esc_html__( $s, $d = null ) { return $s; }
	function esc_url( $s ) { return $s; }
	function esc_attr( $s ) { return $s; }
	function wp_kses_post( $s ) { return $s; }
	function admin_url( $p = '' ) { return 'https://example.test/wp-admin/' . $p; }
	function number_format_i18n( $n ) { return (string) $n; }
	function current_user_can( $cap ) { return ! empty( $GLOBALS['cap'] ); }
	function count_users() { return array( 'total_users' => 10 ); }
	function add_action() {}
	function wp_add_dashboard_widget( $id, $title, $cb ) { $GLOBALS['widgets'][ $id ] = $title; }

	class FakeWpdb {
		public $prefix = 'wp_';
		public $total = 3; public $distinct = 2; public $audit = array();
		public function prepare( $sql, ...$args ) {
			foreach ( $args as $a ) { $sql = preg_replace( '/%s|%d/', is_int( $a ) ? (string) $a : "'" . $a . "'", $sql, 1 ); }
			return $sql;
		}
		public function get_var( $sql ) {
			if ( false !== strpos( $sql, 'DISTINCT' ) ) { return $this->distinct; }
			if ( false !== strpos( $sql, 'COUNT(*)' ) ) { return $this->total; }
			return 0;
		}
		public function get_results( $sql, $out = ARRAY_A ) {
			if ( false !== strpos( $sql, 'rapls_passkey_audit' ) ) { return $this->audit; }
			return array();
		}
	}
	$GLOBALS['wpdb'] = new FakeWpdb();

	require dirname( __DIR__ ) . '/src/Credentials/Schema.php';
	require dirname( __DIR__ ) . '/src/Credentials/Credential.php';
	require dirname( __DIR__ ) . '/src/Credentials/CredentialRepository.php';
	require dirname( __DIR__ ) . '/src/Audit/AuditLog.php';
	require dirname( __DIR__ ) . '/src/Admin/DashboardWidget.php';

	use RaplsPasskey\Credentials\CredentialRepository;
	use RaplsPasskey\Admin\DashboardWidget;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$recent = gmdate( 'Y-m-d H:i:s', time() - 3 * DAY_IN_SECONDS );
	$old    = gmdate( 'Y-m-d H:i:s', time() - 60 * DAY_IN_SECONDS );
	$GLOBALS['wpdb']->audit = array(
		array( 'event' => 'login', 'created_at' => $recent ),
		array( 'event' => 'login', 'created_at' => $recent ),
		array( 'event' => 'registered', 'created_at' => $recent ),
		array( 'event' => 'login', 'created_at' => $old ), // outside the window
	);

	$widget = new DashboardWidget( new CredentialRepository() );

	// --- registration gating ---------------------------------------------------
	$GLOBALS['cap'] = true;
	$widget->add_widget();
	check( 'registers the widget for capable users', isset( $GLOBALS['widgets']['rapls_passkey_adoption'] ) );

	$GLOBALS['widgets'] = array();
	$GLOBALS['cap'] = false;
	$widget->add_widget();
	check( 'skips registration without manage_options', array() === $GLOBALS['widgets'] );
	$GLOBALS['cap'] = true;

	// --- body ------------------------------------------------------------------
	ob_start();
	$widget->render();
	$html = ob_get_clean();

	check( 'shows the total passkey count (3)', false !== strpos( $html, '3' ) );
	check( 'shows users with a passkey and total (2 / 10)', false !== strpos( $html, '2 / 10' ) );
	check( 'computes the adoption percentage (20%)', false !== strpos( $html, '20%' ) );
	check( 'counts recent logins in the window (2)', false !== strpos( $html, '2 logins' ) );
	check( 'counts recent registrations in the window (1)', false !== strpos( $html, '1 new registrations' ) );
	check( 'links to settings', false !== strpos( $html, 'page=rapls-passkey' ) );
	check( 'links to the users list', false !== strpos( $html, 'users.php' ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
