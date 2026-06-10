<?php
/**
 * UsersColumn + CredentialRepository aggregates: the Users-list column header,
 * per-user cell rendering (count / last-used / 未登録, one query), and the
 * site-wide adoption stats.
 *
 *   php tests/smoke-users-column.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	define( 'ABSPATH', __DIR__ . '/' );
	if ( ! defined( 'ARRAY_A' ) ) {
		define( 'ARRAY_A', 'ARRAY_A' );
	}

	function __( $s, $d = null ) { return $s; }
	function esc_html( $s ) { return $s; }
	function esc_html__( $s, $d = null ) { return $s; }
	function get_option( $k, $d = false ) { return 'Y-m-d'; }
	function mysql2date( $fmt, $date ) { return substr( (string) $date, 0, 10 ); }

	/**
	 * $wpdb stub backed by an in-memory credentials table, with a query counter
	 * so we can prove the column does one grouped query, not one per row.
	 */
	class FakeWpdb {
		public $prefix = 'wp_';
		public $rows = array();
		public $group_queries = 0;

		public function get_results( $sql, $output = ARRAY_A ) {
			if ( false !== strpos( $sql, 'GROUP BY user_id' ) ) {
				$this->group_queries++;
				$agg = array();
				foreach ( $this->rows as $r ) {
					$uid = (int) $r['user_id'];
					if ( ! isset( $agg[ $uid ] ) ) {
						$agg[ $uid ] = array( 'user_id' => $uid, 'c' => 0, 'last_used' => null );
					}
					$agg[ $uid ]['c']++;
					$lu = $r['last_used_at'] ?? null;
					if ( $lu && ( null === $agg[ $uid ]['last_used'] || $lu > $agg[ $uid ]['last_used'] ) ) {
						$agg[ $uid ]['last_used'] = $lu;
					}
				}
				return array_values( $agg );
			}
			return array();
		}

		public function get_var( $sql ) {
			if ( false !== strpos( $sql, 'COUNT(DISTINCT user_id)' ) ) {
				$u = array();
				foreach ( $this->rows as $r ) { $u[ (int) $r['user_id'] ] = true; }
				return count( $u );
			}
			if ( false !== strpos( $sql, 'COUNT(*)' ) ) {
				return count( $this->rows );
			}
			return 0;
		}
	}

	$GLOBALS['wpdb'] = new FakeWpdb();

	require dirname( __DIR__ ) . '/src/Credentials/Schema.php';
	require dirname( __DIR__ ) . '/src/Credentials/Credential.php';
	require dirname( __DIR__ ) . '/src/Credentials/CredentialRepository.php';
	require dirname( __DIR__ ) . '/src/Admin/UsersColumn.php';

	use RaplsPasskey\Credentials\CredentialRepository;
	use RaplsPasskey\Admin\UsersColumn;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$wpdb = $GLOBALS['wpdb'];
	$wpdb->rows = array(
		array( 'id' => 1, 'user_id' => 5, 'last_used_at' => '2026-02-01 09:00:00' ),
		array( 'id' => 2, 'user_id' => 5, 'last_used_at' => '2026-03-15 09:00:00' ),
		array( 'id' => 3, 'user_id' => 9, 'last_used_at' => null ),
	);

	$repo = new CredentialRepository();

	// --- aggregates ------------------------------------------------------------
	$stats = $repo->stats();
	check( 'stats counts total passkeys', $stats['total'] === 3 );
	check( 'stats counts distinct users', $stats['users'] === 2 );

	$by = $repo->counts_by_user();
	check( 'counts_by_user groups per user', count( $by ) === 2 );
	check( 'user 5 has 2 passkeys', ( $by[5]['count'] ?? 0 ) === 2 );
	check( 'user 5 last-used is the latest', ( $by[5]['last_used'] ?? '' ) === '2026-03-15 09:00:00' );
	check( 'user 9 last-used is null', array_key_exists( 9, $by ) && null === $by[9]['last_used'] );

	// --- column ----------------------------------------------------------------
	$col = new UsersColumn( $repo );
	$cols = $col->add_column( array( 'username' => 'Username' ) );
	check( 'column header added', isset( $cols['rapls_passkey'] ) );

	// Non-matching column passes the existing output through untouched.
	check( 'other columns untouched', $col->render_column( 'KEEP', 'email', 5 ) === 'KEEP' );

	$wpdb->group_queries = 0;
	$c5 = $col->render_column( '', 'rapls_passkey', 5 );
	$c9 = $col->render_column( '', 'rapls_passkey', 9 );
	$c7 = $col->render_column( '', 'rapls_passkey', 7 ); // no passkeys

	check( 'user 5 cell shows the count', false !== strpos( $c5, '2 個' ) );
	check( 'user 5 cell shows last-used date', false !== strpos( $c5, '2026-03-15' ) );
	check( 'user 9 cell shows the count without a date', false !== strpos( $c9, '1 個' ) && false === strpos( $c9, '最終' ) );
	check( 'user 7 cell shows 未登録', false !== strpos( $c7, '未登録' ) );
	check( 'counts loaded with a single grouped query for all rows', $wpdb->group_queries === 1 );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
