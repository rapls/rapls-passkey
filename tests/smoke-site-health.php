<?php
/**
 * SiteHealth: pure status decisions, the result-array shape, and that the
 * tests are registered as direct Site Health checks.
 *
 *   php tests/smoke-site-health.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Credentials {
	class Schema {
		public static function credentials_table(): string { return 'wp_rapls_passkey_credentials'; }
		public static function audit_table(): string { return 'wp_rapls_passkey_audit'; }
	}
}
namespace RaplsPasskey\Support {
	class Compat { public static function detect(): array { return array(); } }
}
namespace RaplsPasskey\WebAuthn {
	class RelyingParty {
		public static function from_site(): self { return new self(); }
		public function id(): string { return 'example.test'; }
	}
}

namespace {
	define( 'ABSPATH', __DIR__ . '/' );

	function __( $s, $d = null ) { return $s; }
	function add_filter() {}
	function esc_html( $s ) { return $s; }
	function is_ssl() { return $GLOBALS['__ssl'] ?? true; }
	function home_url() { return $GLOBALS['__home'] ?? 'https://example.test'; }
	function wp_parse_url( $url, $c = -1 ) { return parse_url( $url, $c ); }

	class FakeWpdb {
		public $prefix = 'wp_';
		public function prepare( $sql, ...$a ) {
			foreach ( $a as $x ) { $sql = preg_replace( '/%s|%d/', is_int( $x ) ? (string) $x : "'$x'", $sql, 1 ); }
			return $sql;
		}
		public function get_var( $sql ) {
			if ( false !== strpos( $sql, 'SHOW TABLES LIKE' ) ) {
				return preg_match( "/'([^']+)'/", $sql, $m ) ? $m[1] : null;
			}
			if ( false !== strpos( $sql, 'COUNT(*)' ) ) { return 5; }
			return null;
		}
	}
	$GLOBALS['wpdb'] = new FakeWpdb();

	require dirname( __DIR__ ) . '/src/Admin/SiteHealth.php';

	use RaplsPasskey\Admin\SiteHealth;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	// --- pure status helpers ---------------------------------------------------
	check( 'https good when secure', SiteHealth::https_status( true ) === 'good' );
	check( 'https critical when not secure', SiteHealth::https_status( false ) === 'critical' );
	check( 'library good when present', SiteHealth::library_status( true ) === 'good' );
	check( 'library critical when missing', SiteHealth::library_status( false ) === 'critical' );
	check( 'tables good when present', SiteHealth::tables_status( true ) === 'good' );
	check( 'tables recommended when missing', SiteHealth::tables_status( false ) === 'recommended' );

	$sh = new SiteHealth();

	// --- registration ----------------------------------------------------------
	$tests = $sh->add_tests( array() );
	$direct = $tests['direct'] ?? array();
	check( 'registers four direct tests', count( $direct ) === 4 );
	check( 'each test has a callable', ! in_array( false, array_map( function ( $t ) { return is_callable( $t['test'] ); }, $direct ), true ) );

	// --- result shape (https critical on a public host without SSL) ------------
	$GLOBALS['__ssl']  = false;
	$GLOBALS['__home'] = 'https://example.com'; // public host (not .test/.local).
	$r = $sh->test_https();
	check( 'https test reports critical without SSL', $r['status'] === 'critical' );
	check( 'result carries a badge + description + test key', isset( $r['badge']['color'], $r['description'] ) && $r['test'] === 'rapls_passkey_https' );
	check( 'critical badge is red', $r['badge']['color'] === 'red' );

	// Local host is treated as secure even without SSL.
	$GLOBALS['__home'] = 'https://example.test'; // ends with .test -> local -> good.
	check( 'local host is treated as secure', $sh->test_https()['status'] === 'good' );

	// RP test is informational/good and reports the RP id.
	check( 'rp test is good', $sh->test_rp()['status'] === 'good' );
	check( 'rp description mentions the RP id', false !== strpos( $sh->test_rp()['description'], 'example.test' ) );

	// --- Info tab (debug_information) ------------------------------------------
	$info = $sh->add_debug_info( array() );
	check( 'adds a Rapls Passkey info panel', isset( $info['rapls-passkey']['fields'] ) );
	$fields = $info['rapls-passkey']['fields'];
	check( 'info panel reports the RP id', ( $fields['rp_id']['value'] ?? '' ) === 'example.test' );
	check( 'info panel reports the passkey count', ( $fields['registered']['value'] ?? '' ) === '5' );
	check( 'info panel reports tables present', ( $fields['tables']['debug'] ?? '' ) === 'true' );
	check( 'info panel keeps existing sections', array_key_exists( 'rapls-passkey', $sh->add_debug_info( array( 'core' => array() ) ) ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
