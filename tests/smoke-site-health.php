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
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
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

	// The object-cache check leaves a marker in the database and looks for it in
	// the cache on the next run, so both have to be present here.
	define( 'HOUR_IN_SECONDS', 3600 );
	$GLOBALS['__ext_cache'] = false;
	$GLOBALS['__cache']     = array();
	function wp_using_ext_object_cache() { return (bool) ( $GLOBALS['__ext_cache'] ?? false ); }
	function wp_cache_get( $k, $g = '' ) { return $GLOBALS['__cache'][ "$g:$k" ] ?? false; }
	function wp_cache_set( $k, $v, $g = '', $ttl = 0 ) { $GLOBALS['__cache'][ "$g:$k" ] = $v; return true; }
	function wp_rand( $min = 0, $max = 1 ) { return 1; } // never trigger the sweep

	require_once __DIR__ . '/lib/wpdb-options.php';
	class FakeWpdb extends WPDB_Options {
		public function get_var( $sql ) {
			if ( false !== strpos( $sql, 'SHOW TABLES LIKE' ) ) {
				return preg_match( "/'([^']+)'/", $sql, $m ) ? $m[1] : null;
			}
			if ( false !== strpos( $sql, 'COUNT(*)' ) ) { return 5; }
			return parent::get_var( $sql );
		}
	}
	$GLOBALS['wpdb'] = new FakeWpdb();

	require dirname( __DIR__ ) . '/src/Support/OneTimeStore.php';
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
	check( 'registers five direct tests', count( $direct ) === 5 );
	check( 'each test has a callable', ! in_array( false, array_map( function ( $t ) { return is_callable( $t['test'] ); }, $direct ), true ) );
	check( 'the object-cache check is one of them', isset( $direct['rapls_passkey_cache'] ) );

	// --- the object cache -------------------------------------------------------
	// With no persistent cache installed there is nothing between two requests, so
	// there is nothing to warn about.
	$GLOBALS['__ext_cache'] = false;
	$r = $sh->test_object_cache();
	check( 'no object cache is reported as fine', 'good' === $r['status'] );

	// With one installed, the first run has nothing to compare against and must
	// not cry wolf; it leaves a marker instead.
	$GLOBALS['__ext_cache'] = true;
	$GLOBALS['__cache']     = array();
	$r = $sh->test_object_cache();
	check( 'the first run reports nothing and seeds a marker', 'good' === $r['status'] );

	// A cache that carried the marker across is behaving as WordPress assumes.
	$r = $sh->test_object_cache();
	check( 'a cache that carries the marker is fine', 'good' === $r['status'] );

	// A cache that lost it is the fault being looked for: anything spanning two
	// requests then fails at random.
	$GLOBALS['__cache'] = array();
	$r = $sh->test_object_cache();
	check( 'a cache that lost the marker is flagged', 'recommended' === $r['status'] );
	// The advice has to be actionable: name the usual cause and the file to look
	// at. A description that only says "something is wrong" sends nobody anywhere.
	check( 'and the advice names the usual cause', false !== strpos( $r['description'], 'APCu' ) );
	check( 'and the file to look at', false !== strpos( $r['description'], 'object-cache.php' ) );

	// --- result shape (https critical on a public host without SSL) ------------
	$GLOBALS['__ssl']  = false;
	$GLOBALS['__home'] = 'https://example.com'; // public host (not .test/.local).
	$r = $sh->test_https();
	check( 'https test reports critical without SSL', $r['status'] === 'critical' );
	check( 'result carries a badge + description + test key', isset( $r['badge']['color'], $r['description'] ) && $r['test'] === 'rapls_passkey_https' );
	check( 'critical badge is red', $r['badge']['color'] === 'red' );

	// Only true loopback hosts are treated as secure without SSL (browsers do not
	// exempt .local/.test), matching SetupWizard.
	$GLOBALS['__home'] = 'https://example.test'; // .test is NOT a secure context.
	check( 'a .test host without SSL is not treated as secure', $sh->test_https()['status'] === 'critical' );
	$GLOBALS['__home'] = 'http://localhost'; // loopback -> secure context -> good.
	check( 'localhost is treated as secure', $sh->test_https()['status'] === 'good' );
	$GLOBALS['__home'] = 'https://example.test'; // restore for the RP-id checks below.

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
