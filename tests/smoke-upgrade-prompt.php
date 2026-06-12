<?php
/**
 * UpgradePrompt::maybe_intercept — only an eligible password login (logged in,
 * no passkey, enabled, not recently seen, not interim) is redirected to the
 * upgrade screen.
 *
 *   php tests/smoke-upgrade-prompt.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Support {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	class Settings {
		public static $on = true;
		public static function upgrade_prompt_enabled(): bool { return self::$on; }
	}
}

namespace {
	define( 'ABSPATH', __DIR__ . '/' );
	define( 'DAY_IN_SECONDS', 86400 );
	if ( ! defined( 'ARRAY_A' ) ) {
		define( 'ARRAY_A', 'ARRAY_A' );
	}

	$GLOBALS['__meta'] = array();

	function get_user_meta( $uid, $key, $single = false ) { return $GLOBALS['__meta'][ $uid ][ $key ] ?? ''; }
	function add_filter() {}
	function add_action() {}
	function admin_url( $p = '' ) { return 'https://example.test/wp-admin/' . $p; }
	function wp_login_url() { return 'https://example.test/wp-login.php'; }
	function add_query_arg( $args, $url ) {
		$q = array();
		foreach ( $args as $k => $v ) { $q[] = $k . '=' . $v; }
		return $url . '?' . implode( '&', $q );
	}

	class FakeWpdb {
		public $prefix = 'wp_';
		public $rows = array(); // credential rows
		public function get_results( $sql, $output = ARRAY_A ) {
			if ( preg_match( '/user_id = (\d+)/', $sql, $m ) ) {
				$uid = (int) $m[1];
				return array_values( array_filter( $this->rows, fn( $r ) => (int) $r['user_id'] === $uid ) );
			}
			return array();
		}
		public function prepare( $sql, ...$args ) {
			foreach ( $args as $a ) { $sql = preg_replace( '/%d|%s/', is_int( $a ) ? (string) $a : "'$a'", $sql, 1 ); }
			return $sql;
		}
	}
	$GLOBALS['wpdb'] = new FakeWpdb();

	require dirname( __DIR__ ) . '/src/Credentials/Schema.php';
	require dirname( __DIR__ ) . '/src/Credentials/Credential.php';
	require dirname( __DIR__ ) . '/src/Credentials/CredentialRepository.php';
	require dirname( __DIR__ ) . '/src/Login/UpgradePrompt.php';

	use RaplsPasskey\Credentials\CredentialRepository;
	use RaplsPasskey\Login\UpgradePrompt;
	use RaplsPasskey\Support\Settings;

	class WP_User { public $ID; public function __construct( $id ) { $this->ID = $id; } }

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}
	function is_upgrade_url( $v ) { return is_string( $v ) && false !== strpos( $v, 'action=rapls_pk_upgrade' ); }

	$up   = new UpgradePrompt( new CredentialRepository() );
	$dash = 'https://example.test/wp-admin/';

	// Not a user (WP_Error path): passthrough.
	check( 'passes through when not a user', $up->maybe_intercept( $dash, '', null ) === $dash );

	// Eligible: logged in, no passkey, enabled, not seen => intercept.
	Settings::$on = true;
	check( 'intercepts an eligible password login', is_upgrade_url( $up->maybe_intercept( $dash, '', new WP_User( 1 ) ) ) );

	// Carries the destination along.
	check( 'preserves the destination', false !== strpos( $up->maybe_intercept( $dash, '', new WP_User( 1 ) ), rawurlencode( $dash ) ) );

	// Disabled: passthrough.
	Settings::$on = false;
	check( 'no intercept when disabled', $up->maybe_intercept( $dash, '', new WP_User( 1 ) ) === $dash );
	Settings::$on = true;

	// Has a passkey: passthrough.
	$GLOBALS['wpdb']->rows = array( array( 'id' => 1, 'user_id' => 2, 'credential_id' => 'X', 'credential_data' => '{}', 'sign_count' => 0, 'label' => null, 'created_at' => 'x', 'last_used_at' => null ) );
	check( 'no intercept when the user already has a passkey', $up->maybe_intercept( $dash, '', new WP_User( 2 ) ) === $dash );

	// Recently seen: passthrough.
	$GLOBALS['__meta'][3]['rapls_pk_upgrade_seen'] = time() - 100;
	check( 'no intercept when recently shown', $up->maybe_intercept( $dash, '', new WP_User( 3 ) ) === $dash );

	// Seen long ago: intercept again.
	$GLOBALS['__meta'][3]['rapls_pk_upgrade_seen'] = time() - ( 40 * DAY_IN_SECONDS );
	check( 'intercepts again after the interval', is_upgrade_url( $up->maybe_intercept( $dash, '', new WP_User( 3 ) ) ) );

	// interim-login: passthrough.
	$_REQUEST['interim-login'] = '1';
	check( 'no intercept during interim-login', $up->maybe_intercept( $dash, '', new WP_User( 1 ) ) === $dash );
	unset( $_REQUEST['interim-login'] );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
