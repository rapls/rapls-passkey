<?php
/**
 * Notifications: event emails fire when enabled, respect filters, and the
 * new-device gate (silent on a known device, loud on a new one or a recovery
 * code login).
 *
 *   php tests/smoke-notifications.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Support {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	// Lightweight stand-in for the real Settings accessor.
	class Settings {
		public static $on = true;
		public static function notifications_enabled(): bool { return self::$on; }
	}
}

namespace {
	define( 'ABSPATH', __DIR__ . '/' );
	define( 'YEAR_IN_SECONDS', 31536000 );

	$GLOBALS['__mail']    = array();
	$GLOBALS['__meta']    = array();
	$GLOBALS['__filters'] = array(); // tag => callable returning bool

	function get_user_by( $field, $id ) { return $GLOBALS['__users'][ (int) $id ] ?? false; }
	function get_user_meta( $uid, $key, $single = false ) { return $GLOBALS['__meta'][ $uid ][ $key ] ?? ''; }
	function update_user_meta( $uid, $key, $value ) { $GLOBALS['__meta'][ $uid ][ $key ] = $value; return true; }
	function sanitize_text_field( $s ) { return trim( (string) $s ); }
	function wp_unslash( $s ) { return $s; }
	function is_email( $s ) { return false !== strpos( (string) $s, '@' ); }
	function is_ssl() { return true; }
	function wp_salt( $s = 'auth' ) { return 'unit-test-salt'; }
	function wp_date( $fmt ) { return '2026-06-10 12:00:00 (UTC)'; }
	function get_bloginfo( $k ) { return 'Test Site'; }
	function wp_specialchars_decode( $s, $q = null ) { return $s; }
	function __( $s, $d = null ) { return $s; }
	function apply_filters( $tag, $value, ...$args ) {
		if ( isset( $GLOBALS['__filters'][ $tag ] ) ) {
			return call_user_func( $GLOBALS['__filters'][ $tag ], $value, ...$args );
		}
		return $value;
	}
	function add_action() {}
	function wp_mail( $to, $subject, $body ) {
		$GLOBALS['__mail'][] = array( 'to' => $to, 'subject' => $subject, 'body' => $body );
		return true;
	}

	require dirname( __DIR__ ) . '/src/Security/Notifications.php';

	use RaplsPasskey\Security\Notifications;
	use RaplsPasskey\Support\Settings;

	class WP_User {
		public $ID;
		public $user_login;
		public $user_email;
		public $display_name;
		public function __construct( $id, $login, $email, $name ) {
			$this->ID = $id; $this->user_login = $login; $this->user_email = $email; $this->display_name = $name;
		}
	}

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}
	function mailcount() { return count( $GLOBALS['__mail'] ); }
	function lastmail() { return end( $GLOBALS['__mail'] ) ?: array( 'subject' => '', 'to' => '' ); }
	function reset_mail() { $GLOBALS['__mail'] = array(); }

	$alice = new WP_User( 1, 'alice', 'alice@example.test', 'Alice' );
	$GLOBALS['__users'] = array( 1 => $alice );

	$n = new Notifications();

	// --- registered ------------------------------------------------------------
	Settings::$on = true;
	reset_mail();
	$n->on_registered( 1, 99, 'My Phone' );
	check( 'registered email sent when enabled', mailcount() === 1 );
	check( 'registered email goes to the user', lastmail()['to'] === 'alice@example.test' );

	// disabled globally
	Settings::$on = false;
	reset_mail();
	$n->on_registered( 1, 99, 'My Phone' );
	check( 'no email when notifications disabled', mailcount() === 0 );
	Settings::$on = true;

	// filter veto
	$GLOBALS['__filters']['rapls_passkey_notify_registered'] = function ( $v, $uid ) { return false; };
	reset_mail();
	$n->on_registered( 1, 99, 'My Phone' );
	check( 'registered email suppressed by filter', mailcount() === 0 );
	unset( $GLOBALS['__filters']['rapls_passkey_notify_registered'] );

	// unknown user -> nothing
	reset_mail();
	$n->on_registered( 999, 1, null );
	check( 'no email for an unknown user', mailcount() === 0 );

	// --- deleted ---------------------------------------------------------------
	reset_mail();
	$n->on_deleted( 1, 99, 0 );
	check( 'removed email sent (self)', mailcount() === 1 );
	reset_mail();
	$n->on_deleted( 1, 99, 7 );
	check( 'removed email sent (by admin)', mailcount() === 1 );

	// --- new-device login ------------------------------------------------------
	// Fresh user, no cookie => new device => email, and the device is remembered.
	$GLOBALS['__meta'] = array();
	unset( $_COOKIE['rapls_pk_seen'] );
	reset_mail();
	$n->on_login( $alice, 'login' );
	check( 'new device login notifies', mailcount() === 1 );
	$seen = $GLOBALS['__meta'][1]['rapls_pk_seen_devices'] ?? array();
	check( 'new device is remembered', is_array( $seen ) && count( $seen ) === 1 );

	// Now present the matching cookie => known device => silent.
	// Recover the raw token the class minted by re-deriving from the stored hash
	// is impossible (hashed); instead simulate a known device by setting a cookie
	// and pre-seeding its hash.
	$token = str_repeat( 'a', 32 );
	$hash  = hash_hmac( 'sha256', $token, 'unit-test-salt' );
	$GLOBALS['__meta'][1]['rapls_pk_seen_devices'] = array( $hash );
	$_COOKIE['rapls_pk_seen'] = $token;
	reset_mail();
	$n->on_login( $alice, 'login' );
	check( 'known device login stays silent', mailcount() === 0 );

	// Recovery-code login always notifies, even on a known device.
	reset_mail();
	$n->on_login( $alice, 'recovery-code' );
	check( 'recovery-code login always notifies', mailcount() === 1 );
	check( 'recovery email has its own subject', false !== strpos( lastmail()['subject'], 'リカバリーコード' ) );

	// Filter veto on new-device still records the device but sends nothing.
	$GLOBALS['__meta'] = array();
	unset( $_COOKIE['rapls_pk_seen'] );
	$GLOBALS['__filters']['rapls_passkey_notify_new_device'] = function ( $v, $u, $ctx ) { return false; };
	reset_mail();
	$n->on_login( $alice, 'login' );
	check( 'new-device email suppressed by filter', mailcount() === 0 );
	$seen2 = $GLOBALS['__meta'][1]['rapls_pk_seen_devices'] ?? array();
	check( 'device still remembered despite filter veto', is_array( $seen2 ) && count( $seen2 ) === 1 );
	unset( $GLOBALS['__filters']['rapls_passkey_notify_new_device'] );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
