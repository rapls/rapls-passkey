<?php
/**
 * LoginGate: the pre-login veto filter — allow by default, deny on false or a
 * WP_Error from the rapls_passkey/allow_login filter.
 *
 *   php tests/smoke-login-gate.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );

	$GLOBALS['filter'] = null;
	$GLOBALS['__spam'] = null;   // What core's multisite check returns.
	$GLOBALS['__order'] = array();
	function __( $s, $d = null ) { return $s; }
	// Core's own check, as registered on `authenticate` at priority 99. These
	// logins set the cookie directly and never traverse that chain, so the gate
	// has to call it itself.
	function wp_authenticate_spam_check( $user ) {
		$GLOBALS['__order'][] = 'core';
		return $GLOBALS['__spam'];
	}
	function apply_filters( $tag, $value, ...$args ) {
		$GLOBALS['__order'][] = 'filter';
		return is_callable( $GLOBALS['filter'] ) ? call_user_func( $GLOBALS['filter'], $value, ...$args ) : $value;
	}
	class WP_User { public $ID; public function __construct( $id ) { $this->ID = $id; } }
	class WP_Error {
		public $code; public $msg;
		public function __construct( $code = '', $msg = '', $data = array() ) { $this->code = $code; $this->msg = $msg; }
		public function get_error_message() { return $this->msg; }
	}

	require dirname( __DIR__ ) . '/src/Security/LoginGate.php';

	use RaplsPasskey\Security\LoginGate;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$user = new WP_User( 5 );

	// Default: allowed (null).
	$GLOBALS['filter'] = null;
	check( 'allows by default (null)', null === LoginGate::check( $user, 'login' ) );

	// Filter returns false -> denied with a WP_Error.
	$GLOBALS['filter'] = function ( $v ) { return false; };
	$r = LoginGate::check( $user, 'login' );
	check( 'denies when filter returns false', $r instanceof WP_Error );

	// Filter returns a WP_Error -> passed through.
	$custom = new WP_Error( 'blocked', 'Account suspended' );
	$GLOBALS['filter'] = function ( $v ) use ( $custom ) { return $custom; };
	check( 'passes through a WP_Error from the filter', LoginGate::check( $user, 'login' ) === $custom );

	// Filter returns true -> allowed.
	$GLOBALS['filter'] = function ( $v ) { return true; };
	check( 'allows when filter returns true', null === LoginGate::check( $user, 'qr-channel' ) );

	// Context is passed to the filter.
	$seen = '';
	$GLOBALS['filter'] = function ( $v, $u, $ctx ) use ( &$seen ) { $seen = $ctx; return true; };
	LoginGate::check( $user, 'magic-link' );
	check( 'passes the context to the filter', 'magic-link' === $seen );

	// --- core's multisite check (R20-01 / R21-P3) ----------------------------
	// A user marked as spam on the network is refused even when a site filter
	// says yes, and the refusal is core's own error, not one of ours.
	$spam_error       = new WP_Error( 'spammer_account', 'Your account has been marked as a spammer.' );
	$GLOBALS['__spam'] = $spam_error;
	$GLOBALS['filter'] = function ( $v ) { return true; };
	$GLOBALS['__order'] = array();
	$r = LoginGate::check( $user, 'login' );
	check( 'a spam-marked account is refused despite a permissive filter', $r === $spam_error );
	check( "and core's check ran BEFORE any filter of ours", array( 'core' ) === $GLOBALS['__order'] );

	// Every entry point that sets the cookie directly goes through the one gate.
	foreach ( array( 'login', 'qr-channel', 'magic-link', 'recovery-code' ) as $ctx ) {
		check( "context '{$ctx}' is covered by the same check", LoginGate::check( $user, $ctx ) === $spam_error );
	}

	// Not spam: the filter decides as before.
	$GLOBALS['__spam'] = null;
	$GLOBALS['filter'] = function ( $v ) { return false; };
	check( 'an ordinary account still falls through to our filter', LoginGate::check( $user, 'login' ) instanceof WP_Error );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
