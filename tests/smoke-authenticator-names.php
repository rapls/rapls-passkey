<?php
/**
 * AuthenticatorNames: AAGUID extraction from a stored record, the bundled
 * provider-name lookup, zero/unknown handling, and the override filter.
 *
 *   php tests/smoke-authenticator-names.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );

	$GLOBALS['rapls_filter'] = null;
	function apply_filters( $hook, $value ) {
		if ( is_callable( $GLOBALS['rapls_filter'] ) ) {
			return call_user_func( $GLOBALS['rapls_filter'], $value, $hook );
		}
		return $value;
	}

	require dirname( __DIR__ ) . '/src/Credentials/AuthenticatorNames.php';

	use RaplsPasskey\Credentials\AuthenticatorNames;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	function record( $aaguid ) {
		return json_encode( array( 'aaguid' => $aaguid, 'counter' => 0 ) );
	}

	// --- AAGUID extraction -----------------------------------------------------
	check(
		'extracts a normal AAGUID (lowercased)',
		'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' === AuthenticatorNames::aaguid_from_record( record( 'EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4' ) )
	);
	check( 'zero AAGUID resolves to null', null === AuthenticatorNames::aaguid_from_record( record( AuthenticatorNames::ZERO_AAGUID ) ) );
	check( 'missing AAGUID resolves to null', null === AuthenticatorNames::aaguid_from_record( '{"counter":0}' ) );
	check( 'malformed JSON resolves to null', null === AuthenticatorNames::aaguid_from_record( 'not json' ) );

	// --- name lookup -----------------------------------------------------------
	check( 'known provider name (Google)', 'Google Password Manager' === AuthenticatorNames::name_for_record( record( 'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' ) ) );
	check( 'known provider name (1Password)', '1Password' === AuthenticatorNames::name_for_aaguid( 'bada5566-a7aa-401f-bd96-45619a55122d' ) );
	check( 'unknown AAGUID has no name', null === AuthenticatorNames::name_for_aaguid( '11111111-2222-3333-4444-555555555555' ) );

	// --- display fallback ------------------------------------------------------
	check( 'display returns provider when known', 'iCloud Keychain' === AuthenticatorNames::display( record( 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' ), 'Unknown' ) );
	check( 'display returns fallback when unknown', 'Unknown' === AuthenticatorNames::display( record( AuthenticatorNames::ZERO_AAGUID ), 'Unknown' ) );

	// --- override filter -------------------------------------------------------
	$GLOBALS['rapls_filter'] = function ( $map, $hook ) {
		if ( 'rapls_passkey/authenticator_names' === $hook ) {
			$map['11111111-2222-3333-4444-555555555555'] = 'Acme Authenticator';
		}
		return $map;
	};
	check( 'filter can add a custom name', 'Acme Authenticator' === AuthenticatorNames::name_for_aaguid( '11111111-2222-3333-4444-555555555555' ) );
	check( 'filter leaves bundled names intact', 'Bitwarden' === AuthenticatorNames::name_for_aaguid( 'd548826e-79b4-db40-a3d8-11116f7e8349' ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
