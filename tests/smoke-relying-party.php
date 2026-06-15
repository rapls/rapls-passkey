<?php
/**
 * RelyingParty: derivation from the site URL and the rp_id / rp_name filters
 * (used for network-wide passkeys on multisite).
 *
 *   php tests/smoke-relying-party.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

// Stub the one library class RelyingParty imports.
namespace Webauthn { class PublicKeyCredentialRpEntity { public static function create( $n, $i ) { return array( $n, $i ); } } }

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );

	$GLOBALS['__home']    = 'https://site1.example.com';
	$GLOBALS['__rp_id']   = null;   // null => filter passes through
	$GLOBALS['__rp_name'] = null;

	function home_url( $path = '' ) { return $GLOBALS['__home']; }
	function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
	function get_bloginfo( $key ) { return 'Site One'; }
	function wp_specialchars_decode( $t, $q = null ) { return html_entity_decode( (string) $t, ENT_QUOTES ); }
	function apply_filters( $tag, $value, ...$rest ) {
		if ( 'rapls_passkey_rp_id' === $tag && null !== $GLOBALS['__rp_id'] ) { return $GLOBALS['__rp_id']; }
		if ( 'rapls_passkey_rp_name' === $tag && null !== $GLOBALS['__rp_name'] ) { return $GLOBALS['__rp_name']; }
		return $value;
	}

	require dirname( __DIR__ ) . '/src/WebAuthn/RelyingParty.php';

	use RaplsPasskey\WebAuthn\RelyingParty;

	$pass = 0;
	$failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	// Default derivation.
	$rp = RelyingParty::from_site();
	check( 'id defaults to the host', $rp->id() === 'site1.example.com' );
	check( 'origin is scheme://host', $rp->origin() === 'https://site1.example.com' );
	check( 'name from bloginfo', $rp->name() === 'Site One' );

	// rp_id filter => network-wide parent domain.
	$GLOBALS['__rp_id'] = 'example.com';
	$rp = RelyingParty::from_site();
	check( 'rp_id filter overrides the host', $rp->id() === 'example.com' );
	check( 'origin is unchanged by rp_id filter', $rp->origin() === 'https://site1.example.com' );

	// Empty filter result falls back to host.
	$GLOBALS['__rp_id'] = '';
	$rp = RelyingParty::from_site();
	check( 'empty rp_id falls back to host', $rp->id() === 'site1.example.com' );

	// rp_name filter.
	$GLOBALS['__rp_id']   = null;
	$GLOBALS['__rp_name'] = 'My Network';
	$rp = RelyingParty::from_site();
	check( 'rp_name filter overrides the name', $rp->name() === 'My Network' );

	// --- RP ID validity helper ---
	check( 'exact host is valid', RelyingParty::is_valid_rp_id( 'site1.example.com', 'site1.example.com' ) );
	check( 'registrable parent is valid', RelyingParty::is_valid_rp_id( 'example.com', 'site1.example.com' ) );
	check( 'unrelated domain is invalid', ! RelyingParty::is_valid_rp_id( 'evil.com', 'site1.example.com' ) );
	check( 'suffix without a dot boundary is invalid', ! RelyingParty::is_valid_rp_id( 'ample.com', 'example.com' ) );
	check( 'empty RP ID is invalid', ! RelyingParty::is_valid_rp_id( '', 'example.com' ) );

	// A bogus rp_id filter value is rejected and falls back to the host.
	$GLOBALS['__rp_id'] = 'attacker.example';
	$rp = RelyingParty::from_site();
	check( 'bogus rp_id filter falls back to the host', $rp->id() === 'site1.example.com' );
	$GLOBALS['__rp_id'] = null;

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
