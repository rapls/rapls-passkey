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

	// Point the Public Suffix List loader at a small representative snapshot so the
	// matching algorithm (normal / wildcard / exception / private rules) is
	// exercised here; production ships the full data/public_suffix_list.dat.
	$psl_dir = sys_get_temp_dir() . '/rapls_psl_' . getmypid();
	@mkdir( $psl_dir . '/data', 0777, true );
	file_put_contents(
		$psl_dir . '/data/public_suffix_list.dat',
		"// ===BEGIN ICANN DOMAINS===\ncom\nnet\norg\njp\nco.jp\nio\nuk\nco.uk\nar\ncom.ar\nid\nco.id\nck\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\nappspot.com\n// ===END PRIVATE DOMAINS===\n"
	);
	define( 'RAPLS_PASSKEY_DIR', $psl_dir . '/' );

	$GLOBALS['__home']    = 'https://site1.example.com';
	$GLOBALS['__site']    = 'https://site1.example.com';
	$GLOBALS['__rp_id']   = null;   // null => filter passes through
	$GLOBALS['__rp_name'] = null;

	function home_url( $path = '' ) { return $GLOBALS['__home']; }
	function site_url( $path = '' ) { return $GLOBALS['__site'] ?? $GLOBALS['__home']; }
	function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
	function get_bloginfo( $key ) { return 'Site One'; }
	function wp_specialchars_decode( $t, $q = null ) { return html_entity_decode( (string) $t, ENT_QUOTES ); }
	$GLOBALS['__related'] = array();
	function apply_filters( $tag, $value, ...$rest ) {
		if ( 'rapls_passkey_rp_id' === $tag && null !== $GLOBALS['__rp_id'] ) { return $GLOBALS['__rp_id']; }
		if ( 'rapls_passkey_rp_name' === $tag && null !== $GLOBALS['__rp_name'] ) { return $GLOBALS['__rp_name']; }
		if ( 'rapls_passkey/related_origins' === $tag ) { return $GLOBALS['__related']; }
		return $value;
	}

	require dirname( __DIR__ ) . '/src/WebAuthn/PublicSuffixList.php';
	require dirname( __DIR__ ) . '/src/WebAuthn/RelyingParty.php';

	use RaplsPasskey\WebAuthn\RelyingParty;
	use RaplsPasskey\WebAuthn\PublicSuffixList;

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

	// Public suffixes must never be accepted as an RP ID (WebAuthn forbids it).
	check( 'single-label TLD is rejected', ! RelyingParty::is_valid_rp_id( 'com', 'example.com' ) );
	check( 'multi-label public suffix is rejected', ! RelyingParty::is_valid_rp_id( 'co.jp', 'example.co.jp' ) );
	check( 'registrable domain under a public suffix is valid', RelyingParty::is_valid_rp_id( 'example.co.jp', 'shop.example.co.jp' ) );
	check( 'localhost is allowed for dev', RelyingParty::is_valid_rp_id( 'localhost', 'localhost' ) );

	// --- Full Public Suffix List matching (F-04) ---
	check( 'PSL: a bare TLD is a public suffix', PublicSuffixList::is_public_suffix( 'com' ) );
	check( 'PSL: co.jp is a public suffix', PublicSuffixList::is_public_suffix( 'co.jp' ) );
	check( 'PSL: a private-section suffix (github.io) is caught', PublicSuffixList::is_public_suffix( 'github.io' ) );
	check( 'PSL: appspot.com is caught', PublicSuffixList::is_public_suffix( 'appspot.com' ) );
	check( 'PSL: com.ar (denylist-missed) is caught', PublicSuffixList::is_public_suffix( 'com.ar' ) );
	check( 'PSL: co.id (denylist-missed) is caught', PublicSuffixList::is_public_suffix( 'co.id' ) );
	check( 'PSL: a registrable domain is not a public suffix', ! PublicSuffixList::is_public_suffix( 'example.com' ) );
	check( 'PSL: a registrable domain under github.io is fine', ! PublicSuffixList::is_public_suffix( 'myapp.github.io' ) );
	// Wildcard and exception rules.
	check( 'PSL: a wildcard suffix (foo.ck) is a public suffix', PublicSuffixList::is_public_suffix( 'foo.ck' ) );
	check( 'PSL: an exception (www.ck) is registrable, not a suffix', ! PublicSuffixList::is_public_suffix( 'www.ck' ) );

	// End-to-end RP ID validation using the list.
	check( 'RP ID github.io is rejected', ! RelyingParty::is_valid_rp_id( 'github.io', 'myapp.github.io' ) );
	check( 'RP ID myapp.github.io (registrable) is accepted', RelyingParty::is_valid_rp_id( 'myapp.github.io', 'sub.myapp.github.io' ) );
	check( 'RP ID com.ar is rejected', ! RelyingParty::is_valid_rp_id( 'com.ar', 'example.com.ar' ) );
	check( 'RP ID example.com.ar (registrable) is accepted', RelyingParty::is_valid_rp_id( 'example.com.ar', 'x.example.com.ar' ) );

	// --- allowed_origins(): unify REST gate and WebAuthn verifier ---
	$GLOBALS['__home'] = 'https://site1.example.com';
	$GLOBALS['__site'] = 'https://site1.example.com';
	$rp = RelyingParty::from_site();
	check( 'allowed_origins is just the one origin when home == site', $rp->allowed_origins() === array( 'https://site1.example.com' ) );

	// Split config: Site Address (home) and WordPress Address (site) differ.
	$GLOBALS['__site'] = 'https://login.example.com';
	$rp = RelyingParty::from_site();
	$origins = $rp->allowed_origins();
	check( 'allowed_origins includes the home origin', in_array( 'https://site1.example.com', $origins, true ) );
	check( 'allowed_origins includes the site (login) origin', in_array( 'https://login.example.com', $origins, true ) );
	check( 'allowed_origins has no duplicates', count( $origins ) === count( array_unique( $origins ) ) );
	$GLOBALS['__site'] = 'https://site1.example.com';

	// Default ports are omitted so origins match the browser Origin header.
	$GLOBALS['__home'] = 'https://site1.example.com:443';
	$GLOBALS['__site'] = 'https://site1.example.com:443';
	$rp = RelyingParty::from_site();
	check( 'default https port is dropped from the origin', $rp->origin() === 'https://site1.example.com' );
	$GLOBALS['__home'] = 'https://site1.example.com';
	$GLOBALS['__site'] = 'https://site1.example.com';

	// --- Related Origin Requests: cross-domain shared RP ID (F-40) ---
	// A member site (host shop.example) uses the shared RP ID "central.example",
	// authorized because its own origin is listed in the related origins.
	$GLOBALS['__related'] = array( 'https://shop.example', 'https://blog.example' );
	check( 'shared RP ID accepted for an authorized member host', RelyingParty::is_valid_rp_id( 'central.example', 'shop.example' ) );
	check( 'shared RP ID rejected for a non-member host', ! RelyingParty::is_valid_rp_id( 'central.example', 'stranger.example' ) );
	check( 'a public-suffix RP ID is still rejected even for a member', ! RelyingParty::is_valid_rp_id( 'com', 'shop.example' ) );

	// The ceremony verifier must accept assertions from the related origins.
	$GLOBALS['__home'] = 'https://shop.example';
	$GLOBALS['__site'] = 'https://shop.example';
	$rp = RelyingParty::from_site();
	$origins = $rp->allowed_origins();
	check( 'allowed_origins includes the member\'s own origin', in_array( 'https://shop.example', $origins, true ) );
	check( 'allowed_origins includes the other related origins', in_array( 'https://blog.example', $origins, true ) );
	$GLOBALS['__related'] = array();
	$GLOBALS['__home'] = 'https://site1.example.com';
	$GLOBALS['__site'] = 'https://site1.example.com';

	// A bogus rp_id filter value is rejected and falls back to the host.
	$GLOBALS['__rp_id'] = 'attacker.example';
	$rp = RelyingParty::from_site();
	check( 'bogus rp_id filter falls back to the host', $rp->id() === 'site1.example.com' );
	$GLOBALS['__rp_id'] = null;

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
