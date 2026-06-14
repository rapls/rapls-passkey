<?php
/**
 * Secret: at-rest encryption round-trip, empty handling, legacy plaintext
 * passthrough, tamper rejection, and the s1: (sodium) / o1: (openssl) tags.
 *
 *   php tests/smoke-secret.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );

	function wp_salt( $scheme = 'auth' ) { return 'unit-test-salt-value-1234567890'; }

	require dirname( __DIR__ ) . '/src/Security/Secret.php';

	use RaplsPasskey\Security\Secret;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$plain = 'super-secret-key_6Lc-ABCDEF';

	// Round-trip.
	$enc = Secret::encrypt( $plain );
	check( 'ciphertext is tagged (s1:/o1:)', 0 === strncmp( $enc, 's1:', 3 ) || 0 === strncmp( $enc, 'o1:', 3 ) );
	check( 'ciphertext differs from plaintext', $enc !== $plain );
	check( 'decrypt restores the plaintext', $plain === Secret::decrypt( $enc ) );

	// Empty stays empty.
	check( 'encrypt empty is empty', '' === Secret::encrypt( '' ) );
	check( 'decrypt empty is empty', '' === Secret::decrypt( '' ) );

	// Legacy untagged plaintext passes through unchanged.
	check( 'legacy plaintext passthrough', 'legacy-value' === Secret::decrypt( 'legacy-value' ) );

	// Two encryptions of the same value differ (random nonce/IV).
	check( 'nonce randomises ciphertext', Secret::encrypt( $plain ) !== Secret::encrypt( $plain ) );

	// Tampered ciphertext fails to decrypt (returns '').
	$tampered = substr( $enc, 0, -3 ) . ( 'AAA' === substr( $enc, -3 ) ? 'BBB' : 'AAA' );
	check( 'tampered ciphertext does not decrypt to the secret', $plain !== Secret::decrypt( $tampered ) );

	// Unicode survives the round-trip.
	$uni = 'シークレット鍵🔐';
	check( 'unicode round-trips', $uni === Secret::decrypt( Secret::encrypt( $uni ) ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
