<?php
/**
 * At-rest encryption for stored secrets (API keys, webhook URLs).
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Symmetric encryption for the few third-party secrets the plugins must store
 * and reuse (so they are not kept as raw plaintext in wp_options). Output is
 * versioned, tagged ciphertext — "s1:" for libsodium (secretbox), "o1:" for the
 * OpenSSL AES-256-GCM fallback — round-trippable with the site's auth salt as
 * the key.
 *
 * Back-compatible: decrypt() returns any untagged value unchanged, so secrets
 * saved before encryption was added keep working until the next save re-stores
 * them encrypted. If the auth salt is rotated, old ciphertext can no longer be
 * read and the secret must be re-entered (it is recoverable from the provider).
 */
final class Secret {

	/** libsodium tag. */
	private const TAG_SODIUM = 's1:';

	/** OpenSSL AES-256-GCM tag. */
	private const TAG_OPENSSL = 'o1:';

	/**
	 * Whether a stored value is already tagged ciphertext produced by encrypt().
	 *
	 * Lets callers keep a value idempotent: a sanitiser that runs twice (e.g. the
	 * settings import, where update_option() re-triggers the registered
	 * sanitize_callback) must not encrypt an already-encrypted value again.
	 *
	 * @param string $value Stored value.
	 * @return bool
	 */
	public static function is_encrypted( string $value ): bool {
		return 0 === strncmp( $value, self::TAG_SODIUM, 3 ) || 0 === strncmp( $value, self::TAG_OPENSSL, 3 );
	}

	/**
	 * Encrypt a plaintext secret. Empty stays empty (so "unset" is preserved).
	 *
	 * @param string $plain Plaintext.
	 * @return string Tagged ciphertext, or '' for empty input.
	 */
	public static function encrypt( string $plain ): string {
		if ( '' === $plain ) {
			return '';
		}

		if ( self::has_sodium() ) {
			$key    = self::sodium_key();
			$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $plain, $nonce, $key );
			sodium_memzero( $key );
			return self::TAG_SODIUM . base64_encode( $nonce . $cipher );
		}

		$key    = self::openssl_key();
		$iv     = random_bytes( 12 );
		$tag    = '';
		$cipher = openssl_encrypt( $plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
		if ( false === $cipher ) {
			return ''; // Fail closed: never store the raw secret.
		}
		return self::TAG_OPENSSL . base64_encode( $iv . $tag . $cipher );
	}

	/**
	 * Decrypt a value produced by encrypt(). An untagged value is returned as-is
	 * (legacy plaintext); an undecryptable value returns ''.
	 *
	 * @param string $value Stored value.
	 * @return string Plaintext.
	 */
	public static function decrypt( string $value ): string {
		if ( '' === $value ) {
			return '';
		}

		if ( 0 === strncmp( $value, self::TAG_SODIUM, 3 ) ) {
			if ( ! self::has_sodium() ) {
				return '';
			}
			$raw = base64_decode( substr( $value, 3 ), true );
			$min = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
			if ( false === $raw || strlen( $raw ) <= $min ) {
				return '';
			}
			$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$key    = self::sodium_key();
			$plain  = sodium_crypto_secretbox_open( $cipher, $nonce, $key );
			sodium_memzero( $key );
			return false === $plain ? '' : $plain;
		}

		if ( 0 === strncmp( $value, self::TAG_OPENSSL, 3 ) ) {
			$raw = base64_decode( substr( $value, 3 ), true );
			if ( false === $raw || strlen( $raw ) <= 28 ) { // 12 IV + 16 tag.
				return '';
			}
			$iv     = substr( $raw, 0, 12 );
			$tag    = substr( $raw, 12, 16 );
			$cipher = substr( $raw, 28 );
			$plain  = openssl_decrypt( $cipher, 'aes-256-gcm', self::openssl_key(), OPENSSL_RAW_DATA, $iv, $tag );
			return false === $plain ? '' : $plain;
		}

		// Untagged: legacy plaintext.
		return $value;
	}

	/**
	 * Whether libsodium is usable.
	 *
	 * @return bool
	 */
	private static function has_sodium(): bool {
		return function_exists( 'sodium_crypto_secretbox' ) && defined( 'SODIUM_CRYPTO_SECRETBOX_KEYBYTES' );
	}

	/**
	 * 32-byte libsodium key derived from the site auth salt.
	 *
	 * @return string
	 */
	private static function sodium_key(): string {
		return sodium_crypto_generichash( wp_salt( 'auth' ), '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}

	/**
	 * 32-byte OpenSSL key derived from the site auth salt.
	 *
	 * @return string
	 */
	private static function openssl_key(): string {
		return hash( 'sha256', wp_salt( 'auth' ), true );
	}
}
