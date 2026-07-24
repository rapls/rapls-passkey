<?php
/**
 * Stable per-user WebAuthn user handle.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

use ParagonIE\ConstantTime\Base64UrlSafe;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Each WordPress user gets one opaque, stable user handle (the WebAuthn
 * `user.id`). It must stay constant across a user's credentials, so it is
 * generated once and cached in user meta. The handle is intentionally NOT the
 * WP user id, to avoid leaking enumerable identifiers to authenticators.
 */
final class UserHandle {

	/** User meta key holding the base64url handle. */
	public const META = 'rapls_passkey_user_handle';

	/**
	 * Get (creating on first use) the base64url handle for a user.
	 *
	 * @param int $user_id WordPress user id.
	 * @return string Base64url-encoded handle.
	 */
	public static function get( int $user_id ): string {
		$handle = get_user_meta( $user_id, self::META, true );
		if ( is_string( $handle ) && '' !== $handle ) {
			return $handle;
		}

		// First use. add_user_meta( …, true ) inserts only when no row exists yet,
		// so two concurrent first registrations cannot mint two different handles
		// for the same account (which would give one user two WebAuthn user.ids):
		// the loser's insert fails and it re-reads the winner's value.
		$candidate = Base64UrlSafe::encodeUnpadded( random_bytes( 32 ) );
		if ( add_user_meta( $user_id, self::META, $candidate, true ) ) {
			return $candidate;
		}

		wp_cache_delete( $user_id, 'user_meta' );
		$handle = get_user_meta( $user_id, self::META, true );
		return is_string( $handle ) && '' !== $handle ? $handle : $candidate;
	}

	/**
	 * Raw (binary) handle bytes for use as the library `user.id`.
	 *
	 * @param int $user_id WordPress user id.
	 * @return string Raw bytes.
	 */
	public static function raw( int $user_id ): string {
		return Base64UrlSafe::decode( self::get( $user_id ) );
	}
}
