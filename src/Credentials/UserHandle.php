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
	 * LEGACY wp_options prefix. Earlier versions minted a random handle under a
	 * first-creation lock row; handles are derived now, so nothing writes this any
	 * more. It remains only so uninstall and the personal-data eraser can clear
	 * rows those versions left behind.
	 */
	public const LOCK_PREFIX = 'rapls_pk_handle_lock_';

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

		// No stored handle: DERIVE one. It is a pure function of the user id and the
		// site's salt, so every request — concurrent first registrations, a retry
		// after a failed write, a read served by a replica that has not caught up —
		// arrives at the same value. That is what stops one account's credentials
		// being split across two WebAuthn identities, and it needs no lock, no
		// insert, and nothing read back. (An account that already carries a stored
		// handle keeps it: the meta above always wins.)
		return self::derive( $user_id );
	}

	/**
	 * The handle a user has when nothing is stored for them.
	 *
	 * HMAC over the user id with the site's auth salt: stable for this site,
	 * unguessable without the salt, and carrying nothing about the person. It is
	 * not written anywhere — being derivable IS the storage.
	 *
	 * @param int $user_id WordPress user id.
	 * @return string Base64url handle.
	 */
	private static function derive( int $user_id ): string {
		return Base64UrlSafe::encodeUnpadded(
			hash_hmac( 'sha256', 'rapls-passkey-user-handle|' . $user_id, wp_salt( 'auth' ), true )
		);
	}

	/**
	 * Give a user the handle a ceremony has ALREADY used, and confirm it stuck.
	 *
	 * Passwordless sign-up mints the handle before the account exists, so the
	 * account has to adopt that exact value afterwards. Storing it in the meta is
	 * enough: {@see get()} prefers the stored value over the derived one, so the
	 * account keeps the handle its credential was created against. A failed write
	 * returns false so the caller can undo the sign-up rather than store a
	 * credential that will not resolve.
	 *
	 * @param int    $user_id WordPress user id.
	 * @param string $handle  Base64url handle the ceremony used.
	 * @return bool True when the user demonstrably owns that handle.
	 */
	public static function adopt( int $user_id, string $handle ): bool {
		if ( $user_id <= 0 || '' === $handle ) {
			return false;
		}

		// Store it and judge by the write itself. Nothing is read back: a read can be
		// answered by a replica that has not applied the write yet, and treating that
		// as failure would undo a sign-up that in fact succeeded. update_user_meta()
		// returns false only on a real failure here, because this account is brand
		// new and so cannot already hold this exact value.
		return false !== update_user_meta( $user_id, self::META, $handle );
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
