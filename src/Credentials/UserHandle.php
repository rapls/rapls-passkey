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
	 * wp_options prefix for the per-user handle claim row. The row's existence is
	 * the fact "this account has a handle"; its value is that handle. The unique
	 * index on option_name is what makes claiming it a decision the database
	 * takes, rather than one taken from a value that was read.
	 */
	public const CLAIM_PREFIX = 'rapls_pk_handle_';

	/**
	 * Get (creating on first use) the base64url handle for a user.
	 *
	 * Returns null when the account's handle cannot be established — never a
	 * second handle for an account that already has one. A caller must refuse the
	 * ceremony rather than continue: minting a different identity for the same
	 * account is the failure this whole class exists to prevent.
	 *
	 * @param int $user_id WordPress user id.
	 * @return string|null Base64url-encoded handle, or null when it cannot be established.
	 */
	public static function get( int $user_id ): ?string {
		if ( $user_id <= 0 ) {
			return null;
		}

		$handle = get_user_meta( $user_id, self::META, true );
		if ( is_string( $handle ) && '' !== $handle ) {
			// A stored handle is authoritative. Even a lagging reader is safe here:
			// a handle never changes once set, so the value a replica carries is the
			// value the writer holds.
			return $handle;
		}

		// Nothing visible — which is NOT the same as nothing stored. A reader served
		// by a replica that has not caught up returns exactly this, and deriving a
		// handle on that basis is how an account's credentials end up split across
		// two WebAuthn identities.
		//
		// So prove it with a WRITE. Every account that holds a handle also holds a
		// claim row, whose name is unique in the options table (the migration
		// back-fills one for every existing handle). Inserting that row succeeds
		// only if no handle was ever established for this account — a fact the
		// database decides, on the writer, with no read involved.
		$derived = self::derive( $user_id );
		$claimed = self::claim( $user_id, $derived );

		if ( true === $claimed ) {
			// Ours: this account provably had no handle. Mirror it into the meta so
			// the ordinary path finds it from now on (and so a salt change cannot
			// move it afterwards).
			update_user_meta( $user_id, self::META, $derived );
			return $derived;
		}

		// The row exists, or the database refused to answer. Either way an
		// established handle may be sitting where we cannot see it: refuse.
		return null;
	}

	/**
	 * Claim the one-and-only handle row for a user.
	 *
	 * A plain INSERT into a table whose `option_name` is unique. It either wrote
	 * the row — meaning this account had no handle and now has this one — or the
	 * database refused it. Nothing is read, so no replica can change the answer.
	 *
	 * @param int    $user_id User id.
	 * @param string $handle  The handle to claim.
	 * @return bool|null True when claimed here, false when a row already exists,
	 *                   null when the database could not be asked.
	 */
	private static function claim( int $user_id, string $handle ): ?bool {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return null;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$ok = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::CLAIM_PREFIX . $user_id,
				$handle
			)
		);

		if ( false !== $ok ) {
			return true;
		}
		// The insert failed. A duplicate name is the expected reason; a broken
		// connection is not, and the two are not distinguishable from here — both
		// mean "cannot establish this handle", which is what the caller acts on.
		return false;
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

		// Claim the account's one handle row FIRST. The account is brand new, so the
		// row cannot exist; if it somehow does, another handle is already
		// established for this id and adopting a second one is exactly what must not
		// happen. The claim is decided by the database, not by a value read back.
		if ( true !== self::claim( $user_id, $handle ) ) {
			return false;
		}

		// Then store it and judge by the write itself. Nothing is read back: a read
		// can be answered by a replica that has not applied the write yet, and
		// treating that as failure would undo a sign-up that in fact succeeded.
		// update_user_meta() returns false only on a real failure here, because this
		// account is brand new and so cannot already hold this exact value.
		return false !== update_user_meta( $user_id, self::META, $handle );
	}

	/**
	 * Raw (binary) handle bytes for use as the library `user.id`.
	 *
	 * @param int $user_id WordPress user id.
	 * @return string Raw bytes, or '' when the handle could not be established —
	 *                callers treat that as "refuse the ceremony".
	 */
	public static function raw( int $user_id ): string {
		$handle = self::get( $user_id );
		if ( null === $handle ) {
			return '';
		}
		try {
			return Base64UrlSafe::decode( $handle );
		} catch ( \Throwable $e ) {
			return '';
		}
	}
}
