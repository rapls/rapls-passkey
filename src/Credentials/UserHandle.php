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

	/** wp_options prefix for the atomic first-creation lock (also holds the handle). */
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

		// First use. wp_usermeta has no unique constraint, so add_user_meta(unique)
		// is a SELECT-then-INSERT that two concurrent first registrations can both
		// pass — minting two different handles for one account. Serialise creation
		// with an ATOMIC insert into wp_options (option_name is unique-indexed): the
		// single winner mints the handle, and the row also carries it so a loser
		// recovers the winner's value without a read race.
		global $wpdb;
		$lock      = self::LOCK_PREFIX . $user_id;
		$candidate = Base64UrlSafe::encodeUnpadded( random_bytes( 32 ) );

		$suppress = $wpdb->suppress_errors( true );
		$won      = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$lock,
				$candidate
			)
		);
		$wpdb->suppress_errors( $suppress );

		if ( 1 === (int) $won ) {
			update_user_meta( $user_id, self::META, $candidate );
			return $candidate;
		}

		// A concurrent request won; the authoritative handle is in the lock row.
		$winner = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $lock )
		);
		if ( is_string( $winner ) && '' !== $winner ) {
			wp_cache_delete( $user_id, 'user_meta' );
			if ( '' === (string) get_user_meta( $user_id, self::META, true ) ) {
				update_user_meta( $user_id, self::META, $winner );
			}
			return $winner;
		}

		// Extreme fallback: re-read meta.
		wp_cache_delete( $user_id, 'user_meta' );
		$handle = get_user_meta( $user_id, self::META, true );
		return is_string( $handle ) && '' !== $handle ? $handle : $candidate;
	}

	/**
	 * Give a user the handle a ceremony has ALREADY used, and confirm it stuck.
	 *
	 * Passwordless sign-up mints the handle before the account exists, so the
	 * account has to adopt that exact value afterwards. Both places {@see get()}
	 * looks are written — the meta and the creation-lock row — so a later call can
	 * never mint a second, different handle for the same account and split that
	 * user's credentials across two WebAuthn identities. The write is read back:
	 * an unconfirmed handle returns false so the caller can undo the sign-up
	 * rather than store a credential that will not resolve.
	 *
	 * @param int    $user_id WordPress user id.
	 * @param string $handle  Base64url handle the ceremony used.
	 * @return bool True when the user demonstrably owns that handle.
	 */
	public static function adopt( int $user_id, string $handle ): bool {
		if ( $user_id <= 0 || '' === $handle ) {
			return false;
		}

		global $wpdb;
		$lock = self::LOCK_PREFIX . $user_id;

		// Claim the creation lock for this handle. If a row already exists it must
		// hold the same value, or this account has another handle already.
		$suppress = $wpdb->suppress_errors( true );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				$lock,
				$handle
			)
		);
		$wpdb->suppress_errors( $suppress );

		$claimed = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $lock )
		);
		if ( (string) $claimed !== $handle ) {
			return false;
		}

		update_user_meta( $user_id, self::META, $handle );
		wp_cache_delete( $user_id, 'user_meta' );
		return $handle === (string) get_user_meta( $user_id, self::META, true );
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
