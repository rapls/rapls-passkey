<?php
/**
 * Stable per-user WebAuthn user handle.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

defined( 'ABSPATH' ) || exit;

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

	/** {@see claim()} wrote the row: this account had no handle until now. */
	private const CLAIM_WON = 'won';

	/** The row was already there: this account already has a handle. */
	private const CLAIM_TAKEN = 'taken';

	/** The database could not be asked, so nothing is known either way. */
	private const CLAIM_ERROR = 'error';

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

		$stored = get_user_meta( $user_id, self::META, true );
		if ( is_string( $stored ) && '' !== $stored ) {
			// The meta is a MIRROR of the claim row, not the record. It is checked
			// first only because it is the cheap path; what it says is accepted only
			// once the row agrees with it.
			$claim = self::claim( $user_id, $stored );

			if ( self::CLAIM_WON === $claim ) {
				// No row existed — an account from before the row, or one the
				// migration never reached — and this value is now recorded as its
				// identity. The mirror was right, and is now backed by the record.
				return $stored;
			}

			if ( self::CLAIM_TAKEN === $claim ) {
				// A row exists. Whether the mirror matches it is exactly the question:
				// a mirror that disagrees is how the same account hands out two
				// different handles depending on which request reads which copy. So
				// the row decides, and a disagreeing mirror is repaired to match it.
				$record = self::stored_claim( $user_id );
				if ( null === $record ) {
					return null; // The record exists but cannot be read: refuse.
				}
				if ( $record !== $stored ) {
					// Drop the cached mirror on BOTH sides of the write. Before,
					// because what we just read may have come from the cache; after,
					// because the write can be a no-op — the migration may already have
					// corrected the row, and update_user_meta() then changes nothing and
					// leaves the stale entry in place. The comparison is a byte
					// comparison ('AbCd' and 'abCd' are different handles), which is why
					// this repair, not the migration's SQL, is the guarantee.
					wp_cache_delete( $user_id, 'user_meta' );
					update_user_meta( $user_id, self::META, $record );
					wp_cache_delete( $user_id, 'user_meta' );
				}
				return $record;
			}

			// The row could not be established and we cannot tell whether it is
			// there. Handing the mirror out now would leave that gap open.
			return null;
		}

		// Nothing visible — which is NOT the same as nothing stored. A reader served
		// by a replica that has not caught up returns exactly this, and deriving a
		// handle on that basis is how an account's credentials end up split across
		// two WebAuthn identities.
		//
		// So prove it with a WRITE. Every account that holds a handle also holds a
		// claim row, whose name is unique in the options table. Inserting that row
		// succeeds only if no handle was ever established for this account — a fact
		// the database decides, on the writer, with no read involved.
		//
		// That guarantee rests on the migration having given every pre-existing
		// handle its row, so until the schema is confirmed current nothing is MINTED:
		// an account whose handle is invisible right now may simply be one the
		// back-fill has not reached. An account that already has its row is
		// unaffected — its handle is recovered from that row as usual.
		if ( ! Schema::is_current() ) {
			return self::stored_claim( $user_id );
		}

		$derived = self::derive( $user_id );
		$claim   = self::claim( $user_id, $derived );

		if ( self::CLAIM_WON === $claim ) {
			// Ours: this account provably had no handle. Mirror it into the meta so
			// the ordinary path finds it from now on (and so a salt change cannot move
			// it afterwards). The mirror is a convenience, not the record — the claim
			// row already holds this exact value, so a failed write here costs a slower
			// path next time, not the account's identity.
			update_user_meta( $user_id, self::META, $derived );
			return $derived;
		}

		if ( self::CLAIM_TAKEN === $claim ) {
			// A handle exists for this account and the meta could not show it to us.
			// The claim row carries that same value and is written exactly once, so
			// whatever it holds IS the handle: a replica either has the one true value
			// or has nothing, and can never offer a different one. This is what keeps
			// a failed meta write from leaving an account permanently unable to
			// register.
			$recovered = self::stored_claim( $user_id );
			if ( null !== $recovered ) {
				update_user_meta( $user_id, self::META, $recovered );
				return $recovered;
			}
		}

		// The row exists but cannot be read yet, or the database refused to answer.
		// Either way an established handle may be sitting where we cannot see it.
		return null;
	}

	/**
	 * The handle recorded in the account's claim row, or null when it cannot be
	 * read.
	 *
	 * @param int $user_id User id.
	 * @return string|null
	 */
	private static function stored_claim( int $user_id ): ?string {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return null;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$value = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
				self::CLAIM_PREFIX . $user_id
			)
		);

		return ( is_string( $value ) && '' !== $value ) ? $value : null;
	}

	/**
	 * Claim the one-and-only handle row for a user.
	 *
	 * A plain INSERT into a table whose `option_name` is unique. It either wrote
	 * the row — meaning this account had no handle and now has this one — or the
	 * database refused it. Nothing is read, so no replica can change the answer.
	 *
	 * The three outcomes are kept apart because they mean different things: a
	 * duplicate says the account already has a handle, which is the steady state on
	 * every later request, while any other failure says we do not know.
	 *
	 * @param int    $user_id User id.
	 * @param string $handle  The handle to claim.
	 * @return string One of CLAIM_WON, CLAIM_TAKEN, CLAIM_ERROR.
	 */
	private static function claim( int $user_id, string $handle ): string {
		global $wpdb;

		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) ) {
			return self::CLAIM_ERROR;
		}

		// A duplicate here is the NORMAL answer for an account that already has a
		// handle, so it must not be reported as a database error: left unsuppressed
		// it writes to debug.log, shows up in monitoring, can leak into a REST
		// response on a site with show_errors on, and buries real failures in noise.
		// Suppression is restored afterwards, and it does not hide anything from us —
		// the driver's error number and $wpdb->last_error are still set, which is
		// what the classification below reads.
		$suppressed = method_exists( $wpdb, 'suppress_errors' ) ? $wpdb->suppress_errors( true ) : null;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$ok = $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')",
				self::CLAIM_PREFIX . $user_id,
				$handle
			)
		);

		$result = ( false !== $ok )
			? self::CLAIM_WON
			: ( self::duplicate_key_error() ? self::CLAIM_TAKEN : self::CLAIM_ERROR );

		if ( null !== $suppressed ) {
			$wpdb->suppress_errors( $suppressed );
		}

		return $result;
	}

	/**
	 * Whether the last statement failed because the row was already there.
	 *
	 * The driver is asked first (errno 1062 is unambiguous) and only then the
	 * message, so a driver that exposes no error number still works. When neither
	 * can answer, the caller treats it as "do not know" — which refuses.
	 *
	 * @return bool
	 */
	private static function duplicate_key_error(): bool {
		global $wpdb;

		if ( isset( $wpdb->dbh ) && $wpdb->dbh instanceof \mysqli && 0 !== (int) $wpdb->dbh->errno ) {
			return 1062 === (int) $wpdb->dbh->errno;
		}
		$message = isset( $wpdb->last_error ) ? (string) $wpdb->last_error : '';
		return '' !== $message && ( false !== stripos( $message, 'duplicate entry' ) || false !== strpos( $message, '1062' ) );
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
		return self::b64url_encode(
			hash_hmac( 'sha256', 'rapls-passkey-user-handle|' . $user_id, wp_salt( 'auth' ), true )
		);
	}

	/**
	 * Base64url, unpadded — the encoding WebAuthn uses for binary identifiers.
	 *
	 * Done here rather than through the bundled library so this class, which every
	 * ceremony goes through, carries no dependency beyond WordPress itself.
	 *
	 * @param string $bytes Raw bytes.
	 * @return string
	 */
	private static function b64url_encode( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	/**
	 * Inverse of {@see b64url_encode()}. Returns '' for anything that is not a
	 * well-formed base64url string.
	 *
	 * @param string $value Base64url string, padded or not.
	 * @return string Raw bytes, or '' when the input is not valid.
	 */
	private static function b64url_decode( string $value ): string {
		if ( '' === $value || 1 !== preg_match( '#^[A-Za-z0-9\-_]+=*$#', $value ) ) {
			return '';
		}
		$padded  = strtr( $value, '-_', '+/' );
		$remain  = strlen( $padded ) % 4;
		if ( 0 !== $remain ) {
			$padded .= str_repeat( '=', 4 - $remain );
		}
		$decoded = base64_decode( $padded, true );
		return false === $decoded ? '' : $decoded;
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
		if ( self::CLAIM_WON !== self::claim( $user_id, $handle ) ) {
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
		return self::b64url_decode( $handle );
	}
}
