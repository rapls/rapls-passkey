<?php
/**
 * Per-key attempt and quota limits enforced by a database uniqueness constraint.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Caps how often something may happen per key (per IP, per token, …) within a
 * fixed time window.
 *
 * Every limit here is enforced by the UNIQUE index on `option_name`, never by
 * comparing a number the code has read. One row is one consumed attempt: a
 * request claims slot N of the window by inserting a row whose name embeds N.
 * Because only slots 1..max exist, no number of simultaneous requests can
 * consume more than the cap.
 *
 * Claiming READS NOTHING. The insert either succeeded — and with a unique
 * option_name that means this request holds the slot — or it did not. This
 * matters on real deployments:
 *
 *  - A read/write-splitting `db.php` drop-in serves SELECTs from a replica,
 *    which may not yet have the row just written, or may still show a row that
 *    has since been released. Neither says anything true about what the writer
 *    accepted, so no decision here depends on a read.
 *  - `wpdb` transparently reconnects and replays a statement, so a failed insert
 *    may be our own earlier one that did land. Each failed attempt is therefore
 *    followed by a token-scoped DELETE — a write, so it reaches the writer —
 *    which removes our row if it exists and nothing otherwise. A request that
 *    ends up refused has provably left no row behind.
 *  - Nothing depends on affected-row counts (which vary with
 *    MYSQLI_CLIENT_FOUND_ROWS), on a session-scoped lock, or on a transactional
 *    storage engine.
 *
 * Windows are clock-aligned and half-open: a window ending at T covers
 * (T - length, T], and at exactly T the next window has already begun. Every
 * request computes the same boundary from its own clock without reading anything,
 * so there is no window on which two requests can disagree.
 *
 * Shared by the free plugin and Pro (Pro references it under the free plugin's
 * unprefixed namespace).
 */
final class RateLimit {

	/** wp_options name prefix for attempt slots (see admit()). */
	private const ATTEMPT_PREFIX = 'rapls_passkey_ra_';

	/** wp_options name prefix for quota reservation slots (see reserve()). */
	private const RESERVE_PREFIX = 'rapls_passkey_rs_';

	/**
	 * Consume one attempt from a $max-sized budget for $key in the current window.
	 *
	 * @param string $key    Logical key (e.g. "login|<ip>").
	 * @param int    $window Window length in seconds.
	 * @param int    $max    Attempts allowed within the window.
	 * @return int The claimed slot number — 1 for the first attempt of the window,
	 *             2 for the second, … — or 0 when the budget is exhausted or the
	 *             claim cannot be confirmed (fail closed). The number is the
	 *             caller's own position, taken from a row it provably owns, so a
	 *             caller that must act on the Nth attempt can compare against it.
	 */
	public static function admit( string $key, int $window, int $max ): int {
		return self::claim( self::ATTEMPT_PREFIX, $key, $window, $max )['slot'];
	}

	/**
	 * Reserve one slot from a $max-sized quota for $key in the current window.
	 *
	 * Unlike admit(), a reservation can be handed back with release() when the work
	 * it was taken for does not complete.
	 *
	 * @param string $key    Logical key.
	 * @param int    $window Window length in seconds.
	 * @param int    $max    Reservations allowed within the window.
	 * @return string An opaque token identifying this reservation (pass it to
	 *                release()), or '' when the quota is full or the claim cannot
	 *                be confirmed (fail closed).
	 */
	public static function reserve( string $key, int $window, int $max ): string {
		return self::claim( self::RESERVE_PREFIX, $key, $window, $max )['token'];
	}

	/**
	 * Hand a reservation back (e.g. the sign-up it was taken for failed).
	 *
	 * A token-scoped, idempotent DELETE of exactly the row this reservation
	 * created: it cannot disturb another request's slot, a double release is a
	 * no-op, and it needs no serialisation with a concurrent reserve().
	 *
	 * @param string $key   Logical key (the one passed to reserve()).
	 * @param string $token The token returned by reserve() ('' = no-op).
	 */
	public static function release( string $key, string $token ): void {
		if ( '' === $token ) {
			return;
		}
		$parts = explode( '|', $token );
		if ( 3 !== count( $parts ) ) {
			return;
		}
		list( $end, $slot, $nonce ) = $parts;

		global $wpdb;
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s",
				self::slot_name( self::RESERVE_PREFIX, $key, (int) $end, (int) $slot ),
				( (int) $end ) . ':' . $nonce
			)
		);
	}

	/**
	 * Give $key its full budget back — e.g. a successful login should not leave
	 * the user's failed attempts counting against them. Removes this key's slots
	 * in every window, both attempt and reservation rows.
	 *
	 * @param string $key Logical key.
	 */
	public static function clear( string $key ): void {
		global $wpdb;
		foreach ( array( self::ATTEMPT_PREFIX, self::RESERVE_PREFIX ) as $prefix ) {
			$like = $wpdb->esc_like( $prefix . md5( $key ) . '_' ) . '%';
			$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $like )
			);
		}
	}

	/**
	 * How many slots $key holds in the current window.
	 *
	 * ADVISORY ONLY. This is a read, so a replica can answer with a stale value;
	 * never decide whether to allow something from it — call admit() or reserve(),
	 * which are enforced by the database. It is here for reporting, for tests, and
	 * for cheap "already full, skip the work" hints where being wrong merely costs
	 * one more call to the authoritative path.
	 *
	 * @param string $key    Logical key.
	 * @param int    $window Window length in seconds.
	 * @param bool   $quota  True to count reservations instead of attempts.
	 * @return int Slots held, or 0 when the count cannot be read.
	 */
	public static function used( string $key, int $window, bool $quota = false ): int {
		global $wpdb;
		$prefix = $quota ? self::RESERVE_PREFIX : self::ATTEMPT_PREFIX;
		$like   = $wpdb->esc_like( $prefix . md5( $key ) . '_' . self::window_end( $window ) . '_' ) . '%';

		$count = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", $like )
		);
		return null === $count ? 0 : (int) $count;
	}

	/**
	 * Claim the lowest free numbered slot for $key in the current window.
	 *
	 * The claim is a plain INSERT of a row whose name embeds the slot number. The
	 * UNIQUE index on option_name means at most one request can hold slot N.
	 * Success is decided by whether the INSERT itself was accepted. Nothing is
	 * read back: not the row, not an affected-row count, not a total.
	 *
	 * @param string $prefix Option-name prefix (attempt or reservation).
	 * @param string $key    Logical key.
	 * @param int    $window Window length in seconds.
	 * @param int    $max    Slots that exist in the window.
	 * @return array{slot:int,token:string} The claimed slot and its token, or
	 *                                      slot 0 / token '' when nothing was claimed.
	 */
	private static function claim( string $prefix, string $key, int $window, int $max ): array {
		global $wpdb;
		$none = array(
			'slot'  => 0,
			'token' => '',
		);
		if ( $max <= 0 ) {
			return $none;
		}

		$window = max( 1, $window );
		$end    = self::window_end( $window );
		$nonce  = self::nonce();
		$value  = $end . ':' . $nonce;

		for ( $slot = 1; $slot <= $max; $slot++ ) {
			$name = self::slot_name( $prefix, $key, $end, $slot );

			// The INSERT itself decides. It either wrote the row — which, with a
			// UNIQUE option_name, means this request and no other holds the slot —
			// or the database refused it. Nothing is read: a reader can be a replica,
			// and a replica may be missing the row we just wrote OR still showing a
			// row somebody has since released, and neither tells us anything true
			// about what the writer accepted. Success is also not read from an
			// affected-row count, only from "did the statement error", which no
			// connection flag can change.
			// A duplicate is the NORMAL answer here (somebody else holds this slot),
			// so it must not be reported as a database error: unsuppressed it fills
			// debug.log and monitoring with expected failures and buries real ones.
			// Suppression does not hide anything from us — last_error is still set.
			$suppressed = method_exists( $wpdb, 'suppress_errors' ) ? $wpdb->suppress_errors( true ) : null;
			$ok         = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $value )
			);
			if ( null !== $suppressed ) {
				$wpdb->suppress_errors( $suppressed );
			}
			if ( false !== $ok ) {
				self::gc();
				return array(
					'slot'  => $slot,
					'token' => $end . '|' . $slot . '|' . $nonce,
				);
			}

			// The insert did not go through. Usually that is a duplicate — somebody
			// else holds this slot — and nothing of ours was written. But it can also
			// be our OWN row: WordPress transparently reconnects and replays a
			// statement, so the first execution may have landed before the failure we
			// see. A token-scoped DELETE settles it: it is a write, so it reaches the
			// writer, and it removes our row if it is there and nothing otherwise.
			// After it, this request provably owns no row on this slot, so moving to
			// the next one cannot leave anything behind.
			$cleaned = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s", $name, $value )
			);
			if ( false === $cleaned ) {
				// Cannot confirm we left nothing behind — stop rather than write more.
				return $none;
			}
		}

		self::gc();
		return $none; // Every slot in the window is taken.
	}

	/**
	 * End of the window containing "now", as a clock-aligned unix time. Windows are
	 * half-open — a window ending at T covers (T - $window, T] and at exactly T the
	 * next one has begun — so a request's own clock is enough to place it, and the
	 * boundary second cannot be read as "no window" by one caller and "the old
	 * window" by another.
	 *
	 * @param int $window Window length in seconds.
	 * @return int
	 */
	private static function window_end( int $window ): int {
		$window = max( 1, $window );
		return ( intdiv( time(), $window ) + 1 ) * $window;
	}

	/**
	 * Option name holding one slot.
	 *
	 * @param string $prefix Option-name prefix.
	 * @param string $key    Logical key.
	 * @param int    $end    Window end.
	 * @param int    $slot   Slot number.
	 * @return string
	 */
	private static function slot_name( string $prefix, string $key, int $end, int $slot ): string {
		return $prefix . md5( $key ) . '_' . $end . '_' . $slot;
	}

	/**
	 * A random token identifying one claim. Ownership of a slot is decided by
	 * comparing this value, so it MUST be unique per call — a repeated token would
	 * let a second request believe it owns a slot the first one holds.
	 *
	 * @return string
	 */
	private static function nonce(): string {
		try {
			return bin2hex( random_bytes( 12 ) );
		} catch ( \Throwable $e ) {
			// No CSPRNG (should not happen on a supported PHP): uniqid() is still
			// unique per process/time, which is all this needs.
			return str_replace( '.', '', uniqid( '', true ) );
		}
	}

	/**
	 * Occasionally sweep slots whose window has passed (raw options do not expire
	 * the way transients do). The stored value starts with the window end, so one
	 * comparison covers every key.
	 */
	private static function gc(): void {
		if ( 0 !== wp_rand( 0, 49 ) ) {
			return;
		}
		global $wpdb;
		foreach ( array( self::ATTEMPT_PREFIX, self::RESERVE_PREFIX ) as $prefix ) {
			$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) <= %d",
					$wpdb->esc_like( $prefix ) . '%',
					time()
				)
			);
		}
	}
}
