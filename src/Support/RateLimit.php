<?php
/**
 * Atomic per-key fixed-window rate counter.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A per-IP / per-key attempt counter that increments atomically, so two
 * concurrent requests cannot both read the same value and each write count+1 (the
 * lost-update race a get_transient/set_transient read-modify-write has). The
 * counter is a single wp_options row whose value is "count:window_end"; a single
 * INSERT ... ON DUPLICATE KEY UPDATE either starts a fresh window or increments
 * in place. Shared by the free plugin and Pro (Pro references it under the free
 * plugin's unprefixed namespace).
 */
final class RateLimit {

	/** wp_options name prefix (kept in sync with the free plugin's uninstall sweep). */
	private const PREFIX = 'rapls_passkey_rl_';

	/** wp_options name prefix for quota reservation slots (see reserve()). */
	private const RESERVE_PREFIX = 'rapls_passkey_rs_';

	/**
	 * Sentinel count returned when the counter cannot be read or written. It is
	 * larger than any sane limit, so every caller's `>= max` / `> max` / `<= max`
	 * comparison treats a database failure as "over the limit" — i.e. the guarded
	 * action FAILS CLOSED (is blocked) rather than being silently allowed.
	 */
	public const OVERFLOW = 2147483647;

	/**
	 * Atomically increment the counter for $key within a $window-second fixed
	 * window and return the resulting count.
	 *
	 * On a database error the counter cannot be trusted, so this returns OVERFLOW
	 * (fail closed) instead of a low value that would let the caller through.
	 *
	 * @param string $key    Logical key (e.g. "2fa|<ip>"); hashed for the option name.
	 * @param int    $window Window length in seconds.
	 * @return int Count after this increment, or OVERFLOW on a DB error.
	 */
	public static function incr( string $key, int $window ): int {
		global $wpdb;
		$name   = self::PREFIX . md5( $key );
		$window = max( 1, $window );
		$now    = time();
		$init   = '1:' . ( $now + $window );

		$ok = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')
				 ON DUPLICATE KEY UPDATE option_value = IF(
					CAST(SUBSTRING_INDEX(option_value, ':', -1) AS UNSIGNED) < %d,
					%s,
					CONCAT(CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) + 1, ':', SUBSTRING_INDEX(option_value, ':', -1))
				 )",
				$name,
				$init,
				$now,
				$init
			)
		);
		// wpdb::query() returns false on a database error — fail closed.
		if ( false === $ok ) {
			return self::OVERFLOW;
		}
		self::gc();
		return self::count( $key );
	}

	/**
	 * Reserve one slot from a $cap-sized quota within a fixed $window-second window,
	 * by claiming a NUMBERED RESERVATION ROW whose uniqueness the database enforces.
	 * Concurrent requests can therefore never take the same slot, and only slots
	 * 1..$cap exist, so the quota is exact however many requests race. Pair with
	 * release() to hand the slot back if the work it was taken for fails.
	 *
	 * @param string $key    Logical key.
	 * @param int    $window Window length in seconds.
	 * @param int    $cap    Maximum reservations allowed within the window.
	 * @return string An opaque token identifying this reservation (pass it to
	 *                release()), or '' when the cap is reached or on a database
	 *                error (fail closed).
	 */
	public static function reserve( string $key, int $window, int $cap ): string {
		global $wpdb;
		if ( $cap <= 0 ) {
			return '';
		}
		$window = max( 1, $window );
		// A FIXED, clock-aligned window, so every concurrent request computes the same
		// window end without reading anything first.
		$end = ( intdiv( time(), $window ) + 1 ) * $window;

		$base  = self::RESERVE_PREFIX . md5( $key ) . '_' . $end . '_';
		$nonce = self::nonce();

		// Claim a numbered slot. The reservation is a row whose option_name embeds the
		// slot number, so the UNIQUE index on option_name lets exactly one request own
		// slot N — the cap is enforced by the DATABASE, not by counting. Success is
		// decided by READING THE ROW BACK and comparing our own token: it never reads
		// an affected-row count (which depends on the connection's
		// MYSQLI_CLIENT_FOUND_ROWS flag) and never needs a session-scoped lock (which
		// a transparent reconnect or a read/write-splitting db.php would silently
		// lose). It is also idempotent: if a reconnect replays our INSERT, the
		// duplicate is rejected but the read-back still shows our token, so we
		// correctly conclude we hold the slot.
		for ( $slot = 1; $slot <= $cap; $slot++ ) {
			$name  = $base . $slot;
			$value = $end . ':' . $nonce;

			$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $value )
			);

			$stored = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name )
			);
			if ( null === $stored && '' !== (string) $wpdb->last_error ) {
				return ''; // Cannot confirm ownership → no reservation (fail closed).
			}
			if ( (string) $stored === $value ) {
				self::gc();
				// The token identifies THIS reservation: slot + the nonce that proves
				// the row is ours, so release() can only ever remove our own row.
				return $end . '|' . $slot . '|' . $nonce;
			}
			// Somebody else owns this slot — try the next one.
		}

		self::gc();
		return ''; // Every slot in the window is taken: the cap is reached.
	}

	/**
	 * Hand a reservation back (e.g. the sign-up it was taken for failed).
	 *
	 * A token-scoped, idempotent DELETE of exactly the row this reservation created:
	 * it cannot disturb another request's slot, cannot double-release, and needs no
	 * serialisation with concurrent reserve() calls (unlike decrementing a shared
	 * counter, where a release could be lost or applied to a value another request
	 * had already read).
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
				self::RESERVE_PREFIX . md5( $key ) . '_' . (int) $end . '_' . (int) $slot,
				( (int) $end ) . ':' . $nonce
			)
		);
	}

	/**
	 * How many slots are currently reserved for $key in the window $window seconds
	 * long. Used for reporting and tests; admission itself never relies on a count.
	 *
	 * @param string $key    Logical key.
	 * @param int    $window Window length in seconds.
	 * @return int Reserved slots, or OVERFLOW on a database error (fail closed).
	 */
	public static function reserved_count( string $key, int $window ): int {
		global $wpdb;
		$window = max( 1, $window );
		$end    = ( intdiv( time(), $window ) + 1 ) * $window;
		$like   = $wpdb->esc_like( self::RESERVE_PREFIX . md5( $key ) . '_' . $end . '_' ) . '%';

		$count = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", $like )
		);
		if ( null === $count && '' !== (string) $wpdb->last_error ) {
			return self::OVERFLOW;
		}
		return (int) $count;
	}

	/**
	 * A random token identifying one reservation. Ownership of a slot is decided by
	 * comparing this value, so it MUST be unique per call — a repeated token would
	 * make a second request believe it owns a slot the first one holds.
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
	 * Current count for $key (0 once the window has passed). Reads the row directly
	 * so it reflects a concurrent incr() commit. Returns OVERFLOW on a DB read error
	 * so a caller that gates on the count fails closed.
	 *
	 * @param string $key Logical key.
	 * @return int
	 */
	public static function count( string $key ): int {
		global $wpdb;
		$val = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::PREFIX . md5( $key ) )
		);
		// get_var() returns null both for an absent row (count 0) and for a DB error;
		// last_error disambiguates. On a genuine error, fail closed.
		if ( '' !== (string) $wpdb->last_error ) {
			return self::OVERFLOW;
		}
		if ( ! is_string( $val ) || false === strpos( $val, ':' ) ) {
			return 0;
		}
		list( $count, $end ) = explode( ':', $val, 2 );
		return (int) $end > time() ? (int) $count : 0;
	}

	/**
	 * Clear the counter for $key (e.g. after a success).
	 *
	 * @param string $key Logical key.
	 */
	public static function clear( string $key ): void {
		global $wpdb;
		$wpdb->delete( $wpdb->options, array( 'option_name' => self::PREFIX . md5( $key ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Occasionally sweep counters whose window has passed (raw options do not
	 * auto-expire the way transients do).
	 */
	private static function gc(): void {
		if ( 0 !== wp_rand( 0, 49 ) ) {
			return;
		}
		global $wpdb;
		// Counters: "count:window_end" — the window end is the LAST segment.
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, ':', -1) AS UNSIGNED) < %d",
				$wpdb->esc_like( self::PREFIX ) . '%',
				time()
			)
		);
		// Reservation slots: "window_end:nonce" — the window end is the FIRST segment.
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) < %d",
				$wpdb->esc_like( self::RESERVE_PREFIX ) . '%',
				time()
			)
		);
	}
}
