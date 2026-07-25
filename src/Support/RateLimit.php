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
	 * Atomically reserve one slot from a $cap-sized quota within a $window-second
	 * fixed window: increment ONLY while the count is still below $cap, in a single
	 * INSERT ... ON DUPLICATE KEY UPDATE. This is the "check-and-act" done as one
	 * atomic statement, so concurrent requests near the cap cannot all read the same
	 * under-limit value and each proceed. Pair with release() to hand a slot back if
	 * the work the reservation was for later fails.
	 *
	 * @param string $key    Logical key.
	 * @param int    $window Window length in seconds.
	 * @param int    $cap    Maximum reservations allowed within the window.
	 * @return int The reserved window's end (unix time) on success — pass it to
	 *             release() so a hand-back is scoped to THIS window — or 0 if the cap
	 *             is reached or on a DB error (fail closed).
	 */
	public static function reserve( string $key, int $window, int $cap ): int {
		global $wpdb;
		if ( $cap <= 0 ) {
			return 0;
		}
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
					IF(
						CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) < %d,
						CONCAT(CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) + 1, ':', SUBSTRING_INDEX(option_value, ':', -1)),
						option_value
					)
				 )",
				$name,
				$init,
				$now,
				$init,
				$cap
			)
		);
		// DB error → no reservation (fail closed).
		if ( false === $ok ) {
			return 0;
		}
		// Capture the reservation's row count BEFORE gc(): gc() runs a separate DELETE
		// that would otherwise overwrite $wpdb->rows_affected. rows_affected: 1 =
		// inserted (first this window), 2 = window reset or incremented, 0 = unchanged
		// because the cap is already reached (WordPress connects mysqli WITHOUT
		// CLIENT_FOUND_ROWS, so an UPDATE that changes nothing reports 0 rows).
		$reserved = (int) $wpdb->rows_affected > 0;
		self::gc();
		if ( ! $reserved ) {
			return 0;
		}
		// Read back the window end so release() can be scoped to exactly this window
		// (a stale request from an earlier, since-reset window must not decrement a
		// newer window's count).
		$val = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name )
		);
		if ( ! is_string( $val ) || false === strpos( $val, ':' ) ) {
			return 0;
		}
		return (int) substr( $val, strpos( $val, ':' ) + 1 );
	}

	/**
	 * Hand one reserved slot back to a specific window (e.g. the sign-up the
	 * reservation was taken for failed). Decrements ONLY when the row still belongs
	 * to $window_end — the value returned by the matching reserve() — so a late
	 * failure from an earlier window cannot subtract from a newer window's count.
	 * Never drops below zero.
	 *
	 * @param string $key        Logical key.
	 * @param int    $window_end The window end returned by reserve() (0 = no-op).
	 */
	public static function release( string $key, int $window_end ): void {
		if ( $window_end <= 0 ) {
			return;
		}
		global $wpdb;
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"UPDATE {$wpdb->options}
				 SET option_value = CONCAT(
					GREATEST( CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) - 1, 0 ),
					':',
					SUBSTRING_INDEX(option_value, ':', -1)
				 )
				 WHERE option_name = %s
				   AND CAST(SUBSTRING_INDEX(option_value, ':', -1) AS UNSIGNED) = %d",
				self::PREFIX . md5( $key ),
				$window_end
			)
		);
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
		$like = $wpdb->esc_like( self::PREFIX ) . '%';
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, ':', -1) AS UNSIGNED) < %d",
				$like,
				time()
			)
		);
	}
}
