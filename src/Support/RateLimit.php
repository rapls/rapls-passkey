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
	 * Atomically increment the counter for $key within a $window-second fixed
	 * window and return the resulting count.
	 *
	 * @param string $key    Logical key (e.g. "2fa|<ip>"); hashed for the option name.
	 * @param int    $window Window length in seconds.
	 * @return int Count after this increment (0 is never returned for a hit).
	 */
	public static function incr( string $key, int $window ): int {
		global $wpdb;
		$name   = self::PREFIX . md5( $key );
		$window = max( 1, $window );
		$now    = time();
		$init   = '1:' . ( $now + $window );

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
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
		self::gc();
		return self::count( $key );
	}

	/**
	 * Current count for $key (0 once the window has passed). Reads the row directly
	 * so it reflects a concurrent incr() commit.
	 *
	 * @param string $key Logical key.
	 * @return int
	 */
	public static function count( string $key ): int {
		global $wpdb;
		$val = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::PREFIX . md5( $key ) )
		);
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
