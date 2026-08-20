<?php
/**
 * Short-lived state that a login ceremony depends on, kept where every PHP
 * worker can see it.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

defined( 'ABSPATH' ) || exit;

/**
 * A small key/value store for state that is written by one request and read by
 * the next: a WebAuthn challenge, a parked second-factor login, a cross-device
 * channel. Rows live in `wp_options`, written and read with `$wpdb` directly.
 *
 * WHY NOT TRANSIENTS. `set_transient()` stores in the object cache whenever a
 * persistent one is installed, and WordPress assumes such a cache is shared
 * between PHP processes. That assumption is not always true — APCu, a common
 * choice for `object-cache.php`, is per-worker — and when it does not hold, two
 * separate things break at once:
 *
 *  - The ceremony written by the worker that handled `login/options` is simply
 *    not there for the worker that handles `login/verify`, so a correct passkey
 *    is refused as an expired ceremony. Which worker answers is chance, so the
 *    same passkey works, then does not, then works again.
 *  - Worse, single use was enforced with `wp_cache_add()` on a lock key, which
 *    is atomic only across callers that share the cache. On a per-worker cache
 *    two requests can both be told they won, and the challenge is no longer
 *    single-use. A guarantee that quietly disappears because of how the host is
 *    configured is not a guarantee, so nothing here depends on the cache at all.
 *
 * These rows are therefore addressed with `$wpdb` and never through
 * `get_option()` / `update_option()` / the transient API, so no cache sits in
 * the path. `autoload = 'no'` keeps them out of the alloptions blob.
 *
 * Single use is decided by the DELETE: `option_name` is uniquely indexed, so of
 * any number of simultaneous callers exactly one deletes a row and is handed the
 * payload. The others are told there was nothing to take.
 */
final class OneTimeStore {

	/** Option-name prefix for every row this class owns. */
	private const PREFIX = 'rapls_pk_ot_';

	/** Keys are opaque ids we generate; anything else is a programming error. */
	private const KEY_PATTERN = '/^[A-Za-z0-9_-]{1,150}$/';

	/**
	 * Store a payload under a key for a limited time.
	 *
	 * @param string $key     Opaque id (base64url or hex).
	 * @param string $payload Anything the caller can serialise to a string.
	 * @param int    $ttl     Lifetime in seconds.
	 * @return bool True when the row is committed and can be read back.
	 */
	public static function put( string $key, string $payload, int $ttl ): bool {
		$db = self::db();
		if ( null === $db || ! self::valid( $key ) || $ttl <= 0 ) {
			return false;
		}

		$name  = self::PREFIX . $key;
		$value = ( time() + $ttl ) . '|' . $payload;

		// One statement, so a key written twice cannot leave the row missing in
		// between. A caller that reuses a key is replacing its own ceremony.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$done = $db->query(
			$db->prepare(
				"INSERT INTO {$db->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')
				 ON DUPLICATE KEY UPDATE option_value = VALUES(option_value)",
				$name,
				$value
			)
		);

		if ( false === $done ) {
			// The caller turns this into a refusal rather than sending someone into a
			// ceremony the server will not be able to finish.
			return false;
		}

		self::gc();
		return true;
	}

	/**
	 * Read a payload without consuming it.
	 *
	 * For state that is read several times before it is finished with — a parked
	 * login is shown a form, then answered — where consuming on the first read
	 * would throw it away.
	 *
	 * @param string $key Opaque id.
	 * @return string|null Payload, or null if absent or expired.
	 */
	public static function peek( string $key ): ?string {
		$row = self::row( $key );
		return null === $row ? null : $row['payload'];
	}

	/**
	 * Read a payload and consume it, so it can be used exactly once.
	 *
	 * The read is only to fetch the payload; the DELETE is what decides. Of two
	 * requests presenting the same key, one deletes the row and is answered, the
	 * other is told there is nothing there.
	 *
	 * @param string $key Opaque id.
	 * @return string|null Payload, or null if absent, expired, or claimed by
	 *                     another caller first.
	 */
	public static function take( string $key ): ?string {
		$row = self::row( $key );
		if ( null === $row ) {
			return null;
		}
		return self::claim( self::PREFIX . $key ) ? $row['payload'] : null;
	}

	/**
	 * Discard a key, whether or not it is there.
	 *
	 * @param string $key Opaque id.
	 */
	public static function forget( string $key ): void {
		$db = self::db();
		if ( null === $db || ! self::valid( $key ) ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$db->delete( $db->options, array( 'option_name' => self::PREFIX . $key ) );
	}

	/**
	 * Delete rows whose time has passed.
	 *
	 * Every path that reads a row also removes it, so this only clears ceremonies
	 * nobody came back for — a passkey prompt dismissed, a challenge screen
	 * abandoned. Called opportunistically by {@see gc()}; the cap bounds one run.
	 *
	 * @param int $limit Most rows to remove in one run.
	 * @return int Rows removed.
	 */
	public static function prune( int $limit = 1000 ): int {
		$db = self::db();
		if ( null === $db ) {
			return 0;
		}
		$limit = max( 1, min( 10000, $limit ) );

		// The expiry is the part of the value before the first '|'.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$removed = $db->query(
			$db->prepare(
				"DELETE FROM {$db->options}
				 WHERE option_name LIKE %s
				   AND CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) < %d
				 LIMIT %d",
				$db->esc_like( self::PREFIX ) . '%',
				time(),
				$limit
			)
		);

		return is_numeric( $removed ) ? (int) $removed : 0;
	}

	/**
	 * Remove every row this class owns (uninstall).
	 *
	 * @return int Rows removed.
	 */
	public static function drop_all(): int {
		$db = self::db();
		if ( null === $db ) {
			return 0;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$removed = $db->query(
			$db->prepare( "DELETE FROM {$db->options} WHERE option_name LIKE %s", $db->esc_like( self::PREFIX ) . '%' )
		);
		return is_numeric( $removed ) ? (int) $removed : 0;
	}

	// --- Internals -----------------------------------------------------------

	/**
	 * Occasionally sweep rows nobody came back for.
	 *
	 * These are plain option rows, so nothing expires them on our behalf. Doing it
	 * on a fraction of writes keeps the table tidy without a scheduled event and
	 * without paying for a DELETE on every ceremony — the same arrangement
	 * {@see RateLimit} uses for its slots.
	 */
	private static function gc(): void {
		if ( ! function_exists( 'wp_rand' ) || 0 !== wp_rand( 0, 49 ) ) {
			return;
		}
		self::prune();
	}

	/**
	 * Fetch and decode a row, treating an expired one as absent (and tidying it
	 * away, so an abandoned ceremony does not sit there until the next sweep).
	 *
	 * @param string $key Opaque id.
	 * @return array{payload:string}|null
	 */
	private static function row( string $key ): ?array {
		$db = self::db();
		if ( null === $db || ! self::valid( $key ) ) {
			return null;
		}

		$name = self::PREFIX . $key;
		// Read with $wpdb, not get_option(): the point of this class is that no
		// cache sits between the worker that wrote the row and the one reading it.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$value = $db->get_var( $db->prepare( "SELECT option_value FROM {$db->options} WHERE option_name = %s", $name ) );
		if ( ! is_string( $value ) ) {
			return null;
		}

		$split = strpos( $value, '|' );
		if ( false === $split ) {
			return null;
		}
		$expires = (int) substr( $value, 0, $split );
		if ( $expires <= time() ) {
			self::forget( $key );
			return null;
		}

		return array( 'payload' => substr( $value, $split + 1 ) );
	}

	/**
	 * Delete one row and report whether THIS caller is the one that removed it.
	 *
	 * @param string $name Full option name.
	 * @return bool
	 */
	private static function claim( string $name ): bool {
		$db = self::db();
		if ( null === $db ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$rows = $db->delete( $db->options, array( 'option_name' => $name ) );

		// A query error must not let a ceremony be replayed, so an unclear answer
		// counts as "somebody else took it". The cost is one failed sign-in that
		// the user can simply retry.
		return is_numeric( $rows ) && $rows > 0;
	}

	/**
	 * The database handle, or null where there is not a usable one (a minimal
	 * CLI context, or a test harness).
	 *
	 * @return \wpdb|null
	 */
	private static function db() {
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return null;
		}
		return $wpdb;
	}

	/**
	 * @param string $key Opaque id.
	 * @return bool
	 */
	private static function valid( string $key ): bool {
		return 1 === preg_match( self::KEY_PATTERN, $key );
	}
}
