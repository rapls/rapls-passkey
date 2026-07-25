<?php
/**
 * Advisory MySQL named lock (GET_LOCK / RELEASE_LOCK).
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A cross-connection advisory lock built on MySQL's GET_LOCK()/RELEASE_LOCK(),
 * used to serialise a short critical section (e.g. a per-user "count then insert"
 * or a "read quota then increment") so it is exact under concurrency.
 *
 * Why a named lock rather than a transaction + SELECT ... FOR UPDATE:
 *  - It is storage-engine independent. Row locks and transactions require InnoDB;
 *    a named lock works even if wp_options / a custom table is MyISAM.
 *  - It does not touch transaction state, so it cannot implicitly COMMIT another
 *    plugin's in-flight transaction on WordPress's shared $wpdb connection (as a
 *    bare START TRANSACTION would).
 *  - The success signal is an explicit scalar (1 / 0 / NULL), not an affected-row
 *    count, so it does not depend on the MYSQLI_CLIENT_FOUND_ROWS connection flag.
 *  - The lock is released automatically if the connection drops, so a fatal error
 *    mid-section cannot strand it.
 *
 * Callers MUST hold at most one of these locks at a time (never nest acquire()
 * calls before releasing): on MySQL < 5.7.5 a connection can hold only a single
 * named lock, so acquiring a second silently releases the first. The plugin never
 * nests its own locks; this is only a constraint on future call sites.
 */
final class DbLock {

	/** Default seconds to wait for the lock before giving up (then fail closed). */
	private const TIMEOUT = 5;

	/**
	 * Try to acquire the named lock, blocking up to $timeout seconds.
	 *
	 * @param string $name    Logical lock name (namespaced + hashed internally).
	 * @param int    $timeout Seconds to wait (>= 0). 0 means "try once, no wait".
	 * @return bool True only when the lock was actually granted. A timeout (0) or a
	 *              database error (NULL) both return false, so callers fail closed.
	 */
	public static function acquire( string $name, int $timeout = self::TIMEOUT ): bool {
		global $wpdb;
		$result = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', self::key( $name ), max( 0, $timeout ) )
		);
		// GET_LOCK() returns 1 (granted), 0 (timed out), or NULL (error/killed).
		return '1' === (string) $result;
	}

	/**
	 * Release the named lock. Safe to call even if the lock was auto-released
	 * (connection drop) or never held; the result is ignored.
	 *
	 * @param string $name Logical lock name (must match the acquire() name).
	 */
	public static function release( string $name ): void {
		global $wpdb;
		$wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::key( $name ) )
		);
	}

	/**
	 * Build the server-side lock name. MySQL named locks share one namespace across
	 * every database on the server instance, so the name is scoped to this install
	 * (DB name + table prefix) to keep separate WordPress sites on a shared MySQL
	 * server from colliding. Hashed to a fixed length well under MySQL's 64-char
	 * limit.
	 *
	 * @param string $name Logical lock name.
	 * @return string
	 */
	private static function key( string $name ): string {
		global $wpdb;
		$scope = ( defined( 'DB_NAME' ) ? DB_NAME : '' ) . '|' . $wpdb->prefix;
		return 'rpk_' . md5( $scope . '|' . $name );
	}
}
