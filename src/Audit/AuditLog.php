<?php
/**
 * Security event audit log.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Audit;

use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Records security-relevant events (registration, login, removal, recovery) to
 * a custom table for later review. No-ops when audit logging is disabled.
 */
final class AuditLog {

	/** Event constants. */
	public const REGISTERED = 'registered';
	public const LOGIN      = 'login';
	public const REMOVED    = 'removed';
	public const RECOVERY   = 'recovery';

	/**
	 * Record an event.
	 *
	 * @param string $event   One of the event constants.
	 * @param int    $user_id Subject user id (0 if unknown).
	 * @param string $detail  Short context string.
	 * @return void
	 */
	public static function record( string $event, int $user_id = 0, string $detail = '' ): void {
		if ( ! Settings::audit_enabled() ) {
			return;
		}

		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::audit_table(),
			array(
				'user_id'    => $user_id,
				'event'      => substr( $event, 0, 40 ),
				'detail'     => '' !== $detail ? substr( $detail, 0, 255 ) : null,
				'ip'         => self::client_ip(),
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%d', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Most recent events, newest first.
	 *
	 * @param int $limit Max rows.
	 * @return array<int,array<string,mixed>>
	 */
	public static function recent( int $limit = 50 ): array {
		global $wpdb;
		$table = Schema::audit_table();
		$rows  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit ),
			ARRAY_A
		);

		return $rows ? $rows : array();
	}

	/**
	 * Best-effort client IP for the log.
	 *
	 * @return string
	 */
	private static function client_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return substr( $ip, 0, 45 );
	}
}
