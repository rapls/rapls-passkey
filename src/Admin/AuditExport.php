<?php
/**
 * Audit-log CSV export.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Audit\AuditLog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Streams the audit log as a UTF-8 CSV (with BOM, so Japanese opens cleanly in
 * Excel) from a nonce-protected admin-post action. Capped to a sane row count.
 */
final class AuditExport {

	/** admin-post action. */
	public const ACTION = 'rapls_pk_audit_export';

	/** Maximum rows exported. */
	private const LIMIT = 50000;

	/**
	 * Hook the export handler.
	 */
	public function register(): void {
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
	}

	/**
	 * Handle the download.
	 */
	public function handle(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'rapls-passkey' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::ACTION );

		$rows = AuditLog::recent( self::LIMIT );
		foreach ( $rows as &$row ) {
			$uid                = (int) ( $row['user_id'] ?? 0 );
			$user               = $uid > 0 ? get_userdata( $uid ) : null;
			$row['user_login']  = $user ? $user->user_login : ( $uid > 0 ? (string) $uid : '' );
		}
		unset( $row );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="rapls-passkey-audit-' . gmdate( 'Ymd-His' ) . '.csv"' );

		echo "\xEF\xBB\xBF"; // UTF-8 BOM.
		echo $this->to_csv( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	/**
	 * Build the CSV text for the given (enriched) audit rows.
	 *
	 * @param array<int,array<string,mixed>> $rows Audit rows with a user_login key.
	 * @return string
	 */
	public function to_csv( array $rows ): string {
		$handle = fopen( 'php://temp', 'r+' );

		// Explicit CSV control args (RFC 4180 quote-doubling, no backslash escape)
		// — also silences the PHP 8.4 fputcsv() $escape deprecation.
		fputcsv(
			$handle,
			array(
				__( 'Date/time (UTC)', 'rapls-passkey' ),
				__( 'Event', 'rapls-passkey' ),
				__( 'User ID', 'rapls-passkey' ),
				__( 'Username', 'rapls-passkey' ),
				__( 'Details', 'rapls-passkey' ),
				'IP',
			),
			',',
			'"',
			''
		);

		foreach ( $rows as $row ) {
			fputcsv(
				$handle,
				array(
					self::csv_safe( (string) ( $row['created_at'] ?? '' ) ),
					self::csv_safe( (string) ( $row['event'] ?? '' ) ),
					self::csv_safe( (string) ( $row['user_id'] ?? '' ) ),
					self::csv_safe( (string) ( $row['user_login'] ?? '' ) ),
					self::csv_safe( (string) ( $row['detail'] ?? '' ) ),
					self::csv_safe( (string) ( $row['ip'] ?? '' ) ),
				),
				',',
				'"',
				''
			);
		}

		rewind( $handle );
		$csv = (string) stream_get_contents( $handle );
		fclose( $handle );

		return $csv;
	}

	/**
	 * Neutralise spreadsheet formula injection: a cell beginning with =, +, -, @,
	 * tab or CR can be executed as a formula by Excel/Sheets, so prefix it with an
	 * apostrophe. Values here can include a user-chosen login, which is attacker
	 * influenced.
	 *
	 * @param string $value Cell value.
	 * @return string
	 */
	private static function csv_safe( string $value ): string {
		if ( '' !== $value && in_array( $value[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
			return "'" . $value;
		}
		return $value;
	}
}
