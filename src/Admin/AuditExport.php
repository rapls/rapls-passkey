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
	 * NOT THE FIRST BYTE — THE FIRST THING THAT COUNTS (V83-02). Spreadsheets skip
	 * leading whitespace before deciding whether a cell is a formula, so a login
	 * of " =1+1", "\t=1+1", a non-breaking space or a byte-order mark followed by
	 * "=1+1" walked straight past a check that looked at $value[0] and got a
	 * space. The licence server's own CSV already stripped those before deciding;
	 * this is the same rule, in the plugin that ships to other people's sites.
	 *
	 * The PREFIX goes on the original value, not on the trimmed one: what is
	 * exported must still be what was recorded.
	 *
	 * @param string $value Cell value.
	 * @return string
	 */
	private static function csv_safe( string $value ): string {
		if ( '' === $value ) {
			return $value;
		}

		// A leading byte-order mark, ASCII control characters and space, and the
		// Unicode spaces a login can contain: NBSP (U+00A0), the U+2000–U+200A
		// range, line/paragraph separators, U+202F, U+205F, U+3000 and the
		// zero-width characters that are invisible in a cell but not to a parser.
		$probe = preg_replace(
			'/\A(?:\xEF\xBB\xBF|[\x00-\x20]|\xC2\xA0|\xE2\x80[\x80-\x8B\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF|\xEF\xBE\xA0)+/',
			'',
			$value
		);
		if ( null === $probe ) {
			// A malformed sequence is not a reason to export it unguarded.
			return "'" . $value;
		}

		if ( '' !== $probe && in_array( $probe[0], array( '=', '+', '-', '@' ), true ) ) {
			return "'" . $value;
		}
		// And a value that BEGINS with a tab or a carriage return is a cell break
		// wherever it appears, formula or not.
		if ( in_array( $value[0], array( "\t", "\r", "\n" ), true ) ) {
			return "'" . $value;
		}
		return $value;
	}
}
