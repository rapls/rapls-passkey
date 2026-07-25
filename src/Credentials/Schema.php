<?php
/**
 * Database schema for stored passkey credentials.
 *
 * Owns the single custom table that holds each user's registered WebAuthn
 * credentials (public key, credential id, sign counter, etc.) and the dbDelta
 * migration that creates / upgrades it. A stored schema version lets us run the
 * migration only when the definition changes.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Creates and versions the plugin's credential table.
 */
final class Schema {

	/** Option key holding the installed schema version. */
	private const VERSION_OPTION = 'rapls_passkey_schema_version';

	/**
	 * Current schema version. Bump when a table definition changes.
	 */
	private const VERSION = '5';

	/**
	 * Option flag recording that the UNIQUE (user_id, slot_no) index exists. The
	 * per-user passkey cap is enforced BY that index, so when it is absent the cap
	 * cannot be guaranteed and registration fails closed (see Rest\Endpoints).
	 */
	public const SLOT_INDEX_OPTION = 'rapls_passkey_slot_index';

	/** Name of the unique index that enforces the per-user cap. */
	private const SLOT_INDEX = 'user_slot';

	/**
	 * Fully-qualified credentials table name.
	 *
	 * @return string
	 */
	public static function credentials_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'rapls_passkey_credentials';
	}

	/**
	 * Fully-qualified audit log table name.
	 *
	 * @return string
	 */
	public static function audit_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'rapls_passkey_audit';
	}

	/**
	 * Run the migration if the stored version is behind the current one.
	 *
	 * Safe to call on every request (it short-circuits when up to date); invoked
	 * from activation and from Plugin::boot() on admin_init.
	 */
	public static function maybe_upgrade(): void {
		if ( get_option( self::VERSION_OPTION ) === self::VERSION ) {
			return;
		}
		self::install();
		update_option( self::VERSION_OPTION, self::VERSION, false );
	}

	/**
	 * Create or update the table via dbDelta.
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$credentials     = self::credentials_table();
		$audit           = self::audit_table();

		/*
		 * dbDelta is whitespace- and format-sensitive: two spaces after KEY,
		 * lowercase field types, one definition per line. Do not reformat
		 * casually — it changes whether dbDelta detects a diff.
		 *
		 * credential_id stores the base64url-encoded WebAuthn credential id and
		 * carries a UNIQUE index so the same authenticator cannot be registered
		 * twice. It is varchar(512): a non-resident authenticator that wraps state
		 * into the credential id can produce ids whose base64url form exceeds 255
		 * characters, which the old width would have silently truncated (breaking
		 * later look-ups). credential_data holds the full serialised CredentialRecord
		 * (public key, transports, aaguid, trust path, counter, …) as JSON — the
		 * source of truth round-tripped through web-auth's serializer. sign_count
		 * is denormalised for display and updated after every assertion.
		 *
		 * slot_no numbers each user's passkeys 1, 2, 3, … and carries a UNIQUE
		 * (user_id, slot_no) index (added separately below, after back-filling).
		 * That index — not an application lock — is what makes the per-user cap
		 * exact: a registration claims a specific slot number, so two concurrent
		 * registrations for the same user cannot both take slot N, and with the cap
		 * set to N only slots 1..N are ever offered. Being a database constraint it
		 * holds across a dropped-and-reopened connection, a read/write-splitting
		 * db.php drop-in, and any storage engine, none of which a session-scoped
		 * lock survives.
		 */
		$sql = "CREATE TABLE {$credentials} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL,
			slot_no bigint(20) unsigned DEFAULT NULL,
			credential_id varchar(512) NOT NULL,
			credential_data longtext NOT NULL,
			sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
			label varchar(191) DEFAULT NULL,
			active tinyint(1) NOT NULL DEFAULT 1,
			created_at datetime NOT NULL,
			last_used_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) {$charset_collate};";

		dbDelta( $sql );

		// The unique slot index is added AFTER dbDelta, not as part of the CREATE
		// TABLE: on an existing install every row starts with slot_no NULL, and the
		// index can only be created once those rows carry distinct numbers.
		self::backfill_slots();
		self::ensure_slot_index();

		/*
		 * Audit log: one row per security-relevant event (registration, login,
		 * removal, recovery). user_id is 0 for events without a known user.
		 */
		$audit_sql = "CREATE TABLE {$audit} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			event varchar(40) NOT NULL,
			detail varchar(255) DEFAULT NULL,
			ip varchar(45) DEFAULT NULL,
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY user_id (user_id),
			KEY event (event),
			KEY created_at (created_at)
		) {$charset_collate};";

		dbDelta( $audit_sql );
	}

	/**
	 * Give every pre-existing row a slot number (1, 2, 3, … per user, oldest
	 * first), so the UNIQUE (user_id, slot_no) index can be created and so the old
	 * rows occupy slots against the cap. Rows written by this version already carry
	 * a number, so this only ever touches the upgrade backlog and is a no-op
	 * afterwards.
	 */
	private static function backfill_slots(): void {
		global $wpdb;
		$table = self::credentials_table();

		// Batched so a site with a large table does not build one huge statement.
		do {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				"SELECT id, user_id FROM {$table} WHERE slot_no IS NULL ORDER BY user_id ASC, id ASC LIMIT 500",
				ARRAY_A
			);
			if ( ! $rows ) {
				return;
			}
			foreach ( $rows as $row ) {
				$user_id = (int) $row['user_id'];
				// The next free number for this user: one past their highest slot.
				$next = 1 + (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
					$wpdb->prepare( "SELECT COALESCE(MAX(slot_no), 0) FROM {$table} WHERE user_id = %d", $user_id )
				);
				$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
					$wpdb->prepare( "UPDATE {$table} SET slot_no = %d WHERE id = %d AND slot_no IS NULL", $next, (int) $row['id'] )
				);
			}
		} while ( count( $rows ) === 500 );
	}

	/**
	 * Create the UNIQUE (user_id, slot_no) index if it is not already there, and
	 * record whether it exists. The per-user cap is enforced by this index, so
	 * Rest\Endpoints refuses to register (rather than registering unprotected) when
	 * a cap is configured and the flag says the index is missing.
	 */
	private static function ensure_slot_index(): void {
		global $wpdb;
		$table = self::credentials_table();

		if ( ! self::slot_index_exists() ) {
			$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				"ALTER TABLE {$table} ADD UNIQUE KEY " . self::SLOT_INDEX . ' (user_id, slot_no)'
			);
		}

		update_option( self::SLOT_INDEX_OPTION, self::slot_index_exists() ? '1' : '0', false );
	}

	/**
	 * Whether the unique slot index is present on the credentials table.
	 *
	 * @return bool
	 */
	private static function slot_index_exists(): bool {
		global $wpdb;
		$table = self::credentials_table();
		$found = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( "SHOW INDEX FROM {$table} WHERE Key_name = %s", self::SLOT_INDEX )
		);
		return null !== $found;
	}

	/**
	 * Whether the database can enforce the per-user cap (the unique slot index is
	 * in place). Cheap: reads the flag recorded by the migration.
	 *
	 * @return bool
	 */
	public static function cap_enforceable(): bool {
		return '1' === (string) get_option( self::SLOT_INDEX_OPTION, '0' );
	}

	/**
	 * Drop the table and the version marker. Used by uninstall.
	 */
	public static function drop(): void {
		global $wpdb;

		// Table names are built from $wpdb->prefix, not user input.
		foreach ( array( self::credentials_table(), self::audit_table() ) as $table ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}
		delete_option( self::VERSION_OPTION );
		delete_option( self::SLOT_INDEX_OPTION );
	}
}
