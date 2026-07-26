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
	 * Per-request memo for {@see cap_enforceable()}. Null until asked.
	 *
	 * @var bool|null
	 */
	private static $cap_enforceable = null;

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
		// Record the new version ONLY when the migration completed — including the
		// slot back-fill and the unique index that enforces the per-user cap. If any
		// step failed (a locked table, a permissions problem, a half-applied
		// change), leaving the stored version behind means the next admin request
		// retries it instead of treating a partial schema as finished.
		if ( self::install() ) {
			update_option( self::VERSION_OPTION, self::VERSION, false );
		}
	}

	/**
	 * Create or update the table via dbDelta.
	 *
	 * @return bool True when the schema is fully in place (tables, slot numbers and
	 *              the unique slot index), false when a step did not complete.
	 */
	public static function install(): bool {
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
		$ok = self::backfill_slots();
		$ok = self::ensure_slot_index() && $ok;

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

		return $ok;
	}

	/**
	 * Give every pre-existing row a slot number (1, 2, 3, … per user, oldest
	 * first), so the UNIQUE (user_id, slot_no) index can be created and so the old
	 * rows occupy slots against the cap. Rows written by this version already carry
	 * a number, so this only ever touches the upgrade backlog and is a no-op
	 * afterwards.
	 *
	 * @return bool True when no row is left without a slot number.
	 */
	private static function backfill_slots(): bool {
		global $wpdb;
		$table = self::credentials_table();

		// Batched so a site with a large table does not build one huge statement.
		do {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				"SELECT id, user_id FROM {$table} WHERE slot_no IS NULL ORDER BY user_id ASC, id ASC LIMIT 500",
				ARRAY_A
			);
			if ( ! is_array( $rows ) || '' !== (string) $wpdb->last_error ) {
				return false; // Could not even read the backlog.
			}
			if ( ! $rows ) {
				return true;
			}
			foreach ( $rows as $row ) {
				$user_id = (int) $row['user_id'];
				// The next free number for this user: one past their highest slot.
				$next = 1 + (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
					$wpdb->prepare( "SELECT COALESCE(MAX(slot_no), 0) FROM {$table} WHERE user_id = %d", $user_id )
				);
				$updated = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
					$wpdb->prepare( "UPDATE {$table} SET slot_no = %d WHERE id = %d AND slot_no IS NULL", $next, (int) $row['id'] )
				);
				if ( false === $updated ) {
					return false; // Leave the version behind so this is retried.
				}
			}
		} while ( count( $rows ) === 500 );

		return true;
	}

	/**
	 * Create the UNIQUE (user_id, slot_no) index if it is not already there, and
	 * report whether it is now in place. The per-user cap is enforced by this
	 * index, so a registration that has a cap to apply refuses (rather than
	 * registering unprotected) when it is missing.
	 *
	 * @return bool True when the index exists afterwards.
	 */
	private static function ensure_slot_index(): bool {
		global $wpdb;
		$table = self::credentials_table();

		if ( ! self::slot_index_exists() ) {
			$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				"ALTER TABLE {$table} ADD UNIQUE KEY " . self::SLOT_INDEX . ' (user_id, slot_no)'
			);
		}

		// Confirm against the table rather than trusting the ALTER's return value.
		self::flush_cap_cache();
		$exists = self::slot_index_exists();
		update_option( self::SLOT_INDEX_OPTION, $exists ? '1' : '0', false );
		return $exists;
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
	 * Whether the database can enforce the per-user cap right now — i.e. the unique
	 * slot index really is on the table.
	 *
	 * This asks the DATABASE, not a stored flag. A flag written during migration
	 * would still say "yes" after the index was later dropped by a restore, a DBA,
	 * or a half-applied schema change, and the cap would then be silently
	 * unenforced. The answer is memoised for the current request only (registration
	 * is rare, so one SHOW INDEX per request costs nothing), and anything other
	 * than a confirmed index — including a failed query — counts as "no", so the
	 * caller fails closed.
	 *
	 * @return bool
	 */
	public static function cap_enforceable(): bool {
		if ( null === self::$cap_enforceable ) {
			self::$cap_enforceable = self::slot_index_exists();
			// Keep the stored flag in step so Site Health and admin notices can show
			// the state without repeating the query. It is a report, never the
			// authority for allowing a write.
			update_option( self::SLOT_INDEX_OPTION, self::$cap_enforceable ? '1' : '0', false );
		}
		return self::$cap_enforceable;
	}

	/**
	 * Forget the memoised index check (after a migration, or in tests).
	 */
	public static function flush_cap_cache(): void {
		self::$cap_enforceable = null;
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
