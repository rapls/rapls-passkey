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
	private const VERSION = '2';

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
		 * twice. credential_data holds the full serialised CredentialRecord
		 * (public key, transports, aaguid, trust path, counter, …) as JSON — the
		 * source of truth round-tripped through web-auth's serializer. sign_count
		 * is denormalised for display and updated after every assertion.
		 */
		$sql = "CREATE TABLE {$credentials} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL,
			credential_id varchar(255) NOT NULL,
			credential_data longtext NOT NULL,
			sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
			label varchar(191) DEFAULT NULL,
			created_at datetime NOT NULL,
			last_used_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY credential_id (credential_id),
			KEY user_id (user_id)
		) {$charset_collate};";

		dbDelta( $sql );

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
	 * Drop the table and the version marker. Used by uninstall.
	 */
	public static function drop(): void {
		global $wpdb;

		// Table names are built from $wpdb->prefix, not user input.
		foreach ( array( self::credentials_table(), self::audit_table() ) as $table ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}
		delete_option( self::VERSION_OPTION );
	}
}
