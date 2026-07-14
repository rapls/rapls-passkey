<?php
/**
 * Credential table data access.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CRUD over the custom credentials table. All queries are prepared and table
 * names come from $wpdb->prefix (never user input).
 */
final class CredentialRepository {

	/**
	 * Insert a freshly registered credential.
	 *
	 * @param int         $user_id       Owning user id.
	 * @param string      $credential_id Base64url credential id.
	 * @param string      $record_json   Serialised CredentialRecord JSON.
	 * @param int         $sign_count    Initial signature counter.
	 * @param string|null $label         Optional user label.
	 * @return int Inserted row id (0 on failure).
	 */
	public function insert( int $user_id, string $credential_id, string $record_json, int $sign_count, ?string $label ): int {
		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );
		$ok  = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array(
				'user_id'         => $user_id,
				'credential_id'   => $credential_id,
				'credential_data' => $record_json,
				'sign_count'      => $sign_count,
				'label'           => $label,
				'created_at'      => $now,
			),
			array( '%d', '%s', '%s', '%d', '%s', '%s' )
		);

		return $ok ? (int) $wpdb->insert_id : 0;
	}

	/**
	 * Look up a credential by its base64url id.
	 *
	 * @param string $credential_id Base64url credential id.
	 * @return Credential|null
	 */
	public function find_by_credential_id( string $credential_id ): ?Credential {
		global $wpdb;
		$table = Schema::credentials_table();
		$row   = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( "SELECT * FROM {$table} WHERE credential_id = %s", $credential_id ),
			ARRAY_A
		);

		return $row ? self::hydrate( $row ) : null;
	}

	/**
	 * All credentials for a user, newest first.
	 *
	 * @param int $user_id User id.
	 * @return Credential[]
	 */
	public function find_by_user( int $user_id ): array {
		global $wpdb;
		$table = Schema::credentials_table();
		$rows  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( "SELECT * FROM {$table} WHERE user_id = %d ORDER BY id DESC", $user_id ),
			ARRAY_A
		);

		return array_map( array( self::class, 'hydrate' ), $rows ?: array() );
	}

	/**
	 * Update the stored record and counter after a successful assertion.
	 *
	 * @param int    $id          Row id.
	 * @param string $record_json Re-serialised CredentialRecord JSON.
	 * @param int    $sign_count  New signature counter.
	 * @return void
	 */
	public function touch( int $id, string $record_json, int $sign_count ): void {
		global $wpdb;
		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array(
				'credential_data' => $record_json,
				'sign_count'      => $sign_count,
				'last_used_at'    => gmdate( 'Y-m-d H:i:s' ),
			),
			array( 'id' => $id ),
			array( '%s', '%d', '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Look up a credential by its row id.
	 *
	 * @param int $id Row id.
	 * @return Credential|null
	 */
	public function find_by_id( int $id ): ?Credential {
		global $wpdb;
		$table = Schema::credentials_table();
		$row   = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ),
			ARRAY_A
		);

		return $row ? self::hydrate( $row ) : null;
	}

	/**
	 * Delete a credential, scoped to its owner so users can only remove their own.
	 *
	 * @param int $id      Row id.
	 * @param int $user_id Owning user id.
	 * @return bool True if a row was deleted.
	 */
	public function delete( int $id, int $user_id ): bool {
		global $wpdb;
		$deleted = $wpdb->delete( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array(
				'id'      => $id,
				'user_id' => $user_id,
			),
			array( '%d', '%d' )
		);

		return (bool) $deleted;
	}

	/**
	 * Rename a credential the user owns.
	 *
	 * A name is the only thing that tells two "iCloud Keychain" entries apart, so a
	 * user who cannot rename after the fact ends up unable to tell which passkey to
	 * revoke when they lose a device.
	 *
	 * @param int         $id      Row id.
	 * @param int         $user_id Owning user id.
	 * @param string|null $label   New name, or null to clear it.
	 * @return bool True if the row exists and belongs to the user.
	 */
	public function rename( int $id, int $user_id, ?string $label ): bool {
		global $wpdb;

		$updated = $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array( 'label' => $label ),
			array(
				'id'      => $id,
				'user_id' => $user_id,
			),
			array( '%s' ),
			array( '%d', '%d' )
		);

		if ( false === $updated ) {
			return false;
		}
		// $wpdb->update() reports 0 changed rows when the new name equals the old
		// one, which is a successful no-op rather than "not yours".
		if ( 0 === (int) $updated ) {
			$credential = $this->find_by_id( $id );
			return null !== $credential && (int) $credential->user_id === $user_id;
		}
		return true;
	}

	/**
	 * Delete a credential by row id, regardless of owner. For trusted
	 * server-side recovery (WP-CLI / admin tooling) only — the REST path uses
	 * the owner-scoped delete().
	 *
	 * @param int $id Row id.
	 * @return bool True if a row was deleted.
	 */
	public function delete_by_id( int $id ): bool {
		global $wpdb;
		$deleted = $wpdb->delete( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array( 'id' => $id ),
			array( '%d' )
		);

		return (bool) $deleted;
	}

	/**
	 * Delete every credential belonging to a user (for the privacy eraser /
	 * user deletion).
	 *
	 * @param int $user_id User id.
	 * @return int Number of rows deleted.
	 */
	public function delete_all_for_user( int $user_id ): int {
		global $wpdb;
		$deleted = $wpdb->delete( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array( 'user_id' => $user_id ),
			array( '%d' )
		);

		return (int) $deleted;
	}

	/**
	 * Passkey count and most-recent use per user, keyed by user id. Only users
	 * with at least one passkey appear. Used to fill the Users-list column in a
	 * single query (no per-row lookups).
	 *
	 * @return array<int,array{count:int,last_used:?string}>
	 */
	public function counts_by_user(): array {
		global $wpdb;
		$table = Schema::credentials_table();
		$rows  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			"SELECT user_id, COUNT(*) AS c, MAX(last_used_at) AS last_used FROM {$table} GROUP BY user_id",
			ARRAY_A
		);

		$out = array();
		foreach ( $rows ?: array() as $row ) {
			$out[ (int) $row['user_id'] ] = array(
				'count'     => (int) $row['c'],
				'last_used' => isset( $row['last_used'] ) && null !== $row['last_used'] ? (string) $row['last_used'] : null,
			);
		}
		return $out;
	}

	/**
	 * Site-wide adoption totals: total passkeys and number of distinct users
	 * holding at least one.
	 *
	 * @return array{total:int,users:int}
	 */
	public function stats(): array {
		global $wpdb;
		$table = Schema::credentials_table();

		return array(
			'total' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			'users' => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT user_id) FROM {$table}" ), // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		);
	}

	/**
	 * Map a DB row to a Credential.
	 *
	 * @param array<string,mixed> $row Row.
	 * @return Credential
	 */
	private static function hydrate( array $row ): Credential {
		return new Credential(
			(int) $row['id'],
			(int) $row['user_id'],
			(string) $row['credential_id'],
			(string) $row['credential_data'],
			(int) $row['sign_count'],
			isset( $row['label'] ) ? ( null === $row['label'] ? null : (string) $row['label'] ) : null,
			(string) $row['created_at'],
			isset( $row['last_used_at'] ) && null !== $row['last_used_at'] ? (string) $row['last_used_at'] : null
		);
	}
}
