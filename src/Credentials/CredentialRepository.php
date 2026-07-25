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
	 * Insert a credential ONLY while the user is still below $max, atomically.
	 *
	 * The count-and-insert is a single `INSERT ... SELECT ... WHERE (count) < max`
	 * statement, so two concurrent registrations cannot both read an under-limit
	 * count and both insert: a request that would exceed the cap inserts zero rows.
	 * The per-user maximum therefore holds without an application lock, a
	 * transaction, or a best-effort post-insert rollback to depend on. The user's
	 * own row count is read inside a derived table so MySQL allows referencing the
	 * target table.
	 *
	 * @param int         $user_id       User id.
	 * @param string      $credential_id Base64url credential id.
	 * @param string      $record_json   Serialised credential record.
	 * @param int         $sign_count    Signature counter.
	 * @param string|null $label         Optional label.
	 * @param int         $max           Maximum credentials per user (<= 0 = unlimited).
	 * @return int New row id (>0), 0 on a database error, or -1 when the cap is reached.
	 */
	public function insert_within_limit( int $user_id, string $credential_id, string $record_json, int $sign_count, ?string $label, int $max ): int {
		if ( $max <= 0 ) {
			return $this->insert( $user_id, $credential_id, $record_json, $sign_count, $label );
		}
		global $wpdb;
		$table = Schema::credentials_table();
		$now   = gmdate( 'Y-m-d H:i:s' );

		if ( null === $label ) {
			$sql = $wpdb->prepare( // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				"INSERT INTO {$table} (user_id, credential_id, credential_data, sign_count, label, created_at)
				 SELECT %d, %s, %s, %d, NULL, %s
				 FROM ( SELECT COUNT(*) AS c FROM {$table} WHERE user_id = %d ) AS cnt
				 WHERE cnt.c < %d",
				$user_id,
				$credential_id,
				$record_json,
				$sign_count,
				$now,
				$user_id,
				$max
			);
		} else {
			$sql = $wpdb->prepare( // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				"INSERT INTO {$table} (user_id, credential_id, credential_data, sign_count, label, created_at)
				 SELECT %d, %s, %s, %d, %s, %s
				 FROM ( SELECT COUNT(*) AS c FROM {$table} WHERE user_id = %d ) AS cnt
				 WHERE cnt.c < %d",
				$user_id,
				$credential_id,
				$record_json,
				$sign_count,
				$label,
				$now,
				$user_id,
				$max
			);
		}

		$ok = $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
		if ( false === $ok ) {
			return 0;
		}
		if ( 0 === (int) $wpdb->rows_affected ) {
			return -1;
		}
		return (int) $wpdb->insert_id;
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
	 * Persist the record and signature counter after a successful assertion, as an
	 * optimistic (compare-and-set) update so a concurrent replay cannot slip past
	 * the counter check between our read and write.
	 *
	 * For a counter-using authenticator (new counter > 0) the row is advanced only
	 * when the stored counter is still strictly lower; a concurrent assertion that
	 * already advanced it updates zero rows and the caller must abort the login.
	 * A counter-less authenticator (always 0) has no freshness signal here — replay
	 * is prevented upstream by the one-time challenge — so it updates by row id.
	 *
	 * @param int    $id          Row id.
	 * @param string $record_json Re-serialised CredentialRecord JSON.
	 * @param int    $sign_count  New signature counter.
	 * @return int  1 when the row was committed, 0 when the counter did not advance
	 *              (reject the login), -1 on a database error (reject the login).
	 */
	public function touch( int $id, string $record_json, int $sign_count ): int {
		global $wpdb;
		$table = Schema::credentials_table();
		$now   = gmdate( 'Y-m-d H:i:s' );

		if ( $sign_count > 0 ) {
			$affected = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				$wpdb->prepare(
					"UPDATE {$table} SET credential_data = %s, sign_count = %d, last_used_at = %s WHERE id = %d AND sign_count < %d",
					$record_json,
					$sign_count,
					$now,
					$id,
					$sign_count
				)
			);
			if ( false === $affected ) {
				return -1;
			}
			return (int) $affected >= 1 ? 1 : 0;
		}

		$affected = $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->prepare(
				"UPDATE {$table} SET credential_data = %s, sign_count = %d, last_used_at = %s WHERE id = %d",
				$record_json,
				$sign_count,
				$now,
				$id
			)
		);
		// A matched-but-unchanged row can report 0 affected; that is fine for a
		// counter-less authenticator, so only a hard DB error (false) is a failure.
		return false === $affected ? -1 : 1;
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
	 * The credentials a user can actually sign in with (suspended ones excluded).
	 *
	 * @param int $user_id User id.
	 * @return Credential[]
	 */
	public function find_active_by_user( int $user_id ): array {
		return array_values(
			array_filter(
				$this->find_by_user( $user_id ),
				static function ( Credential $credential ): bool {
					return $credential->active;
				}
			)
		);
	}

	/**
	 * Suspend or resume a credential.
	 *
	 * Suspending is the answer to "my laptop is at the repair shop": the passkey
	 * stops working immediately but is not destroyed, so it can be brought back
	 * without a re-registration ceremony. Deleting is the answer to "it is gone
	 * for good".
	 *
	 * @param int      $id      Row id.
	 * @param int|null $user_id Owner to scope the update to, or null for an admin
	 *                          acting on someone else's credential (already
	 *                          capability-checked by the caller).
	 * @param bool     $active  New state.
	 * @return bool True if the row exists (and belongs to $user_id when given).
	 */
	public function set_active( int $id, ?int $user_id, bool $active ): bool {
		global $wpdb;

		$where = array( 'id' => $id );
		$types = array( '%d' );
		if ( null !== $user_id ) {
			$where['user_id'] = $user_id;
			$types[]          = '%d';
		}

		$updated = $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			Schema::credentials_table(),
			array( 'active' => $active ? 1 : 0 ),
			$where,
			array( '%d' ),
			$types
		);

		if ( false === $updated ) {
			return false;
		}
		// 0 changed rows means either "already in that state" or "not yours"; only
		// the second is a failure.
		if ( 0 === (int) $updated ) {
			$credential = $this->find_by_id( $id );
			if ( null === $credential ) {
				return false;
			}
			return null === $user_id || (int) $credential->user_id === $user_id;
		}
		return true;
	}

	/**
	 * Every credential on the site, newest first — for the admin overview.
	 *
	 * @param string $search   Match against the label or the owner's login/email ('' for all).
	 * @param int    $per_page Rows to return.
	 * @param int    $offset   Rows to skip.
	 * @return Credential[]
	 */
	public function find_all( string $search = '', int $per_page = 50, int $offset = 0 ): array {
		global $wpdb;
		$table = Schema::credentials_table();
		$users = $wpdb->users;

		$per_page = max( 1, min( 200, $per_page ) );
		$offset   = max( 0, $offset );

		if ( '' !== $search ) {
			$like = '%' . $wpdb->esc_like( $search ) . '%';
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				$wpdb->prepare(
					"SELECT c.* FROM {$table} c
					 LEFT JOIN {$users} u ON u.ID = c.user_id
					 WHERE c.label LIKE %s OR u.user_login LIKE %s OR u.user_email LIKE %s
					 ORDER BY c.id DESC LIMIT %d OFFSET %d",
					$like,
					$like,
					$like,
					$per_page,
					$offset
				),
				ARRAY_A
			);
		} else {
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				$wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset ),
				ARRAY_A
			);
		}

		return array_map( array( self::class, 'hydrate' ), $rows ?: array() );
	}

	/**
	 * How many credentials {@see find_all()} would match.
	 *
	 * @param string $search Same search term.
	 * @return int
	 */
	public function count_all( string $search = '' ): int {
		global $wpdb;
		$table = Schema::credentials_table();
		$users = $wpdb->users;

		if ( '' !== $search ) {
			$like = '%' . $wpdb->esc_like( $search ) . '%';
			return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$table} c
					 LEFT JOIN {$users} u ON u.ID = c.user_id
					 WHERE c.label LIKE %s OR u.user_login LIKE %s OR u.user_email LIKE %s",
					$like,
					$like,
					$like
				)
			);
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
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
			isset( $row['last_used_at'] ) && null !== $row['last_used_at'] ? (string) $row['last_used_at'] : null,
			// Rows written before the column existed are active; the upgrade
			// backfills them, but tolerate a missing key either way.
			! isset( $row['active'] ) || (bool) (int) $row['active']
		);
	}
}
