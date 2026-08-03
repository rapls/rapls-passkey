<?php
/**
 * Credential table data access.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

defined( 'ABSPATH' ) || exit;

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
		// No cap to honour here: take the first slot number that is free, retrying
		// if a concurrent registration claims it first.
		for ( $attempt = 0; $attempt < 10; $attempt++ ) {
			$used = $this->used_slots( $user_id );
			if ( null === $used ) {
				return 0; // Database error.
			}
			$slot = 1;
			while ( in_array( $slot, $used, true ) ) {
				++$slot;
			}
			$id = $this->insert_in_slot( $user_id, $slot, $credential_id, $record_json, $sign_count, $label );
			if ( -1 !== $id ) {
				return $id; // Inserted (>0) or a real error (0).
			}
		}
		return 0;
	}

	/**
	 * The slot numbers a user's passkeys currently occupy.
	 *
	 * @param int $user_id User id.
	 * @return int[]|null Slot numbers, or null on a database error.
	 */
	public function used_slots( int $user_id ): ?array {
		global $wpdb;
		$table = Schema::credentials_table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows  = $wpdb->get_col(
			$wpdb->prepare( "SELECT slot_no FROM {$table} WHERE user_id = %d AND slot_no IS NOT NULL", $user_id )
		);
		if ( ! is_array( $rows ) ) {
			return null;
		}
		if ( '' !== (string) $wpdb->last_error ) {
			return null;
		}
		return array_map( 'intval', $rows );
	}

	/**
	 * Insert a credential claiming one specific slot number.
	 *
	 * This is the primitive that makes the per-user cap exact. The UNIQUE
	 * (user_id, slot_no) index means only ONE of any number of concurrent
	 * registrations can take a given slot — no application lock is involved, so the
	 * guarantee survives a dropped-and-reopened connection, a read/write-splitting
	 * db.php, and any storage engine. The caller only ever offers slots within the
	 * configured cap, so the cap cannot be exceeded however many requests race.
	 *
	 * @param int         $user_id       Owning user id.
	 * @param int         $slot          Slot number to claim (1-based).
	 * @param string      $credential_id Base64url credential id.
	 * @param string      $record_json   Serialised CredentialRecord JSON.
	 * @param int         $sign_count    Initial signature counter.
	 * @param string|null $label         Optional user label.
	 * @return int Inserted row id (>0), -1 when the slot is already taken (try the
	 *             next one), or 0 on any other failure.
	 */
	public function insert_in_slot( int $user_id, int $slot, string $credential_id, string $record_json, int $sign_count, ?string $label ): int {
		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );
		// Losing a slot to a concurrent registration is a normal outcome here — the
		// caller simply tries the next one — so the duplicate it produces should not
		// be logged as a database error. Suppression is restored below and leaves
		// last_error intact for the checks that follow.
		$suppressed = method_exists( $wpdb, 'suppress_errors' ) ? $wpdb->suppress_errors( true ) : null;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$ok  = $wpdb->insert(
			Schema::credentials_table(),
			array(
				'user_id'         => $user_id,
				'slot_no'         => $slot,
				'credential_id'   => $credential_id,
				'credential_data' => $record_json,
				'sign_count'      => $sign_count,
				'label'           => $label,
				'created_at'      => $now,
			),
			array( '%d', '%d', '%s', '%s', '%d', '%s', '%s' )
		);
		if ( null !== $suppressed ) {
			$wpdb->suppress_errors( $suppressed );
		}
		if ( $ok ) {
			return (int) $wpdb->insert_id;
		}

		// The insert failed. Read back to find out WHY, rather than parsing the
		// driver's error text: if our own credential is now stored, the write
		// actually landed (a reconnect can replay the statement, and the unique
		// credential_id index then rejects the duplicate) — treat that as success,
		// which makes the whole registration idempotent under a reconnect.
		$mine = $this->find_by_credential_id( $credential_id );
		if ( null !== $mine && (int) $mine->user_id === $user_id ) {
			return (int) $mine->id;
		}

		$table = Schema::credentials_table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$taken = $wpdb->get_var(
			$wpdb->prepare( "SELECT id FROM {$table} WHERE user_id = %d AND slot_no = %d", $user_id, $slot )
		);
		if ( null !== $taken ) {
			return -1; // Someone else holds this slot — the caller tries the next.
		}

		return 0; // A genuine failure (not a slot collision).
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$row   = $wpdb->get_row(
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows  = $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE user_id = %d ORDER BY id DESC", $user_id ),
			ARRAY_A
		);

		return array_map( array( self::class, 'hydrate' ), $rows ?: array() );
	}

	/**
	 * How many credentials a user holds, distinguishing a genuine database error
	 * (returns -1) from an empty set (returns 0). Unlike find_by_user(), which maps
	 * a failed query to an empty array — indistinguishable from "no credentials" —
	 * so a caller enforcing a registration cap can fail closed on a DB error rather
	 * than treating the failure as "under the limit".
	 *
	 * @param int $user_id User id.
	 * @return int Count, or -1 on a database error.
	 */
	public function count_by_user( int $user_id ): int {
		global $wpdb;
		$table = Schema::credentials_table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$count = $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE user_id = %d", $user_id )
		);
		// A successful COUNT(*) always yields a numeric string ("0" at minimum);
		// get_var() returns null only on a query error, which last_error confirms.
		if ( null === $count && '' !== (string) $wpdb->last_error ) {
			return -1;
		}
		return (int) $count;
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

		// `active = 1` is part of every condition, and touch_nonce is rewritten to a
		// fresh value every time. That second part matters: because the row always
		// changes, "one row changed" is a truthful answer from the SERVER THAT TOOK
		// THE WRITE about whether an active row still existed. The previous version
		// asked a follow-up SELECT when nothing changed, and a read/write-splitting
		// db.php could answer that from a replica still showing the credential as
		// active — letting a login complete against a credential suspended during
		// the ceremony. Nothing is read here now.
		$nonce = bin2hex( random_bytes( 8 ) );

		if ( $sign_count > 0 ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$affected = $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$table} SET credential_data = %s, sign_count = %d, last_used_at = %s, touch_nonce = %s WHERE id = %d AND active = 1 AND sign_count < %d",
					$record_json,
					$sign_count,
					$now,
					$nonce,
					$id,
					$sign_count
				)
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$affected = $wpdb->query(
				$wpdb->prepare(
					"UPDATE {$table} SET credential_data = %s, sign_count = %d, last_used_at = %s, touch_nonce = %s WHERE id = %d AND active = 1",
					$record_json,
					$sign_count,
					$now,
					$nonce,
					$id
				)
			);
		}

		if ( false === $affected ) {
			return -1;
		}
		// 0 changed rows now means exactly one thing: no active row matched — the
		// credential was suspended or removed, or (with a counter) the counter did
		// not advance. Either way the login must not proceed.
		return (int) $affected >= 1 ? 1 : 0;
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$row   = $wpdb->get_row(
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$deleted = $wpdb->delete(
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$updated = $wpdb->update(
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
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$rows = $wpdb->get_results(
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
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$rows = $wpdb->get_results(
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
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			return (int) $wpdb->get_var(
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$updated = $wpdb->update(
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$deleted = $wpdb->delete(
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$deleted = $wpdb->delete(
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows  = $wpdb->get_results(
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
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			'total' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ),
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			'users' => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT user_id) FROM {$table}" ),
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
