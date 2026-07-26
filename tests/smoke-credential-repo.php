<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Exercises CredentialRepository CRUD against an in-memory $wpdb stub.
 *
 *   php tests/smoke-credential-repo.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

// --- In-memory $wpdb ------------------------------------------------------
class WPDB_Mem {
	public $prefix = 'wp_';
	public $users = 'wp_users';
	public $insert_id = 0;
	public $rows_affected = 0;
	public $last_error = '';
	public $fail_next = false; // simulate a single DB error on the next get_var
	public $rows = array();
	private $auto = 0;

	public function insert( $table, $data, $formats ) {
		$this->last_error = '';
		if ( $this->fail_next ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return false;
		}
		// The real table carries UNIQUE (user_id, slot_no) and UNIQUE (credential_id).
		// Those constraints — not any lock — are what bound the per-user cap, so the
		// double must reject a duplicate exactly as MySQL would.
		foreach ( $this->rows as $row ) {
			$slot_clash = isset( $data['slot_no'] ) && isset( $row['slot_no'] )
				&& (int) $row['user_id'] === (int) $data['user_id']
				&& (int) $row['slot_no'] === (int) $data['slot_no'];
			$cred_clash = (string) $row['credential_id'] === (string) $data['credential_id'];
			if ( $slot_clash || $cred_clash ) {
				$this->last_error = 'Duplicate entry';
				return false;
			}
		}
		$data['id'] = ++$this->auto;
		$this->rows[ $data['id'] ] = $data;
		$this->insert_id = $data['id'];
		return 1;
	}
	public function update( $table, $data, $where, $f = null, $wf = null ) {
		$id = (int) $where['id'];
		if ( ! isset( $this->rows[ $id ] ) ) {
			return 0;
		}
		// rename() scopes the update to the owner; touch() does not pass user_id.
		if ( isset( $where['user_id'] ) && (int) $this->rows[ $id ]['user_id'] !== (int) $where['user_id'] ) {
			return 0;
		}
		// Like the real $wpdb, report 0 changed rows when nothing actually changes.
		$merged = array_merge( $this->rows[ $id ], $data );
		if ( $merged === $this->rows[ $id ] ) {
			return 0;
		}
		$this->rows[ $id ] = $merged;
		return 1;
	}
	public function delete( $table, $where, $f = null ) {
		foreach ( $this->rows as $id => $row ) {
			$id_ok   = (int) $id === (int) $where['id'];
			// delete_by_id() omits user_id; owner-scoped delete() includes it.
			$user_ok = ! isset( $where['user_id'] ) || (int) $row['user_id'] === (int) $where['user_id'];
			if ( $id_ok && $user_ok ) {
				unset( $this->rows[ $id ] );
				return 1;
			}
		}
		return 0;
	}
	public function prepare( $query, ...$args ) {
		return array( 'q' => $query, 'args' => $args );
	}
	// touch() runs an optimistic UPDATE via query() (not update()); registration
	// uses insert_within_limit()'s atomic INSERT ... SELECT ... WHERE (count) < max.
	public function query( $prepared ) {
		$q = $prepared['q'];
		$a = $prepared['args'];
		// insert_within_limit(): count this user's rows, insert only if below the cap.
		if ( false !== strpos( $q, 'INSERT INTO' ) && false !== strpos( $q, 'cnt.c <' ) ) {
			$uid = (int) $a[0];
			$max = (int) end( $a );
			$count = 0;
			foreach ( $this->rows as $r ) {
				if ( (int) $r['user_id'] === $uid ) { $count++; }
			}
			if ( $count >= $max ) { $this->rows_affected = 0; return 1; } // cap reached
			$null_label = false !== strpos( $q, ', NULL,' );
			$id = ++$this->auto;
			$this->rows[ $id ] = array(
				'id'              => $id,
				'user_id'         => $uid,
				'credential_id'   => (string) $a[1],
				'credential_data' => (string) $a[2],
				'sign_count'      => (int) $a[3],
				'label'           => $null_label ? null : (string) $a[4],
				'created_at'      => (string) ( $null_label ? $a[4] : $a[5] ),
			);
			$this->insert_id     = $id;
			$this->rows_affected = 1;
			return 1;
		}
		if ( false === strpos( $q, 'UPDATE' ) || false === strpos( $q, 'credential_data' ) ) {
			return 0;
		}
		// touch(): record_json, sign_count, now, touch_nonce, id [, min sign_count].
		$id = (int) $a[4];
		if ( ! isset( $this->rows[ $id ] ) ) {
			return 0;   // Row gone: no active row matched.
		}
		// `active = 1` is part of the WHERE, so a suspended credential matches nothing.
		if ( false !== strpos( $q, 'active = 1' ) && 0 === (int) ( $this->rows[ $id ]['active'] ?? 1 ) ) {
			return 0;
		}
		if ( false !== strpos( $q, 'sign_count < %d' ) ) {
			$min = (int) $a[5];
			if ( (int) $this->rows[ $id ]['sign_count'] >= $min ) {
				return 0; // Counter did not advance.
			}
		}
		$this->rows[ $id ]['credential_data'] = (string) $a[0];
		$this->rows[ $id ]['sign_count']      = (int) $a[1];
		$this->rows[ $id ]['last_used_at']    = (string) $a[2];
		$this->rows[ $id ]['touch_nonce']     = (string) $a[3];
		return 1;
	}
	public function get_row( $prepared, $output = OBJECT ) {
		$arg    = $prepared['args'][0];
		$by_id  = is_string( $prepared['q'] ) && strpos( $prepared['q'], 'WHERE id =' ) !== false;
		foreach ( $this->rows as $row ) {
			if ( $by_id ) {
				if ( (int) $row['id'] === (int) $arg ) {
					return $this->cols( $row );
				}
			} elseif ( (string) $row['credential_id'] === (string) $arg ) {
				return $this->cols( $row );
			}
		}
		return null;
	}
	public function get_results( $prepared, $output = OBJECT ) {
		$newest = array_reverse( $this->rows, true );

		// find_by_user(): WHERE user_id = %d. find_all(): no WHERE, LIMIT/OFFSET.
		if ( strpos( $prepared['q'], 'WHERE user_id =' ) !== false ) {
			$uid = (int) $prepared['args'][0];
			$out = array();
			foreach ( $newest as $row ) {
				if ( (int) $row['user_id'] === $uid ) {
					$out[] = $this->cols( $row );
				}
			}
			return $out;
		}

		$limit  = (int) ( $prepared['args'][0] ?? 50 );
		$offset = (int) ( $prepared['args'][1] ?? 0 );
		return array_map( array( $this, 'cols' ), array_slice( array_values( $newest ), $offset, $limit ) );
	}
	public function get_var( $query ) {
		$this->last_error = '';
		if ( $this->fail_next ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return null; // get_var() returns null on a DB error
		}
		// insert_in_slot(): "is this slot already taken?" read-back.
		if ( is_array( $query ) && isset( $query['q'] ) && false !== strpos( $query['q'], 'slot_no = %d' ) ) {
			$uid  = (int) ( $query['args'][0] ?? 0 );
			$slot = (int) ( $query['args'][1] ?? 0 );
			foreach ( $this->rows as $r ) {
				if ( (int) $r['user_id'] === $uid && (int) ( $r['slot_no'] ?? 0 ) === $slot ) {
					return (string) $r['id'];
				}
			}
			return null;
		}
		// count_by_user(): prepared array carrying a WHERE user_id filter.
		if ( is_array( $query ) && isset( $query['q'] ) && false !== strpos( $query['q'], 'WHERE user_id =' ) ) {
			$uid = (int) ( $query['args'][0] ?? 0 );
			$n   = 0;
			foreach ( $this->rows as $r ) {
				if ( (int) $r['user_id'] === $uid ) {
					$n++;
				}
			}
			return (string) $n;
		}
		// count_all() with no search passes a plain string.
		return count( $this->rows );
	}
	// used_slots(): SELECT slot_no ... WHERE user_id = %d AND slot_no IS NOT NULL
	public function get_col( $prepared ) {
		$this->last_error = '';
		if ( $this->fail_next ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return array(); // wpdb returns an empty array on a failed query
		}
		$uid  = (int) ( $prepared['args'][0] ?? 0 );
		$out  = array();
		foreach ( $this->rows as $r ) {
			if ( (int) $r['user_id'] === $uid && isset( $r['slot_no'] ) && null !== $r['slot_no'] ) {
				$out[] = (string) $r['slot_no'];
			}
		}
		return $out;
	}
	public function esc_like( $s ) { return $s; }
	private function cols( $row ) {
		return array(
			'id'              => $row['id'],
			'user_id'         => $row['user_id'],
			'credential_id'   => $row['credential_id'],
			'credential_data' => $row['credential_data'],
			'sign_count'      => $row['sign_count'],
			'label'           => $row['label'] ?? null,
			'active'          => $row['active'] ?? 1,
			'created_at'      => $row['created_at'],
			'last_used_at'    => $row['last_used_at'] ?? null,
		);
	}
}
if ( ! defined( 'OBJECT' ) ) { define( 'OBJECT', 'OBJECT' ); }
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }
$GLOBALS['wpdb'] = new WPDB_Mem();

spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

use RaplsPasskey\Credentials\CredentialRepository;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

$repo = new CredentialRepository();

$id1 = $repo->insert( 7, 'credAAA', '{"r":1}', 0, 'MacBook' );
$id2 = $repo->insert( 7, 'credBBB', '{"r":2}', 5, null );
$id3 = $repo->insert( 9, 'credCCC', '{"r":3}', 0, 'Phone' );
check( 'insert returns ids', $id1 > 0 && $id2 > 0 && $id3 > 0 );

$found = $repo->find_by_credential_id( 'credBBB' );
check( 'find_by_credential_id returns the right row', $found && $found->user_id === 7 && $found->sign_count === 5 );
check( 'find_by_credential_id maps record_json', $found && $found->record_json === '{"r":2}' );
check( 'find_by_credential_id null when missing', $repo->find_by_credential_id( 'nope' ) === null );

$mine = $repo->find_by_user( 7 );
check( 'find_by_user returns only that user, newest first', count( $mine ) === 2 && $mine[0]->credential_id === 'credBBB' );

// count_by_user() distinguishes an empty set (0) from a DB error (-1) so the
// registration cap can fail closed (V13-01).
check( 'count_by_user counts a user\'s rows', $repo->count_by_user( 7 ) === 2 );
check( 'count_by_user returns 0 for a user with none', $repo->count_by_user( 12345 ) === 0 );
$GLOBALS['wpdb']->fail_next = true;
check( 'count_by_user returns -1 on a DB error (fail closed)', $repo->count_by_user( 7 ) === -1 );

// --- Slot claiming: the DB constraint that makes the cap exact (V14-01) --------
// Every credential occupies a numbered slot under UNIQUE (user_id, slot_no).
check( 'insert() assigns sequential slots', $repo->used_slots( 7 ) === array( 1, 2 ) );
check( 'slots are per user', $repo->used_slots( 9 ) === array( 1 ) );

// A second claim on an occupied slot is refused BY THE DATABASE (-1), which is how
// two concurrent registrations cannot both take the last slot under a cap.
check( 'claiming a taken slot returns -1', $repo->insert_in_slot( 7, 1, 'credDUP', '{}', 0, null ) === -1 );
check( 'and nothing was stored', $repo->find_by_credential_id( 'credDUP' ) === null );

// A free slot is claimable.
$slot3 = $repo->insert_in_slot( 7, 3, 'credDDD', '{"r":4}', 0, 'Key' );
check( 'claiming a free slot succeeds', $slot3 > 0 && $repo->used_slots( 7 ) === array( 1, 2, 3 ) );

// Re-inserting the SAME credential (what a transparent reconnect replay looks like)
// reports the existing row rather than failing — registration stays idempotent.
check( 'replaying the same credential returns the existing row', $repo->insert_in_slot( 7, 4, 'credDDD', '{"r":4}', 0, 'Key' ) === $slot3 );
check( 'the replay created no second row', count( $repo->find_by_user( 7 ) ) === 3 );

// used_slots() distinguishes a DB error (null) from "no slots" (empty array).
check( 'used_slots returns an empty array for a user with none', $repo->used_slots( 4242 ) === array() );
$GLOBALS['wpdb']->fail_next = true;
check( 'used_slots returns null on a DB error (fail closed)', $repo->used_slots( 7 ) === null );
$repo->delete_by_id( $slot3 ); // restore for the checks below

// --- rename (owner-scoped) ---
check( 'rename succeeds for the owner', $repo->rename( $id1, 7, 'Work laptop' ) === true );
check( 'the new name is stored', $repo->find_by_id( $id1 )->label === 'Work laptop' );
check( 'renaming to the same name is still a success', $repo->rename( $id1, 7, 'Work laptop' ) === true );
check( 'a name can be cleared', $repo->rename( $id1, 7, null ) === true && $repo->find_by_id( $id1 )->label === null );
check( "another user cannot rename it", $repo->rename( $id1, 9, 'Stolen' ) === false );
check( "and the name is untouched", $repo->find_by_id( $id1 )->label === null );
check( 'renaming a missing row fails', $repo->rename( 9999, 7, 'Ghost' ) === false );
$repo->rename( $id1, 7, 'MacBook' ); // Restore for the checks below.

// --- suspend / resume ---
check( 'a new passkey is active', $repo->find_by_id( $id1 )->active === true );
check( 'the owner can suspend it', $repo->set_active( $id1, 7, false ) === true );
check( 'it is then suspended', $repo->find_by_id( $id1 )->active === false );
check( 'suspending twice is still a success', $repo->set_active( $id1, 7, false ) === true );
check( 'a suspended passkey drops out of find_active_by_user', count( $repo->find_active_by_user( 7 ) ) === 1 );
check( 'but it is still listed for management', count( $repo->find_by_user( 7 ) ) === 2 );
check( "another user cannot suspend it", $repo->set_active( $id3, 7, false ) === false );
check( "and that one stays active", $repo->find_by_id( $id3 )->active === true );
check( 'an admin (no owner scope) can suspend anyone\'s', $repo->set_active( $id3, null, false ) === true );
check( 'suspending a missing row fails', $repo->set_active( 9999, null, false ) === false );
check( 'the owner can resume it', $repo->set_active( $id1, 7, true ) === true );
check( 'it is active again', $repo->find_by_id( $id1 )->active === true );
$repo->set_active( $id3, null, true ); // Restore.

// --- site-wide list ---
check( 'find_all returns every passkey, newest first', count( $repo->find_all() ) === 3 && $repo->find_all()[0]->id === $id3 );
check( 'count_all counts them', $repo->count_all() === 3 );
check( 'find_all paginates', count( $repo->find_all( '', 2, 0 ) ) === 2 && count( $repo->find_all( '', 2, 2 ) ) === 1 );

check( 'touch commits an advancing counter (returns 1)', $repo->touch( $id2, '{"r":2,"u":1}', 6 ) === 1 );
$after = $repo->find_by_credential_id( 'credBBB' );
check( 'touch updates record + counter', $after->sign_count === 6 && $after->record_json === '{"r":2,"u":1}' );
check( 'touch sets last_used_at', ! empty( $after->last_used_at ) );

// Optimistic CAS (F-13): a replay whose counter does not advance is rejected,
// and the stored record is left untouched.
check( 'touch rejects a non-advancing counter (returns 0)', $repo->touch( $id2, '{"r":2,"u":99}', 6 ) === 0 );
$still = $repo->find_by_credential_id( 'credBBB' );
check( 'a rejected touch leaves the record unchanged', $still->record_json === '{"r":2,"u":1}' && $still->sign_count === 6 );
// A counter-less authenticator (always 0) commits by row id (challenge is the
// replay guard there), so it is not blocked by the CAS.
check( 'touch on a counter-less authenticator commits (returns 1)', $repo->touch( $id3, '{"r":3,"u":1}', 0 ) === 1 );

// R20-09 / R21-02: a credential suspended or removed DURING the ceremony must not
// complete the login. The decision comes from the write itself — the row always
// changes (touch_nonce), so "0 rows changed" can only mean no active row matched.
// No follow-up read is involved, so a replica still showing the old state cannot
// let the login through.
$repo->set_active( $id3, null, false );
check( 'a credential suspended mid-ceremony does not commit (counter-less)', $repo->touch( $id3, '{"r":3,"u":2}', 0 ) === 0 );
check( 'and its record was not advanced', $repo->find_by_id( $id3 )->record_json === '{"r":3,"u":1}' );
$repo->set_active( $id3, null, true );
check( 'once resumed it commits again', $repo->touch( $id3, '{"r":3,"u":3}', 0 ) === 1 );

$repo->set_active( $id2, null, false );
check( 'a suspended credential does not commit with a counter either', $repo->touch( $id2, '{"r":2,"u":9}', 99 ) === 0 );
$repo->set_active( $id2, null, true );

// A deleted row is the same answer: nothing active matched.
check( 'a removed credential does not commit', $repo->touch( 987654, '{}', 5 ) === 0 );

// Every commit rewrites touch_nonce, which is what makes the row always change.
$before_nonce = $GLOBALS['wpdb']->rows[ $id3 ]['touch_nonce'] ?? '';
$repo->touch( $id3, '{"r":3,"u":4}', 0 );
check( 'each commit writes a fresh touch_nonce', ( $GLOBALS['wpdb']->rows[ $id3 ]['touch_nonce'] ?? '' ) !== $before_nonce );

// find_by_id (used by admin delete path).
$by_id = $repo->find_by_id( $id3 );
check( 'find_by_id returns the right row', $by_id && $by_id->user_id === 9 && $by_id->credential_id === 'credCCC' );
check( 'find_by_id null when missing', $repo->find_by_id( 99999 ) === null );

check( 'delete scoped to owner fails for wrong user', $repo->delete( $id1, 9 ) === false );
check( 'delete works for owner', $repo->delete( $id1, 7 ) === true );
check( 'deleted row is gone', $repo->find_by_credential_id( 'credAAA' ) === null );

// delete_by_id (admin/CLI path) ignores ownership.
check( 'delete_by_id removes another user\'s row', $repo->delete_by_id( $id3 ) === true );
check( 'delete_by_id row is gone', $repo->find_by_id( $id3 ) === null );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
