<?php
/**
 * Lockout prevention helpers.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Recovery;

use RaplsPasskey\Credentials\CredentialRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Pure decision helpers that keep passkey enforcement from locking anyone out.
 * Enforcement is added later; these are the preflight checks it must run before
 * requiring a passkey for a user.
 */
final class LockoutGuard {

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Does the user have at least one registered passkey?
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function user_has_passkey( int $user_id ): bool {
		// Only a usable passkey counts. A suspended one cannot sign anyone in, so
		// treating it as "has a passkey" would let enforcement (or the disabled
		// password login) lock the user out with nothing to log in with.
		return array() !== $this->repository->find_active_by_user( $user_id );
	}

	/**
	 * Is it safe to require a passkey for this user right now? Only when they
	 * already have one registered — otherwise enforcement would lock them out.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function can_enforce_for_user( int $user_id ): bool {
		if ( Bypass::active() ) {
			return false;
		}
		// The last administrator is never enforced, so this helper is safe to use
		// as a standalone preflight without repeating the check at the call site.
		if ( $this->is_last_administrator( $user_id ) ) {
			return false;
		}
		return $this->user_has_passkey( $user_id );
	}

	/**
	 * Is this user the only remaining administrator? Used to refuse enforcement
	 * (or password disabling) that could lock the site's last admin out.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public function is_last_administrator( int $user_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		$multisite  = is_multisite();
		$is_super   = $multisite && function_exists( 'is_super_admin' ) && is_super_admin( $user_id );
		$is_admin   = in_array( 'administrator', (array) $user->roles, true ) || $is_super;
		if ( ! $is_admin ) {
			return false;
		}

		if ( ! $multisite ) {
			// Single site: two is enough to know we are not the last one.
			$admins = get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'number' => 2 ) );
			return count( $admins ) <= 1;
		}

		// Multisite: count everyone who can still administer this site, including
		// super admins, who may administer a subsite without holding its local
		// administrator role — otherwise the last one could be locked out.
		$admins = array_map( 'intval', (array) get_users( array( 'role' => 'administrator', 'fields' => 'ID' ) ) );
		if ( function_exists( 'get_super_admins' ) ) {
			foreach ( (array) get_super_admins() as $login ) {
				$super = get_user_by( 'login', $login );
				if ( $super ) {
					$admins[] = (int) $super->ID;
				}
			}
		}
		return count( array_unique( $admins ) ) <= 1;
	}
}
