<?php
/**
 * Lockout prevention helpers.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Recovery;

use RaplsPasskey\Credentials\CredentialRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

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
		return array() !== $this->repository->find_by_user( $user_id );
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
		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return false;
		}
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => 2,
			)
		);
		return count( $admins ) <= 1;
	}
}
