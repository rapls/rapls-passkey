<?php
/**
 * Shared pre-login authorization gate for every passkey/alternative login path.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Passkey, QR, magic-link and recovery-code logins set the auth cookie directly
 * and so do not pass through WordPress's `authenticate` filter chain that some
 * security/membership plugins use to block a user (locked, suspended, must
 * verify email, …). This gate gives those integrations one place to veto a
 * sign-in regardless of the method used, and should be consulted right before
 * the auth cookie is set.
 */
final class LoginGate {

	/**
	 * Decide whether the given user may sign in via an alternative method.
	 *
	 * @param WP_User $user    The user about to be signed in.
	 * @param string  $context Login context (e.g. 'login', 'qr-channel', 'magic-link', 'recovery-code').
	 * @return WP_Error|null A WP_Error to deny, or null to allow.
	 */
	public static function check( WP_User $user, string $context = '' ): ?WP_Error {
		/**
		 * Filter whether a user may complete a passkey / alternative-method login.
		 *
		 * Return false or a WP_Error to deny (so integrations that block users via
		 * the core `authenticate` filter can apply the same block here). Default
		 * allows the login.
		 *
		 * @param bool|WP_Error $allowed True to allow; false or WP_Error to deny.
		 * @param WP_User       $user    The user about to be signed in.
		 * @param string        $context Login context.
		 */
		$allowed = apply_filters( 'rapls_passkey/allow_login', true, $user, $context );

		if ( $allowed instanceof WP_Error ) {
			return $allowed;
		}
		if ( false === $allowed ) {
			return new WP_Error(
				'rapls_passkey_login_blocked',
				__( 'You cannot sign in to this account right now.', 'rapls-passkey' ),
				array( 'status' => 403 )
			);
		}
		return null;
	}
}
