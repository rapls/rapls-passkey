<?php
/**
 * Shared pre-login authorization gate for every passkey/alternative login path.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

use WP_Error;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Passkey, QR, magic-link and recovery-code logins set the auth cookie directly
 * and so do not pass through WordPress's `authenticate` filter chain that some
 * security/membership plugins use to block a user (locked, suspended, must
 * verify email, …). This gate gives those integrations one place to veto a
 * sign-in regardless of the method used, and should be consulted right before
 * the auth cookie is set.
 *
 * It also re-applies the two checks core itself puts in that chain on multisite —
 * spam user and spam primary site — which would otherwise be skipped entirely by
 * these login paths.
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
		// WordPress's own multisite check comes FIRST, before any of our filters.
		// A normal password login reaches it through the `authenticate` chain (core
		// registers it there at priority 99); these logins set the cookie directly,
		// so without this a user marked as spam on a network — or one whose primary
		// site is — could still sign in with a passkey, a QR approval, a magic link
		// or a recovery code. Core's rule wins over anything a site filter allows.
		if ( function_exists( 'wp_authenticate_spam_check' ) ) {
			$spam = wp_authenticate_spam_check( $user );
			if ( $spam instanceof WP_Error ) {
				return $spam;
			}
		}
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
