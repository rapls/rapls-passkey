<?php
/**
 * Single chokepoint for completing an alternative-method login.
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
 * Every passwordless sign-in path (passkey, QR cross-device, magic link,
 * recovery code, sign-up) ends by setting the WordPress auth cookie. Routing
 * them all through here guarantees the same policy is applied each time and a
 * new path cannot forget a step:
 *
 *  - the {@see LoginGate} veto (so account-blocking integrations are honoured),
 *  - a conservative "remember me" default — never persistent for administrators,
 *  - the standard wp_login plus our after_login signal (for 2FA coexistence,
 *    step-up, session management, …).
 *
 * Callers keep their own audit logging and redirect handling.
 */
final class AuthSession {

	/**
	 * Complete a login for the given user, or refuse it.
	 *
	 * @param WP_User $user     The authenticated user.
	 * @param string  $context  Login context (login|qr-channel|magic-link|recovery-code|signup).
	 * @param bool    $remember Whether to issue a persistent session.
	 * @return WP_Error|null A WP_Error to abort (do not log the user in), or null on success.
	 */
	public static function login( WP_User $user, string $context, bool $remember = false ): ?WP_Error {
		$blocked = LoginGate::check( $user, $context );
		if ( $blocked instanceof WP_Error ) {
			return $blocked;
		}

		// Administrators never get a persistent cookie (shared-PC / theft risk).
		if ( user_can( $user, 'manage_options' ) ) {
			$remember = false;
		}

		/**
		 * Filter the "remember me" flag for an alternative-method login.
		 *
		 * @param bool    $remember Whether to persist the session.
		 * @param WP_User $user     The user.
		 * @param string  $context  Login context.
		 */
		$remember = (bool) apply_filters( 'rapls_passkey/login_remember', $remember, $user, $context );

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, $remember );
		do_action( 'wp_login', $user->user_login, $user );

		/**
		 * Fires after an alternative-method login completes (cookie set).
		 *
		 * @param WP_User $user    The user who logged in.
		 * @param string  $context Login context.
		 */
		do_action( 'rapls_passkey/after_login', $user, $context );

		return null;
	}
}
