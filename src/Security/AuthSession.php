<?php
/**
 * Single chokepoint for completing an alternative-method login.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

use RaplsPasskey\Support\Settings;
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
 *  - the {@see SecondFactor} gate (a magic link or a recovery code must not become
 *    a way around the site's 2FA plugin; a passkey already is the second factor),
 *  - a conservative "remember me" default — never persistent for administrators,
 *  - the standard wp_login plus our after_login signal (for 2FA coexistence,
 *    step-up, session management, …).
 *
 * Callers keep their own audit logging and redirect handling.
 */
final class AuthSession {

	/**
	 * The context of the login currently being completed, for the duration of the
	 * `wp_login` action, and '' at any other time.
	 *
	 * @var string
	 */
	private static string $active_context = '';

	/**
	 * What kind of login is completing right now, as seen from inside `wp_login`.
	 *
	 * WordPress's `wp_login` carries no context, so a listener there cannot tell a
	 * passkey login from a password one. That matters for anything that HOLDS a
	 * password login pending a passkey: without this it would hold the passkey
	 * confirmation too, and the user could never finish. Returns '' outside a
	 * login completed through this class (i.e. an ordinary password login).
	 *
	 * @return string One of login|qr-channel|magic-link|recovery-code|signup, or ''.
	 */
	public static function active_context(): string {
		return self::$active_context;
	}

	/**
	 * Complete a login for the given user, or refuse it.
	 *
	 * @param WP_User   $user          The authenticated user.
	 * @param string    $context       Login context (login|qr-channel|magic-link|recovery-code|signup).
	 * @param bool      $remember      Whether to issue a persistent session.
	 * @param bool      $second_factor Whether a second-factor challenge has already been answered.
	 * @param bool|null $user_verified For a passkey login, whether the assertion had
	 *                                 user verification (biometric/PIN); null when
	 *                                 not applicable (e.g. magic link, recovery code).
	 * @return WP_Error|null A WP_Error to abort (do not log the user in), or null on success.
	 */
	public static function login( WP_User $user, string $context, bool $remember = false, bool $second_factor = false, ?bool $user_verified = null ): ?WP_Error {
		$blocked = LoginGate::check( $user, $context );
		if ( $blocked instanceof WP_Error ) {
			return $blocked;
		}

		// A login weaker than a passkey (magic link, recovery code — and a passkey
		// login that did NOT perform user verification) must still meet the site's
		// 2FA plugin. Park it and send the caller to the challenge BEFORE the cookie
		// is set; the error carries the URL, so a caller that ignores it fails closed.
		if ( ! $second_factor ) {
			$gate = SecondFactor::evaluate( $user, $context, $user_verified );
			if ( SecondFactor::GATE_CHALLENGE === $gate ) {
				$challenge = SecondFactor::begin( $user, $context, $remember );
				if ( '' === $challenge ) {
					// The parked login could not be stored, so the challenge screen
					// would have nothing to complete against. Say so plainly instead of
					// sending the user to a dead end.
					return new WP_Error(
						'rapls_passkey_2fa_unavailable',
						__( 'Two-factor authentication cannot be started right now. Please try again.', 'rapls-passkey' ),
						array( 'status' => 503 )
					);
				}
				return new WP_Error(
					'rapls_passkey_2fa_required',
					__( 'Enter your two-factor authentication code to finish signing in.', 'rapls-passkey' ),
					array(
						'status'   => 403,
						'redirect' => $challenge,
					)
				);
			}
			// The site's 2FA plugin is active but its state could not be read. Refuse
			// this weaker login rather than let it bypass a second factor the user may
			// have — a passkey (or password) login is unaffected and remains available.
			if ( SecondFactor::GATE_BLOCK === $gate ) {
				return new WP_Error(
					'rapls_passkey_2fa_unavailable',
					__( 'Two-factor authentication cannot be verified right now. Please sign in with your passkey or password.', 'rapls-passkey' ),
					array( 'status' => 503 )
				);
			}
		}

		// Administrators never get a persistent cookie (shared-PC / theft risk),
		// unless an administrator has explicitly opted in via the setting.
		$is_admin        = user_can( $user, 'manage_options' );
		$force_admin_off = $is_admin && ! Settings::admin_remember_allowed();
		if ( $force_admin_off ) {
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

		// Enforce the administrator rule again: the filter must not be able to
		// re-grant a persistent session to a privileged account (unless opted in).
		if ( $force_admin_off ) {
			$remember = false;
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, $remember );

		// Publish the context BEFORE wp_login, and keep it published for the whole
		// action. Listeners on wp_login (ours and other plugins') otherwise see a
		// passkey login as indistinguishable from a password login.
		self::$active_context = $context;

		/**
		 * Fires immediately before `wp_login`, with the context this login has.
		 *
		 * @param WP_User $user    The user logging in.
		 * @param string  $context Login context.
		 */
		do_action( 'rapls_passkey/before_login', $user, $context );

		do_action( 'wp_login', $user->user_login, $user );
		self::$active_context = '';

		/**
		 * Fires after an alternative-method login completes (cookie set).
		 *
		 * @param WP_User   $user          The user who logged in.
		 * @param string    $context       Login context.
		 * @param bool|null $user_verified Whether a passkey login performed user
		 *                                 verification (null when not applicable).
		 */
		do_action( 'rapls_passkey/after_login', $user, $context, $user_verified );

		return null;
	}
}
