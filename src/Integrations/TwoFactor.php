<?php
/**
 * Coexistence with two-factor authentication plugins.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations;

use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * A passkey is itself phishing-resistant multi-factor authentication (something
 * you have + the authenticator's user verification), so a passkey sign-in should
 * not trigger a second 2FA challenge.
 *
 * Because the plugin completes login over REST (wp_set_auth_cookie + wp_login)
 * rather than through the wp-login.php `authenticate` chain, 2FA plugins that
 * gate that chain are already skipped. The remaining gap is the Automattic
 * Two-Factor plugin, which marks each *session* as 2FA-verified and may
 * otherwise treat a passkey session as incomplete. This shim marks the freshly
 * created session as verified so the two play nicely.
 *
 * The work is best-effort and fully guarded: it only runs when Two-Factor is
 * present, never fatals, and degrades to "no integration" (the status quo) on
 * any error.
 */
final class TwoFactor {

	/**
	 * Session token from the auth cookie just issued during login, captured so
	 * the matching session can be marked within the same request.
	 *
	 * @var string
	 */
	private string $token = '';

	/**
	 * Hook the capture + marking points.
	 */
	public function register(): void {
		add_action( 'set_logged_in_cookie', array( $this, 'capture_token' ), 10, 6 );
		add_action( 'rapls_passkey/after_login', array( $this, 'mark_session' ), 10, 3 );
	}

	/**
	 * Capture the session token from the logged-in cookie WordPress just set.
	 *
	 * @param string $cookie     The logged-in cookie value (unused).
	 * @param int    $expire     Cookie expiry (unused).
	 * @param int    $expiration Session expiry (unused).
	 * @param int    $user_id    User id (unused).
	 * @param string $scheme     Cookie scheme (unused).
	 * @param string $token      Session token.
	 */
	public function capture_token( $cookie, $expire, $expiration, $user_id, $scheme, $token = '' ): void {
		if ( is_string( $token ) && '' !== $token ) {
			$this->token = $token;
		}
	}

	/**
	 * Mark the current session as 2FA-verified for the Automattic Two-Factor
	 * plugin, so a passkey login is not re-challenged.
	 *
	 * @param WP_User   $user          The user who just logged in.
	 * @param string    $context       Login context ('login', 'qr-channel', …).
	 * @param bool|null $user_verified Whether a passkey login performed user
	 *                                 verification; null when not applicable.
	 */
	public function mark_session( $user, $context = '', $user_verified = null ): void {
		// A DIRECT passkey login only counts as the second factor if the
		// authenticator performed user verification (biometric/PIN) — possession
		// alone is a single factor. Contexts that reach here another way (magic
		// link, recovery code) already cleared the site's 2FA gate, and step-up/QR
		// force UV, so only the plain 'login' path is gated on the UV result.
		if ( 'login' === (string) $context && true !== $user_verified ) {
			return;
		}

		if ( ! class_exists( '\\Two_Factor_Core' ) || ! class_exists( '\\WP_Session_Tokens' ) ) {
			return;
		}
		if ( ! $user instanceof WP_User || '' === $this->token ) {
			return;
		}

		/**
		 * Allow disabling the Two-Factor session marking (e.g. a site that wants
		 * to require its own 2FA even after a passkey login).
		 *
		 * @param bool    $enabled Whether to mark the session as 2FA-verified.
		 * @param WP_User $user    The user.
		 */
		if ( ! apply_filters( 'rapls_passkey_satisfies_2fa', true, $user ) ) {
			return;
		}

		try {
			$manager = \WP_Session_Tokens::get_instance( (int) $user->ID );
			$session = $manager->get( $this->token );
			if ( ! is_array( $session ) ) {
				return;
			}
			// Keys used by Automattic Two-Factor to recognise a verified session.
			$session['two-factor-login']    = time();
			$session['two-factor-provider'] = 'RaplsPasskey_WebAuthn';
			$manager->update( $this->token, $session );
		} catch ( \Throwable $e ) {
			// Best-effort only: fall back to the plugin's normal behaviour.
			return;
		}
	}
}
