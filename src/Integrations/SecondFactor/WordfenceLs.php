<?php
/**
 * Wordfence Login Security as a second-factor provider.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations\SecondFactor;

use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wordfence Login Security (also bundled inside Wordfence) checks its 2FA code
 * only inside its `authenticate` filter, and keeps no "this session passed 2FA"
 * marker. A passkey sign-in therefore never meets it — which is the intended
 * outcome, a passkey already being phishing-resistant MFA — but the magic-link
 * and recovery-code logins would slip past it just as easily. This adapter puts
 * Wordfence's own check back in front of those.
 *
 * Verification goes through Wordfence's Controller_TOTP, which accepts both a
 * TOTP code and one of its recovery codes, so the user's normal options still
 * work here.
 */
final class WordfenceLs implements Provider {

	/** POST field Wordfence uses for the code on its own login form. */
	public const FIELD = 'wfls-token';

	/**
	 * Is Wordfence Login Security active?
	 */
	public function is_available(): bool {
		return class_exists( '\\WordfenceLS\\Controller_Users' ) && class_exists( '\\WordfenceLS\\Controller_TOTP' );
	}

	/**
	 * Plugin name.
	 */
	public function label(): string {
		return 'Wordfence Login Security';
	}

	/**
	 * Does this user have Wordfence 2FA switched on?
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function enabled_for( WP_User $user ): bool {
		try {
			return (bool) \WordfenceLS\Controller_Users::shared()->has_2fa_active( $user );
		} catch ( \Throwable $e ) {
			// An API change must not lock anyone out: treat as "no second factor".
			return false;
		}
	}

	/**
	 * Wordfence renders its code field as part of the wp-login.php form it owns,
	 * with no reusable entry point, so we render the field it reads.
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function render( WP_User $user ): void {
		unset( $user );
		?>
		<p>
			<label for="<?php echo esc_attr( self::FIELD ); ?>"><?php esc_html_e( 'Two-factor authentication code', 'rapls-passkey' ); ?></label>
			<input type="text" name="<?php echo esc_attr( self::FIELD ); ?>" id="<?php echo esc_attr( self::FIELD ); ?>" class="input" value="" autocomplete="one-time-code" inputmode="numeric" autocapitalize="off" />
		</p>
		<p class="description"><?php esc_html_e( 'Enter the code from your authenticator app, or one of your Wordfence recovery codes.', 'rapls-passkey' ); ?></p>
		<?php
	}

	/**
	 * Hand the code to Wordfence. It returns null when 2FA is off for the user
	 * and false on a bad code, so only an explicit true is a pass.
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function validate( WP_User $user ): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- The challenge screen verifies its own nonce before calling this.
		$code = isset( $_POST[ self::FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::FIELD ] ) ) : '';
		if ( '' === $code ) {
			return false;
		}

		try {
			return true === \WordfenceLS\Controller_TOTP::shared()->validate_2fa( $user, $code );
		} catch ( \Throwable $e ) {
			return false;
		}
	}
}
