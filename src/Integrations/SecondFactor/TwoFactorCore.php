<?php
/**
 * The Automattic "Two-Factor" plugin as a second-factor provider.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations\SecondFactor;

use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * The Two-Factor plugin is provider-based (TOTP, email, backup codes, …), and each
 * provider knows how to draw its own challenge and how to check the answer. We
 * borrow the user's primary provider rather than re-implementing any of it, so
 * whatever the user has configured is what they are asked for here.
 *
 * A passkey sign-in is separately marked as 2FA-verified (see Integrations\TwoFactor);
 * this adapter is only used for the weaker alternative logins.
 */
final class TwoFactorCore implements Provider {

	/**
	 * Is the Two-Factor plugin active?
	 */
	public function is_available(): bool {
		return class_exists( '\\Two_Factor_Core' );
	}

	/**
	 * Plugin name.
	 */
	public function label(): string {
		return 'Two-Factor';
	}

	/**
	 * Has the user enabled a second factor?
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function enabled_for( WP_User $user ): bool {
		try {
			$using = (bool) \Two_Factor_Core::is_user_using_two_factor( $user->ID );
		} catch ( \Throwable $e ) {
			// The message is a literal; $e is the previous exception, not output.
			// phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
			throw new ProviderUnavailable( 'Two-Factor status could not be read.', 0, $e );
		}
		if ( ! $using ) {
			return false;
		}
		// The user has a second factor, but if we cannot resolve a usable provider
		// to challenge with, fail closed rather than let a weak login through.
		if ( null === $this->provider( $user ) ) {
			throw new ProviderUnavailable( 'Two-Factor primary provider could not be resolved.' );
		}
		return true;
	}

	/**
	 * Draw the primary provider's own challenge.
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function render( WP_User $user ): void {
		$provider = $this->provider( $user );
		if ( null === $provider ) {
			return;
		}

		try {
			// Give the provider its chance to act before being shown — the email
			// provider sends the code from here.
			if ( method_exists( $provider, 'pre_process_authentication' ) ) {
				$provider->pre_process_authentication( $user );
			}
			// Providers call submit_button(), an admin-only function that
			// wp-login.php does not load (Two_Factor_Core does the same require).
			require_once ABSPATH . 'wp-admin/includes/template.php';
			$provider->authentication_page( $user );
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Let the provider check its own answer.
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function validate( WP_User $user ): bool {
		$provider = $this->provider( $user );
		if ( null === $provider ) {
			return false;
		}

		try {
			return true === $provider->validate_authentication( $user );
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * The user's primary Two-Factor provider, if any.
	 *
	 * @param WP_User $user The user signing in.
	 * @return object|null
	 */
	private function provider( WP_User $user ): ?object {
		try {
			$provider = \Two_Factor_Core::get_primary_provider_for_user( $user->ID );
		} catch ( \Throwable $e ) {
			return null;
		}
		if ( ! is_object( $provider ) || ! method_exists( $provider, 'validate_authentication' ) || ! method_exists( $provider, 'authentication_page' ) ) {
			return null;
		}
		return $provider;
	}
}
