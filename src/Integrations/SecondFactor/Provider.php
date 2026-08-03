<?php
/**
 * A two-factor plugin we can challenge against.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations\SecondFactor;

use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Adapter onto a third-party 2FA plugin.
 *
 * 2FA plugins enforce their second factor inside the wp-login.php `authenticate`
 * chain. The plugin's alternative logins (magic link, recovery code) never enter
 * that chain — they validate their own factor and set the auth cookie — so the
 * site's 2FA would silently not apply to them. An adapter lets us put the same
 * challenge in front of those logins, using the 2FA plugin's own verification
 * rather than a re-implementation of it.
 *
 * Register another one with the rapls_passkey/second_factor_providers filter.
 */
interface Provider {

	/**
	 * Is the backing 2FA plugin present?
	 */
	public function is_available(): bool;

	/**
	 * Human-readable plugin name, for the challenge screen and Site Health.
	 */
	public function label(): string;

	/**
	 * Has this user actually set a second factor up? (No second factor
	 * configured means nothing to challenge — we must not lock them out.)
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function enabled_for( WP_User $user ): bool;

	/**
	 * Echo the challenge fields. Called inside our <form>, so do not open one.
	 *
	 * @param WP_User $user The user signing in.
	 */
	public function render( WP_User $user ): void;

	/**
	 * Validate the submitted answer, read from $_POST by the 2FA plugin itself.
	 *
	 * @param WP_User $user The user signing in.
	 * @return bool True only on a positive verification.
	 */
	public function validate( WP_User $user ): bool;
}
