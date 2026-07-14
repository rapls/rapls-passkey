<?php
/**
 * Plugin settings accessor.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads the single options array with sane defaults. The admin UI lives in
 * Admin\SettingsPage; this is the read side used across the plugin.
 */
final class Settings {

	/** Option key. */
	public const OPTION = 'rapls_passkey_settings';

	/**
	 * Defaults for every setting.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults(): array {
		return array(
			'recaptcha_enabled'    => false,
			'recaptcha_site_key'   => '',
			'recaptcha_secret_key' => '',
			'recaptcha_threshold'  => 0.5,
			'audit_enabled'        => true,
			// Max passkeys a user may register (0 = unlimited).
			'max_passkeys'         => 0,
			// Per-IP login rate limit: failed attempts allowed within the window,
			// and the window / lockout length in seconds. Successful logins do not
			// count (the counter is cleared on success).
			'login_rate_max'       => 30,
			'login_rate_window'    => 300,
			// Allow administrators to hold a persistent ("remember me") session on
			// a passkey/alternative login. Off by default: shared-PC / theft risk.
			'admin_remember_allowed' => false,
			// Ask for the site's 2FA code on the logins that are weaker than a
			// passkey (magic link, recovery code), so they cannot bypass it.
			'alt_login_second_factor' => true,
			// Email the user on passkey registration/removal and new-device sign-in.
			'notifications_enabled' => true,
			// Offer to create a passkey right after an interactive (password) login.
			'upgrade_prompt_enabled' => true,
			// WebAuthn ceremony tuning.
			'webauthn_timeout'           => 60,         // seconds; 0 = browser/library default.
			'webauthn_user_verification' => 'preferred', // required | preferred | discouraged.
			'webauthn_attachment'        => '',          // '' = any | platform | cross-platform.
			// Client UI hints (subset of: security-key, client-device, hybrid).
			'webauthn_hints'             => array(),
		);
	}

	/**
	 * The full settings array, merged over defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function all(): array {
		$stored = get_option( self::OPTION, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		return array_merge( self::defaults(), $stored );
	}

	/**
	 * Get one setting.
	 *
	 * @param string $key Setting key.
	 * @return mixed
	 */
	public static function get( string $key ) {
		$all = self::all();
		return $all[ $key ] ?? null;
	}

	/**
	 * reCAPTCHA site key.
	 *
	 * @return string
	 */
	public static function recaptcha_site_key(): string {
		return (string) self::get( 'recaptcha_site_key' );
	}

	/**
	 * reCAPTCHA secret key.
	 *
	 * @return string
	 */
	public static function recaptcha_secret_key(): string {
		return \RaplsPasskey\Security\Secret::decrypt( (string) self::get( 'recaptcha_secret_key' ) );
	}

	/**
	 * Minimum acceptable reCAPTCHA v3 score (0.0–1.0).
	 *
	 * @return float
	 */
	public static function recaptcha_threshold(): float {
		return (float) self::get( 'recaptcha_threshold' );
	}

	/**
	 * Whether reCAPTCHA should run: enabled, both keys present, and not vetoed
	 * by a third party (e.g. a security plugin already providing a CAPTCHA).
	 *
	 * @return bool
	 */
	public static function recaptcha_active(): bool {
		$active = (bool) self::get( 'recaptcha_enabled' )
			&& '' !== self::recaptcha_site_key()
			&& '' !== self::recaptcha_secret_key();

		/**
		 * Filter whether the plugin's reCAPTCHA runs. Return false to defer to
		 * another plugin's login CAPTCHA and avoid a double challenge.
		 *
		 * @param bool $active Whether reCAPTCHA is active.
		 */
		return (bool) apply_filters( 'rapls_passkey_recaptcha_active', $active );
	}

	/**
	 * Whether audit logging is on.
	 *
	 * @return bool
	 */
	public static function audit_enabled(): bool {
		return (bool) self::get( 'audit_enabled' );
	}

	/**
	 * Whether security notification emails (registration, removal, new-device
	 * sign-in) are sent to the affected user.
	 *
	 * @return bool
	 */
	public static function notifications_enabled(): bool {
		$enabled = (bool) self::get( 'notifications_enabled' );

		/**
		 * Filter whether the plugin sends security notification emails.
		 *
		 * @param bool $enabled Whether notifications are enabled.
		 */
		return (bool) apply_filters( 'rapls_passkey_notifications_enabled', $enabled );
	}

	/**
	 * Whether to offer creating a passkey right after an interactive password
	 * login (the post-login "upgrade" prompt).
	 *
	 * @return bool
	 */
	public static function upgrade_prompt_enabled(): bool {
		$enabled = (bool) self::get( 'upgrade_prompt_enabled' );

		/**
		 * Filter whether the post-login passkey upgrade prompt is shown.
		 *
		 * @param bool $enabled Whether the upgrade prompt is enabled.
		 */
		return (bool) apply_filters( 'rapls_passkey_upgrade_prompt_enabled', $enabled );
	}

	/**
	 * WebAuthn ceremony timeout in milliseconds, or null for the library/browser
	 * default. Stored in seconds for a friendlier admin field.
	 *
	 * @return int|null
	 */
	public static function webauthn_timeout(): ?int {
		$ms = (int) self::get( 'webauthn_timeout' ) * 1000;

		/**
		 * Filter the WebAuthn ceremony timeout (milliseconds; 0 = default).
		 *
		 * @param int $ms Timeout in milliseconds.
		 */
		$ms = (int) apply_filters( 'rapls_passkey_webauthn_timeout', $ms );

		return $ms > 0 ? $ms : null;
	}

	/**
	 * User-verification requirement: required | preferred | discouraged.
	 *
	 * @return string
	 */
	public static function webauthn_user_verification(): string {
		$uv = (string) self::get( 'webauthn_user_verification' );

		/**
		 * Filter the user-verification requirement.
		 *
		 * @param string $uv One of required|preferred|discouraged.
		 */
		$uv = (string) apply_filters( 'rapls_passkey_user_verification', $uv );

		return in_array( $uv, array( 'required', 'preferred', 'discouraged' ), true ) ? $uv : 'preferred';
	}

	/**
	 * Authenticator attachment preference for registration: null (any),
	 * 'platform', or 'cross-platform'.
	 *
	 * @return string|null
	 */
	public static function webauthn_attachment(): ?string {
		$attachment = (string) self::get( 'webauthn_attachment' );

		/**
		 * Filter the authenticator attachment preference.
		 *
		 * @param string $attachment '' (any), 'platform', or 'cross-platform'.
		 */
		$attachment = (string) apply_filters( 'rapls_passkey_authenticator_attachment', $attachment );

		return in_array( $attachment, array( 'platform', 'cross-platform' ), true ) ? $attachment : null;
	}

	/**
	 * WebAuthn client UI hints, a validated subset of security-key,
	 * client-device, hybrid (order preserved). Empty = no hint.
	 *
	 * @return string[]
	 */
	public static function webauthn_hints(): array {
		$valid = array( 'security-key', 'client-device', 'hybrid' );
		$hints = self::get( 'webauthn_hints' );
		$hints = is_array( $hints ) ? array_values( array_filter( $hints, static function ( $h ) use ( $valid ) {
			return in_array( $h, $valid, true );
		} ) ) : array();

		/**
		 * Filter the WebAuthn client UI hints.
		 *
		 * @param string[] $hints Hint strings.
		 */
		$hints = (array) apply_filters( 'rapls_passkey_webauthn_hints', $hints );

		return array_values( array_filter( $hints, static function ( $h ) use ( $valid ) {
			return in_array( $h, $valid, true );
		} ) );
	}

	/**
	 * Maximum passkeys a single user may register (0 = unlimited).
	 *
	 * @return int
	 */
	public static function max_passkeys(): int {
		$max = (int) self::get( 'max_passkeys' );

		/**
		 * Filter the per-user passkey registration limit.
		 *
		 * @param int $max Maximum passkeys per user (0 = unlimited).
		 */
		$max = (int) apply_filters( 'rapls_passkey_max_passkeys', $max );

		return max( 0, $max );
	}

	/**
	 * Number of login attempts allowed per IP within the window before the
	 * "too many attempts" lockout. Successful logins do not count toward it.
	 * A value of 0 disables the limit. Minimum of 1 otherwise.
	 *
	 * @return int
	 */
	public static function login_rate_max(): int {
		$max = (int) self::get( 'login_rate_max' );

		/**
		 * Filter the per-IP login attempt limit.
		 *
		 * @param int $max Attempts allowed per window (0 = no limit).
		 */
		$max = (int) apply_filters( 'rapls_passkey_login_rate_max', $max );

		return max( 0, $max );
	}

	/**
	 * The login rate-limit window / lockout length in seconds.
	 *
	 * @return int
	 */
	public static function login_rate_window(): int {
		$window = (int) self::get( 'login_rate_window' );
		if ( $window < 1 ) {
			$window = 300;
		}

		/**
		 * Filter the login rate-limit window (lockout length) in seconds.
		 *
		 * @param int $window Window length in seconds.
		 */
		$window = (int) apply_filters( 'rapls_passkey_login_rate_window', $window );

		return max( 1, $window );
	}

	/**
	 * Whether administrators may hold a persistent ("remember me") session on a
	 * passkey / alternative-method login. Off by default (the secure choice):
	 * administrators never get a persistent cookie, to limit shared-PC / theft
	 * risk. Turn it on to honour the "remember me" checkbox for administrators too.
	 *
	 * @return bool
	 */
	public static function admin_remember_allowed(): bool {
		$allowed = (bool) self::get( 'admin_remember_allowed' );

		/**
		 * Filter whether administrators may hold a persistent session.
		 *
		 * @param bool $allowed Whether administrators may be remembered.
		 */
		return (bool) apply_filters( 'rapls_passkey_admin_remember_allowed', $allowed );
	}

	/**
	 * Whether the alternative logins that are not backed by a WebAuthn ceremony
	 * (magic link, recovery code) must still answer the site's 2FA challenge.
	 *
	 * On by default: those paths skip the wp-login.php authenticate chain, which is
	 * the only place 2FA plugins enforce, so leaving this off makes them a way
	 * around the site's 2FA. It only ever challenges users who have a second factor
	 * configured, and RAPLS_PASSKEY_BYPASS disables it along with all enforcement.
	 *
	 * @return bool
	 */
	public static function alt_login_second_factor(): bool {
		$required = (bool) self::get( 'alt_login_second_factor' );

		/**
		 * Filter whether weaker alternative logins must pass the site's 2FA.
		 *
		 * @param bool $required Whether to challenge.
		 */
		return (bool) apply_filters( 'rapls_passkey_alt_login_second_factor', $required );
	}
}
