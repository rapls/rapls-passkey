<?php
/**
 * Second-factor gate for the alternative (non-passkey) logins.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

use RaplsPasskey\Integrations\SecondFactor\Provider;
use RaplsPasskey\Integrations\SecondFactor\TwoFactorCore;
use RaplsPasskey\Integrations\SecondFactor\WordfenceLs;
use RaplsPasskey\Support\Settings;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * 2FA plugins (Wordfence Login Security, Two-Factor, …) enforce the second factor
 * inside the wp-login.php `authenticate` chain. Passkey sign-in deliberately does
 * not enter that chain: a passkey is already phishing-resistant MFA, so being
 * asked for a TOTP code on top of it is pure friction.
 *
 * The alternative logins are a different story. A magic link is only as strong as
 * an inbox, and a recovery code is a bearer secret. Both skip the same chain, so
 * without this gate they would be a way around the site's 2FA — sign in by email,
 * skip the code. This puts the site's own 2FA challenge back in front of them.
 *
 * Not a lockout risk: the challenge appears only for users who have actually
 * configured a second factor, and RAPLS_PASSKEY_BYPASS switches it off entirely
 * along with the rest of the enforcement.
 */
final class SecondFactor {

	/** Cookie holding the pending-login token (the token itself is never stored). */
	public const COOKIE = 'rapls_pk_2fa';

	/** wp-login.php action for the challenge screen. */
	public const ACTION = 'rapls_passkey_2fa';

	/** Transient prefix for the pending login. */
	private const TRANSIENT = 'rapls_passkey_2fa_';

	/** How long the visitor has to answer the challenge, in seconds. */
	private const TTL = 600;

	/** Wrong answers allowed before the pending login is thrown away. */
	private const MAX_ATTEMPTS = 5;

	/**
	 * Adapters for the 2FA plugins we can challenge against.
	 *
	 * @return Provider[] Only those whose plugin is actually active.
	 */
	public static function providers(): array {
		$providers = array(
			new WordfenceLs(),
			new TwoFactorCore(),
		);

		/**
		 * Register an adapter for another 2FA plugin.
		 *
		 * @param Provider[] $providers Second-factor adapters.
		 */
		$providers = (array) apply_filters( 'rapls_passkey/second_factor_providers', $providers );

		return array_values(
			array_filter(
				$providers,
				static function ( $provider ) {
					return $provider instanceof Provider && $provider->is_available();
				}
			)
		);
	}

	/**
	 * The adapter that will challenge this user, or null when no active 2FA plugin
	 * has a second factor configured for them.
	 *
	 * @param WP_User $user The user signing in.
	 * @return Provider|null
	 */
	public static function provider_for( WP_User $user ): ?Provider {
		foreach ( self::providers() as $provider ) {
			if ( $provider->enabled_for( $user ) ) {
				return $provider;
			}
		}
		return null;
	}

	/**
	 * Must this login answer a second-factor challenge before the cookie is set?
	 *
	 * @param WP_User $user    The user signing in.
	 * @param string  $context Login context (login|qr-channel|magic-link|recovery-code|signup).
	 */
	public static function required( WP_User $user, string $context ): bool {
		// Break-glass: the emergency constant disables enforcement everywhere.
		if ( defined( 'RAPLS_PASSKEY_BYPASS' ) && RAPLS_PASSKEY_BYPASS ) {
			return false;
		}
		if ( ! Settings::alt_login_second_factor() ) {
			return false;
		}
		if ( ! self::weak_context( $context ) ) {
			return false;
		}

		$required = null !== self::provider_for( $user );

		/**
		 * Override whether a second factor is demanded for this login.
		 *
		 * @param bool    $required Whether to challenge.
		 * @param WP_User $user     The user signing in.
		 * @param string  $context  Login context.
		 */
		return (bool) apply_filters( 'rapls_passkey/require_second_factor', $required, $user, $context );
	}

	/**
	 * Is this login weaker than a passkey?
	 *
	 * Passkey, QR cross-device (the phone signs a WebAuthn assertion) and sign-up
	 * (a passkey is created and verified) are all backed by an authenticator, so
	 * they *are* the second factor. Magic link and recovery code are not.
	 *
	 * @param string $context Login context.
	 */
	public static function weak_context( string $context ): bool {
		/**
		 * Login contexts that are not backed by a WebAuthn ceremony.
		 *
		 * @param string[] $contexts Context names.
		 */
		$weak = (array) apply_filters( 'rapls_passkey/second_factor_contexts', array( 'magic-link', 'recovery-code' ) );

		return in_array( $context, $weak, true );
	}

	/**
	 * Park the verified-but-incomplete login and return the challenge URL.
	 *
	 * Only a hash of the token is stored, so a leaked database row cannot be
	 * replayed into a session.
	 *
	 * @param WP_User $user     The user signing in.
	 * @param string  $context  Login context.
	 * @param bool    $remember Whether the session should be persistent.
	 * @return string URL of the challenge screen.
	 */
	public static function begin( WP_User $user, string $context, bool $remember ): string {
		$token = bin2hex( random_bytes( 32 ) );

		set_transient(
			self::TRANSIENT . self::hash( $token ),
			array(
				'user_id'  => (int) $user->ID,
				'context'  => $context,
				'remember' => (bool) $remember,
				'redirect' => self::requested_redirect(),
				'attempts' => 0,
			),
			self::TTL
		);

		if ( ! headers_sent() ) {
			setcookie(
				self::COOKIE,
				$token,
				array(
					'expires'  => time() + self::TTL,
					'path'     => defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
		$_COOKIE[ self::COOKIE ] = $token;

		return add_query_arg( 'action', self::ACTION, wp_login_url() );
	}

	/**
	 * The parked login for the current browser, or null.
	 *
	 * @return array{user_id:int,context:string,remember:bool,redirect:string,attempts:int}|null
	 */
	public static function pending(): ?array {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return null;
		}

		$pending = get_transient( self::TRANSIENT . self::hash( $token ) );
		if ( ! is_array( $pending ) || empty( $pending['user_id'] ) ) {
			return null;
		}
		return $pending;
	}

	/**
	 * Record a wrong answer. Returns false once the pending login has been spent,
	 * so a recovery code cannot be paired with a brute-forced TOTP code.
	 *
	 * @return bool Whether the visitor may try again.
	 */
	public static function count_failure(): bool {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return false;
		}

		$key     = self::TRANSIENT . self::hash( $token );
		$pending = get_transient( $key );
		if ( ! is_array( $pending ) ) {
			return false;
		}

		$pending['attempts'] = (int) ( $pending['attempts'] ?? 0 ) + 1;
		if ( $pending['attempts'] >= self::MAX_ATTEMPTS ) {
			self::forget();
			return false;
		}

		set_transient( $key, $pending, self::TTL );
		return true;
	}

	/**
	 * Discard the pending login (answered, spent, or abandoned).
	 */
	public static function forget(): void {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( 1 === preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			delete_transient( self::TRANSIENT . self::hash( $token ) );
		}

		unset( $_COOKIE[ self::COOKIE ] );

		if ( ! headers_sent() ) {
			setcookie(
				self::COOKIE,
				'',
				array(
					'expires'  => time() - 3600,
					'path'     => defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/',
					'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}

	/**
	 * Where to send the visitor once the challenge is answered.
	 */
	private static function requested_redirect(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- The caller has already authenticated the first factor.
		$requested = isset( $_REQUEST['redirect_to'] ) ? trim( (string) wp_unslash( $_REQUEST['redirect_to'] ) ) : '';

		// wp_validate_redirect( '', $fallback ) returns '' rather than the fallback,
		// and an empty Location yields a blank page.
		return '' !== $requested ? wp_validate_redirect( $requested, admin_url() ) : admin_url();
	}

	/**
	 * Salted hash of a pending-login token (the raw token is never stored).
	 *
	 * @param string $token Raw token.
	 */
	private static function hash( string $token ): string {
		return hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
	}
}
