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
use RaplsPasskey\Support\RateLimit;
use RaplsPasskey\Support\Settings;
use WP_User;

defined( 'ABSPATH' ) || exit;

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

	/** Gate result: the login may proceed without a second factor. */
	public const GATE_PASS = 'pass';

	/** Gate result: the login must answer a provider's second-factor challenge. */
	public const GATE_CHALLENGE = 'challenge';

	/** Gate result: a 2FA plugin is active but its state is unreadable — refuse. */
	public const GATE_BLOCK = 'block';

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
			try {
				if ( $provider->enabled_for( $user ) ) {
					return $provider;
				}
			} catch ( \Throwable $e ) {
				// A provider that cannot report its state can neither render nor
				// validate a challenge; skip it here. The gate (evaluate()) treats
				// the same condition as a reason to refuse a weak login.
				continue;
			}
		}
		return null;
	}

	/**
	 * Evaluate the second-factor gate for a login, distinguishing three outcomes:
	 * no challenge needed, a challenge is required, or an active 2FA plugin's
	 * state could not be read and the (weaker) login must be refused fail-closed.
	 *
	 * @param WP_User $user    The user signing in.
	 * @param string  $context Login context.
	 * @return string One of GATE_PASS, GATE_CHALLENGE, GATE_BLOCK.
	 */
	public static function evaluate( WP_User $user, string $context, ?bool $user_verified = null ): string {
		// Break-glass: the emergency constant disables enforcement everywhere.
		if ( defined( 'RAPLS_PASSKEY_BYPASS' ) && RAPLS_PASSKEY_BYPASS ) {
			return self::GATE_PASS;
		}
		if ( ! Settings::alt_login_second_factor() ) {
			return self::GATE_PASS;
		}
		if ( ! self::weak_context( $context, $user_verified ) ) {
			return self::GATE_PASS;
		}

		$enabled       = false;
		$indeterminate = false;
		foreach ( self::providers() as $provider ) {
			try {
				if ( $provider->enabled_for( $user ) ) {
					$enabled = true;
					break;
				}
			} catch ( \Throwable $e ) {
				// An active 2FA plugin errored while reporting the user's state.
				$indeterminate = true;
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
					error_log( 'rapls-passkey: second-factor provider unavailable: ' . $e->getMessage() );
				}
			}
		}

		/**
		 * Override whether a second factor is demanded for this login.
		 *
		 * @param bool    $required Whether to challenge.
		 * @param WP_User $user     The user signing in.
		 * @param string  $context  Login context.
		 */
		$required = (bool) apply_filters( 'rapls_passkey/require_second_factor', $enabled, $user, $context );

		if ( $required ) {
			return self::GATE_CHALLENGE;
		}
		// A provider could not tell us the state: fail closed rather than let a weak
		// login skip a second factor the user may actually have configured.
		if ( $indeterminate ) {
			return self::GATE_BLOCK;
		}
		return self::GATE_PASS;
	}

	/**
	 * Must this login answer a second-factor challenge before the cookie is set?
	 *
	 * @param WP_User $user    The user signing in.
	 * @param string  $context Login context (login|qr-channel|magic-link|recovery-code|signup).
	 */
	public static function required( WP_User $user, string $context, ?bool $user_verified = null ): bool {
		return self::GATE_CHALLENGE === self::evaluate( $user, $context, $user_verified );
	}

	/**
	 * Is this login weaker than a passkey (so it must still pass the site's 2FA)?
	 *
	 * Magic link and recovery code are never backed by an authenticator. A passkey
	 * ceremony (login / QR / sign-up) IS the second factor — but ONLY if it
	 * performed user verification (biometric/PIN): a passkey verified without UV is
	 * possession-only (one factor), so for MFA it counts as weak and must still meet
	 * the site's 2FA. `$user_verified === false` marks that case; null means
	 * "not applicable / do not downgrade".
	 *
	 * @param string    $context       Login context.
	 * @param bool|null $user_verified Whether a passkey login performed UV.
	 */
	public static function weak_context( string $context, ?bool $user_verified = null ): bool {
		/**
		 * Login contexts that are not backed by a WebAuthn ceremony.
		 *
		 * @param string[] $contexts Context names.
		 */
		$weak = (array) apply_filters( 'rapls_passkey/second_factor_contexts', array( 'magic-link', 'recovery-code' ) );

		if ( in_array( $context, $weak, true ) ) {
			return true;
		}

		// A passkey login/QR/sign-up that did NOT perform user verification is a
		// single factor; treat it as weak so the site's 2FA still applies.
		if ( false === $user_verified && in_array( $context, array( 'login', 'qr-channel', 'signup' ), true ) ) {
			return true;
		}

		return false;
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
	 * @return string URL of the challenge screen, or '' when the parked login could
	 *                not be stored — the caller must then refuse the sign-in rather
	 *                than send the user to a challenge that can never be answered.
	 */
	public static function begin( WP_User $user, string $context, bool $remember ): string {
		$token = bin2hex( random_bytes( 32 ) );

		$stored = set_transient(
			self::TRANSIENT . self::hash( $token ),
			array(
				'user_id'  => (int) $user->ID,
				'context'  => $context,
				'remember' => (bool) $remember,
				'redirect' => self::requested_redirect(),
			),
			self::TTL
		);
		if ( ! $stored ) {
			// Nothing to answer the challenge against. The first factor has already
			// been spent by now (a magic link consumed, a recovery code used up), so
			// sending the user onward would strand them on a screen that cannot
			// complete — and the code they spent is gone either way.
			return '';
		}

		// THE COOKIE HAS TO ACTUALLY GO OUT.
		//
		// Writing $_COOKIE only makes it look present to the rest of THIS request;
		// the browser gets nothing, so the challenge screen has no token to
		// recognise. The first factor is already spent by this point — a magic link
		// consumed, a recovery code used up — so the user would be sent to a screen
		// they cannot complete, with the code they spent gone. Refuse instead, and
		// take the pending record with it so nothing is left half-made.
		$sent = \RaplsPasskey\Support\Cookies::set(
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
		if ( ! $sent ) {
			delete_transient( self::TRANSIENT . self::hash( $token ) );
			return '';
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
	 * Claim one attempt at the second factor, BEFORE the answer is checked.
	 *
	 * The provider used to be asked first and the failure counted afterwards, so
	 * simultaneous submissions all had their code validated and only then queued
	 * up to be counted: the five-attempt budget bounded how many wrong answers
	 * were recorded, not how many were checked (V49-A04).
	 *
	 * The claim is a uniquely-indexed row, so the budget is decided by the write
	 * and not by a total that was read. A claim that cannot be confirmed returns
	 * 0, which discards the pending login — fail closed. Keyed by the
	 * pending-login token, so it follows that login and nothing else.
	 *
	 * @return string The claim token, or '' when there is nothing left to claim
	 *                (the pending login has been discarded).
	 */
	public static function claim_attempt(): string {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return '';
		}

		$key     = self::TRANSIENT . self::hash( $token );
		$pending = get_transient( $key );
		if ( ! is_array( $pending ) ) {
			return '';
		}

		$claim = RateLimit::admit_claim( '2fa_attempts|' . self::hash( $token ), self::TTL, self::MAX_ATTEMPTS );
		if ( 0 === $claim['slot'] ) {
			self::forget();
			return '';
		}
		if ( $claim['slot'] >= self::MAX_ATTEMPTS ) {
			// The last attempt is still checked — it is the fifth try, not a sixth.
			// The parked login is discarded by the caller once it has been checked.
		}
		return $claim['token'];
	}

	/**
	 * Give back an attempt that turned out to be right.
	 *
	 * Only this submission's own: the pending login is discarded on success
	 * anyway, but a wrong answer being checked alongside it must keep its slot.
	 *
	 * @param string $claim The token from claim_attempt().
	 * @return void
	 */
	public static function forgive_attempt( string $claim ): void {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( '' === $claim || 1 !== preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			return;
		}
		RateLimit::forgive( '2fa_attempts|' . self::hash( $token ), $claim );
	}

	/**
	 * Was the claim just taken the last attempt this login allows?
	 *
	 * @param string $claim The token from claim_attempt().
	 * @return bool
	 */
	public static function was_last_attempt( string $claim ): bool {
		$parts = explode( '|', $claim );
		return 3 === count( $parts ) && (int) $parts[1] >= self::MAX_ATTEMPTS;
	}

	/**
	 * Discard the pending login (answered, spent, or abandoned).
	 */
	public static function forget(): void {
		$token = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( 1 === preg_match( '/^[a-f0-9]{64}$/', $token ) ) {
			delete_transient( self::TRANSIENT . self::hash( $token ) );
			// The pending login is being discarded outright, so every row for it goes.
			RateLimit::purge( '2fa_attempts|' . self::hash( $token ) );
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
