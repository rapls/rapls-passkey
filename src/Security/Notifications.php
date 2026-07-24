<?php
/**
 * Security notification emails for account-level passkey events.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

use RaplsPasskey\Credentials\AuthenticatorNames;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Support\Settings;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Emails the affected user when a passkey is registered or removed, and when a
 * passkey sign-in happens from a device this browser hasn't been seen on before.
 * A break-glass recovery-code login (Pro) is always reported.
 *
 * "New device" is judged by an opaque random cookie token whose HMAC is kept in
 * a small list in user meta (the raw token is never stored) — independent of any
 * Pro device-trust state. The cookie is HttpOnly; because it only gates a
 * notification (never authentication), it is a recognition token, not a
 * security credential.
 */
final class Notifications {

	/** Cookie holding this browser's opaque device token. */
	private const SEEN_COOKIE = 'rapls_pk_seen';

	/** User meta: list of HMACs of known device tokens. */
	public const SEEN_META = 'rapls_pk_seen_devices';

	/** Cap on remembered devices per user. */
	private const SEEN_CAP = 20;

	/**
	 * Hook the event actions.
	 */
	public function register(): void {
		add_action( 'rapls_passkey/credential_registered', array( $this, 'on_registered' ), 10, 3 );
		add_action( 'rapls_passkey/credential_deleted', array( $this, 'on_deleted' ), 10, 3 );
		add_action( 'rapls_passkey/after_login', array( $this, 'on_login' ), 10, 2 );
	}

	/**
	 * Notify on a newly registered passkey.
	 *
	 * @param int         $user_id User the passkey belongs to.
	 * @param int         $cred_id Stored credential row id (unused in the body).
	 * @param string|null $label   Optional passkey label.
	 */
	public function on_registered( $user_id, $cred_id, $label = null ): void {
		if ( ! Settings::notifications_enabled() ) {
			return;
		}
		/** Filter: send the "passkey registered" email? @param bool $send @param int $user_id */
		if ( ! apply_filters( 'rapls_passkey_notify_registered', true, (int) $user_id ) ) {
			return;
		}
		$user = get_user_by( 'id', (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] A new passkey was registered', 'rapls-passkey' ), $this->site_name() );

		$body  = $this->greeting( $user );
		$body .= __( 'A new passkey was registered on your account.', 'rapls-passkey' ) . "\n\n";
		if ( is_string( $label ) && '' !== $label ) {
			/* translators: %s: passkey label. */
			$body .= sprintf( __( 'Name: %s', 'rapls-passkey' ), $label ) . "\n";
		}
		$provider = $this->provider_name( (int) $cred_id );
		if ( null !== $provider ) {
			/* translators: %s: authenticator/provider name (e.g. iCloud Keychain). */
			$body .= sprintf( __( 'Authenticator: %s', 'rapls-passkey' ), $provider ) . "\n";
		}
		$body .= $this->context_lines() . "\n";
		$body .= __( 'If this was not you, change your password immediately and remove any unknown passkeys from your profile screen.', 'rapls-passkey' ) . "\n";

		$this->send( $user, $subject, $body );
	}

	/**
	 * Notify on a removed passkey.
	 *
	 * @param int $user_id  User the passkey belonged to.
	 * @param int $cred_id  Removed credential row id (unused in the body).
	 * @param int $by_admin Admin user id if removed by an administrator, else 0.
	 */
	public function on_deleted( $user_id, $cred_id, $by_admin = 0 ): void {
		unset( $cred_id );
		if ( ! Settings::notifications_enabled() ) {
			return;
		}
		/** Filter: send the "passkey removed" email? @param bool $send @param int $user_id */
		if ( ! apply_filters( 'rapls_passkey_notify_removed', true, (int) $user_id ) ) {
			return;
		}
		$user = get_user_by( 'id', (int) $user_id );
		if ( ! $user instanceof WP_User ) {
			return;
		}

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] A passkey was removed', 'rapls-passkey' ), $this->site_name() );

		$body = $this->greeting( $user );
		if ( (int) $by_admin > 0 ) {
			$body .= __( 'A site administrator removed one passkey from your account.', 'rapls-passkey' ) . "\n\n";
		} else {
			$body .= __( 'One passkey was removed from your account.', 'rapls-passkey' ) . "\n\n";
		}
		$body .= $this->context_lines() . "\n";
		$body .= __( 'If this was not you, change your password immediately.', 'rapls-passkey' ) . "\n";

		$this->send( $user, $subject, $body );
	}

	/**
	 * Notify on a passkey sign-in from a new device (and always for a recovery
	 * code login). Known devices on normal logins stay silent.
	 *
	 * @param mixed  $user    The user who logged in.
	 * @param string $context Login context (e.g. 'login', 'recovery-code').
	 */
	public function on_login( $user, $context = '' ): void {
		if ( ! Settings::notifications_enabled() ) {
			return;
		}
		if ( ! $user instanceof WP_User ) {
			return;
		}
		$context = (string) $context;
		$always  = ( 'recovery-code' === $context );

		/** Filter: send the new-device sign-in email? @param bool $send @param WP_User $user @param string $context */
		if ( ! apply_filters( 'rapls_passkey_notify_new_device', true, $user, $context ) ) {
			// Still remember the device so we don't notify later via another path.
			$this->is_known_device( (int) $user->ID );
			return;
		}

		$known = $this->is_known_device( (int) $user->ID );
		if ( $known && ! $always ) {
			return;
		}

		if ( $always ) {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] You signed in with a recovery code', 'rapls-passkey' ), $this->site_name() );
			$body    = $this->greeting( $user );
			$body   .= __( 'Your account was signed into using a recovery code.', 'rapls-passkey' ) . "\n\n";
		} else {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] New device sign-in', 'rapls-passkey' ), $this->site_name() );
			$body    = $this->greeting( $user );
			$body   .= __( 'Your account was signed into with a passkey from a device or browser not seen before.', 'rapls-passkey' ) . "\n\n";
		}
		$body .= $this->context_lines() . "\n";
		$body .= __( 'If this was not you, change your password immediately and remove any unknown passkeys.', 'rapls-passkey' ) . "\n";

		$this->send( $user, $subject, $body );
	}

	// --- Helpers -------------------------------------------------------------

	/**
	 * Whether this browser is a device we've already seen for the user. Unknown
	 * devices are remembered (cookie + meta) as a side effect.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	private function is_known_device( int $user_id ): bool {
		$list = get_user_meta( $user_id, self::SEEN_META, true );
		$list = is_array( $list ) ? $list : array();

		$token = isset( $_COOKIE[ self::SEEN_COOKIE ] ) ? (string) $_COOKIE[ self::SEEN_COOKIE ] : '';
		if ( 1 !== preg_match( '/^[a-f0-9]{32}$/', $token ) ) {
			$token = '';
		}

		if ( '' !== $token && in_array( self::hash( $token ), $list, true ) ) {
			return true;
		}

		// New (or unrecognised) device: mint a token if needed, remember it.
		if ( '' === $token ) {
			$token = bin2hex( random_bytes( 16 ) );
		}
		$list[] = self::hash( $token );
		if ( count( $list ) > self::SEEN_CAP ) {
			$list = array_slice( $list, - self::SEEN_CAP );
		}
		update_user_meta( $user_id, self::SEEN_META, $list );
		$this->set_cookie( $token );

		return false;
	}

	/**
	 * Persist the device token cookie (one year, secure, httponly).
	 *
	 * @param string $token Opaque token.
	 */
	private function set_cookie( string $token ): void {
		if ( headers_sent() ) {
			return;
		}
		setcookie(
			self::SEEN_COOKIE,
			$token,
			array(
				'expires'  => time() + YEAR_IN_SECONDS,
				'path'     => defined( 'COOKIEPATH' ) ? COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		$_COOKIE[ self::SEEN_COOKIE ] = $token;
	}

	/**
	 * HMAC of a device token (never store the raw token).
	 *
	 * @param string $token Token.
	 * @return string
	 */
	private static function hash( string $token ): string {
		return hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
	}

	/**
	 * "Hello <name>," greeting line.
	 *
	 * @param WP_User $user User.
	 * @return string
	 */
	private function greeting( WP_User $user ): string {
		$name = '' !== $user->display_name ? $user->display_name : $user->user_login;
		/* translators: %s: user display name. */
		return sprintf( __( 'Hello %s,', 'rapls-passkey' ), $name ) . "\n\n";
	}

	/**
	 * Resolve the provider/authenticator name for a stored credential row.
	 *
	 * @param int $cred_id Credential row id.
	 * @return string|null Provider name, or null when unknown.
	 */
	private function provider_name( int $cred_id ): ?string {
		if ( $cred_id <= 0 ) {
			return null;
		}
		$credential = ( new CredentialRepository() )->find_by_id( $cred_id );
		if ( null === $credential ) {
			return null;
		}
		return AuthenticatorNames::name_for_record( $credential->record_json );
	}

	/**
	 * Time / IP / browser lines shared by every notification.
	 *
	 * @return string
	 */
	private function context_lines(): string {
		$lines = sprintf(
			/* translators: %s: date and time. */
			__( 'Date/time: %s', 'rapls-passkey' ),
			wp_date( 'Y-m-d H:i:s (T)' )
		) . "\n";

		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( '' !== $ip ) {
			/* translators: %s: IP address. */
			$lines .= sprintf( __( 'IP address: %s', 'rapls-passkey' ), $ip ) . "\n";
		}

		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		if ( '' !== $ua ) {
			/* translators: %s: browser user agent. */
			$lines .= sprintf( __( 'Browser: %s', 'rapls-passkey' ), \RaplsPasskey\Support\Str::substr( $ua, 0, 200 ) ) . "\n";
		}

		return $lines;
	}

	/**
	 * Site name, entity-decoded for a plain-text email.
	 *
	 * @return string
	 */
	private function site_name(): string {
		return wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
	}

	/**
	 * Send the email to the user's account address.
	 *
	 * @param WP_User $user    Recipient.
	 * @param string  $subject Subject.
	 * @param string  $body    Plain-text body.
	 */
	private function send( WP_User $user, string $subject, string $body ): void {
		$to = (string) $user->user_email;
		if ( '' === $to || ! is_email( $to ) ) {
			return;
		}
		wp_mail( $to, $subject, $body );
	}
}
