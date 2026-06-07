<?php
/**
 * reCAPTCHA v3 on the password login form.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Login;

use RaplsPasskey\Support\Settings;
use WP_Error;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Protects the standard username/password login with Google reCAPTCHA v3.
 *
 * Only the password form is gated — passkey login needs no CAPTCHA (an assertion
 * cannot be brute-forced), and the passkey flow uses fetch() so it never submits
 * this form. Active only when enabled with both keys (see Settings), so it never
 * double-challenges a site whose security plugin already adds a CAPTCHA.
 */
final class Recaptcha {

	/** Hidden field / POST key carrying the token. */
	private const FIELD = 'rapls_passkey_recaptcha_token';

	/** Verification endpoint. */
	private const VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

	/** Expected v3 action. */
	private const ACTION = 'login';

	/**
	 * Hook the login screen and the authentication check.
	 */
	public function register(): void {
		if ( ! Settings::recaptcha_active() ) {
			return;
		}
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'login_form', array( $this, 'render_field' ) );
		add_filter( 'authenticate', array( $this, 'verify' ), 25, 3 );
	}

	/**
	 * Load the reCAPTCHA API and our token-injecting script.
	 */
	public function enqueue(): void {
		$site_key = Settings::recaptcha_site_key();

		wp_enqueue_script(
			'rapls-passkey-recaptcha-api',
			'https://www.google.com/recaptcha/api.js?render=' . rawurlencode( $site_key ),
			array(),
			null, // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion -- Google API, no version.
			true
		);
		wp_enqueue_script(
			'rapls-passkey-recaptcha',
			RAPLS_PASSKEY_URL . 'assets/recaptcha.js',
			array( 'rapls-passkey-recaptcha-api' ),
			RAPLS_PASSKEY_VERSION,
			true
		);
		wp_localize_script(
			'rapls-passkey-recaptcha',
			'raplsPasskeyRecaptcha',
			array(
				'siteKey' => $site_key,
				'action'  => self::ACTION,
				'field'   => self::FIELD,
			)
		);
	}

	/**
	 * Hidden field the token is written into before the form submits.
	 */
	public function render_field(): void {
		echo '<input type="hidden" name="' . esc_attr( self::FIELD ) . '" id="' . esc_attr( self::FIELD ) . '" value="">';
	}

	/**
	 * Verify the token during interactive password login. Other auth paths
	 * (application passwords, REST, programmatic) don't post log+pwd and pass
	 * through untouched.
	 *
	 * @param null|WP_User|WP_Error $user     Auth result so far.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return null|WP_User|WP_Error
	 */
	public function verify( $user, $username, $password ) {
		// Already failed upstream, or not an interactive password submission.
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if ( ! isset( $_POST['log'], $_POST['pwd'] ) ) {
			return $user;
		}
		$token = isset( $_POST[ self::FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::FIELD ] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === $token ) {
			return new WP_Error( 'rapls_passkey_recaptcha_missing', __( 'reCAPTCHA の確認に失敗しました。ページを再読み込みしてお試しください。', 'rapls-passkey' ) );
		}
		if ( ! $this->token_passes( $token ) ) {
			return new WP_Error( 'rapls_passkey_recaptcha_failed', __( 'reCAPTCHA の検証に失敗しました。', 'rapls-passkey' ) );
		}

		return $user;
	}

	/**
	 * Call Google to validate the token. Fails open on a transport error (so a
	 * Google outage can't lock everyone out) but closed on an explicit reject.
	 *
	 * @param string $token Client token.
	 * @return bool
	 */
	private function token_passes( string $token ): bool {
		$response = wp_remote_post(
			self::VERIFY_URL,
			array(
				'timeout' => 5,
				'body'    => array(
					'secret'   => Settings::recaptcha_secret_key(),
					'response' => $token,
					'remoteip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return true; // Fail open on transport failure.
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || empty( $data['success'] ) ) {
			return false;
		}
		if ( isset( $data['action'] ) && self::ACTION !== $data['action'] ) {
			return false;
		}
		if ( isset( $data['score'] ) && (float) $data['score'] < Settings::recaptcha_threshold() ) {
			return false;
		}

		return true;
	}
}
