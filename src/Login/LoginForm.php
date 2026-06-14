<?php
/**
 * wp-login.php passkey integration.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Login;

use RaplsPasskey\Support\Help;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds a "Sign in with a passkey" button to the login form and the script that
 * drives the assertion ceremony (username + passkey for the MVP).
 */
final class LoginForm {

	/**
	 * Hook the login screen.
	 */
	public function register(): void {
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'login_form', array( $this, 'render_button' ) );
	}

	/**
	 * Enqueue the login script and its config.
	 */
	public function enqueue(): void {
		wp_enqueue_script(
			'rapls-passkey-webauthn',
			RAPLS_PASSKEY_URL . 'assets/webauthn.js',
			array(),
			RAPLS_PASSKEY_VERSION,
			true
		);
		wp_enqueue_script(
			'rapls-passkey-login',
			RAPLS_PASSKEY_URL . 'assets/login.js',
			array( 'rapls-passkey-webauthn' ),
			RAPLS_PASSKEY_VERSION,
			true
		);

		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		wp_localize_script(
			'rapls-passkey-login',
			'raplsPasskeyLogin',
			array(
				'restUrl'    => esc_url_raw( rest_url( 'rapls-passkey/v1/' ) ),
				'redirectTo' => $redirect_to,
				'i18n'       => array(
					'authenticating' => __( 'Authenticating...', 'rapls-passkey' ),
					'failed'         => __( 'Passkey authentication failed.', 'rapls-passkey' ),
					'unsupported'    => __( 'This browser does not support passkeys.', 'rapls-passkey' ),
					'cancelled'      => __( 'Authentication was cancelled or timed out. Please try again.', 'rapls-passkey' ),
					'needUsername'   => __( 'Please enter your username or email address.', 'rapls-passkey' ),
				),
			)
		);
	}

	/**
	 * Output the passkey button inside the login form.
	 */
	public function render_button(): void {
		?>
		<div style="margin:0 0 16px">
			<button type="button" class="button button-secondary" id="rapls-passkey-login-btn" style="width:100%">
				<?php esc_html_e( 'Sign in with a passkey', 'rapls-passkey' ); ?>
			</button>
			<p id="rapls-passkey-login-status" style="margin:8px 0 0"></p>
			<?php Help::render(); ?>
		</div>
		<?php
	}
}
