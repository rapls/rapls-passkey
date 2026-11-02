<?php
/**
 * wp-login.php passkey integration.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Login;

use RaplsPasskey\Support\Help;

defined( 'ABSPATH' ) || exit;

/**
 * Adds a "Sign in with a passkey" button to the login form and the script that
 * drives the assertion ceremony (username + passkey for the MVP).
 */
final class LoginForm {

	/**
	 * Whether the button has been put on a front-end form this request.
	 *
	 * @var bool
	 */
	private $front_rendered = false;

	/**
	 * Hook the login screen.
	 */
	public function register(): void {
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'login_form', array( $this, 'render_button' ) );
	}

	/**
	 * Enqueue the login script and its config.
	 *
	 * @param bool $front_end True when a front-end form (not wp-login.php) asked
	 *                        for the button. Its sign-in then returns to the page
	 *                        it started on rather than the dashboard.
	 */
	public function enqueue( $front_end = false ): void {
		$front_end = true === $front_end;
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

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';

		wp_localize_script(
			'rapls-passkey-login',
			'raplsPasskeyLogin',
			array(
				'restUrl'    => esc_url_raw( rest_url( 'rapls-passkey/v1/' ) ),
				'redirectTo' => $redirect_to,
				'frontEnd'   => $front_end ? 1 : 0,
				'i18n'       => array(
					'authenticating' => __( 'Authenticating...', 'rapls-passkey' ),
					'failed'         => __( 'Passkey authentication failed.', 'rapls-passkey' ),
					'unsupported'    => __( 'This browser does not support passkeys.', 'rapls-passkey' ),
					'cancelled'      => __( 'Authentication was cancelled or timed out. Please try again.', 'rapls-passkey' ),
					'busy'           => __( 'Another sign-in attempt is still running. Wait a moment and try again.', 'rapls-passkey' ),
					'network'        => __( 'Could not reach the site. Check your connection and try again.', 'rapls-passkey' ),
					'insecure'       => __( 'Passkeys need a secure (HTTPS) connection on this site\'s own address.', 'rapls-passkey' ),
					'needUsername'   => __( 'Please enter your username or email address.', 'rapls-passkey' ),
				),
			)
		);
	}

	/**
	 * Output the passkey button inside the login form.
	 */
	public function render_button(): void {
		// Other login forms fire login_form too -- WP-Members, bbPress, LearnDash
		// -- on ordinary front-end pages, where login_enqueue_scripts never runs.
		// The button used to be printed there without its script: it showed, and
		// did nothing when pressed. Load the script here instead, and print the
		// button only once, since the script binds to it by id.
		if ( ! did_action( 'login_enqueue_scripts' ) ) {
			if ( $this->front_rendered || is_user_logged_in() ) {
				return;
			}
			$this->front_rendered = true;
			$this->enqueue( true );
		}
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
