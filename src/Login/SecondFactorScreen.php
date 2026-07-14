<?php
/**
 * The second-factor challenge screen for alternative logins.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Login;

use RaplsPasskey\Security\AuthSession;
use RaplsPasskey\Security\SecondFactor;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Shown between a successful magic-link / recovery-code login and the auth cookie:
 * the first factor is proven, and now the site's own 2FA plugin gets to ask for the
 * second one. The answer is checked by that plugin, not by us.
 *
 * The parked login lives in a short-lived transient keyed by a hashed token from an
 * HttpOnly cookie, so nothing sensitive travels in the URL and a stolen database row
 * cannot be replayed.
 */
final class SecondFactorScreen {

	/**
	 * Hook the wp-login.php action.
	 */
	public function register(): void {
		add_action( 'login_form_' . SecondFactor::ACTION, array( $this, 'handle' ) );
	}

	/**
	 * Render / process the challenge. Always exits.
	 */
	public function handle(): void {
		$pending = SecondFactor::pending();
		$user    = $pending ? get_user_by( 'id', (int) $pending['user_id'] ) : false;
		$provider = $user instanceof WP_User ? SecondFactor::provider_for( $user ) : null;

		// Nothing parked, expired, or the user's 2FA went away while they were here:
		// send them back to the login form rather than stranding them.
		if ( ! $pending || ! $user instanceof WP_User || null === $provider ) {
			SecondFactor::forget();
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$error = '';
		if ( 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) {
			$error = $this->process( $user, $provider, $pending ); // Exits on success.
		}

		$this->render_screen( $user, $provider, $error );
		exit;
	}

	/**
	 * Check the submitted answer and, if it is right, finish the login.
	 *
	 * @param WP_User                                             $user     The user signing in.
	 * @param \RaplsPasskey\Integrations\SecondFactor\Provider    $provider The 2FA plugin adapter.
	 * @param array{user_id:int,context:string,remember:bool,redirect:string,attempts:int} $pending Parked login.
	 * @return string Error message to show, or '' if a redirect was issued.
	 */
	private function process( WP_User $user, $provider, array $pending ): string {
		if (
			! isset( $_POST['rapls_pk_2fa_nonce'] ) ||
			! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['rapls_pk_2fa_nonce'] ) ), SecondFactor::ACTION )
		) {
			return __( 'Your session is invalid. Please try again.', 'rapls-passkey' );
		}

		if ( ! $provider->validate( $user ) ) {
			if ( ! SecondFactor::count_failure() ) {
				// Out of attempts: the parked login is gone, so the recovery code /
				// magic link has to be presented again from the start.
				wp_safe_redirect( wp_login_url() );
				exit;
			}
			return __( 'The two-factor authentication code is not correct.', 'rapls-passkey' );
		}

		SecondFactor::forget();

		// Second factor done — complete the login the caller had to leave pending.
		$blocked = AuthSession::login( $user, (string) $pending['context'], (bool) $pending['remember'], true );
		if ( $blocked instanceof \WP_Error ) {
			return $blocked->get_error_message();
		}

		wp_safe_redirect( (string) $pending['redirect'] );
		exit;
	}

	/**
	 * Draw the challenge, with the 2FA plugin supplying the fields.
	 *
	 * @param WP_User                                          $user     The user signing in.
	 * @param \RaplsPasskey\Integrations\SecondFactor\Provider $provider The 2FA plugin adapter.
	 * @param string                                           $error    Error message, or ''.
	 */
	private function render_screen( WP_User $user, $provider, string $error ): void {
		// Some providers (Two-Factor's, for instance) draw their own submit button;
		// buffer their fields so we only add ours when they did not.
		ob_start();
		$provider->render( $user );
		$fields     = (string) ob_get_clean();
		$has_submit = false !== stripos( $fields, 'type="submit"' );

		login_header( __( 'Two-factor authentication', 'rapls-passkey' ), '' );

		if ( '' !== $error ) {
			echo '<div id="login_error" class="notice notice-error"><p>' . esc_html( $error ) . '</p></div>';
		}
		?>
		<form name="raplspk2fa" method="post" action="<?php echo esc_url( add_query_arg( 'action', SecondFactor::ACTION, wp_login_url() ) ); ?>">
			<p class="message">
				<?php
				printf(
					/* translators: %s: the user's login name. */
					esc_html__( 'Signed in as %s. One more step: confirm your second factor.', 'rapls-passkey' ),
					esc_html( $user->user_login )
				);
				?>
			</p>
			<?php
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Markup comes from the 2FA plugin, which escapes it (this is what it prints on wp-login.php).
			echo $fields;
			?>
			<?php wp_nonce_field( SecondFactor::ACTION, 'rapls_pk_2fa_nonce' ); ?>
			<?php if ( ! $has_submit ) : ?>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Confirm', 'rapls-passkey' ); ?>" style="width:100%" />
			</p>
			<?php endif; ?>
		</form>
		<p id="nav">
			<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Back to the normal login', 'rapls-passkey' ); ?></a>
		</p>
		<?php
		login_footer();
	}
}
