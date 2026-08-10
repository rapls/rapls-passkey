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

defined( 'ABSPATH' ) || exit;

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
		$method = isset( $_SERVER['REQUEST_METHOD'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) )
			: '';
		if ( 'POST' === $method ) {
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

		// The attempt is CLAIMED FIRST. Asking the provider and counting the
		// failure afterwards meant simultaneous submissions all had their code
		// validated and only then queued up to be counted, so the budget bounded
		// what was recorded rather than what was checked (V49-A04).
		$claim = SecondFactor::claim_attempt();
		if ( '' === $claim ) {
			// Out of attempts: the parked login is gone, so the recovery code /
			// magic link has to be presented again from the start.
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		if ( ! $provider->validate( $user ) ) {
			// The parked login is discarded only AFTER the answer has been checked:
			// discarding it as the attempt was claimed made a correct fifth answer
			// impossible (the same shape as V50-03 on the QR side).
			if ( SecondFactor::was_last_attempt( $claim ) ) {
				SecondFactor::forget();
				wp_safe_redirect( wp_login_url() );
				exit;
			}
			return __( 'The two-factor authentication code is not correct.', 'rapls-passkey' );
		}

		SecondFactor::forgive_attempt( $claim );
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
	/**
	 * The HTML a second-factor provider may print on this screen.
	 *
	 * Form controls and ordinary text markup. Deliberately no `script`: this
	 * output arrives from whichever 2FA plugin is installed, and the screen sits
	 * between a spent first factor and a session.
	 *
	 * @return array<string,array<string,bool>>
	 */
	private static function provider_html(): array {
		$attrs = array(
			'id' => true, 'class' => true, 'style' => true, 'title' => true, 'role' => true,
			'name' => true, 'value' => true, 'type' => true, 'placeholder' => true,
			'autocomplete' => true, 'autocapitalize' => true, 'autocorrect' => true,
			'spellcheck' => true, 'inputmode' => true, 'pattern' => true, 'maxlength' => true,
			'minlength' => true, 'size' => true, 'min' => true, 'max' => true, 'step' => true,
			'required' => true, 'readonly' => true, 'disabled' => true, 'checked' => true,
			'selected' => true, 'multiple' => true, 'rows' => true, 'cols' => true,
			'for' => true, 'form' => true, 'tabindex' => true, 'autofocus' => true,
			'aria-label' => true, 'aria-labelledby' => true, 'aria-describedby' => true,
			'aria-hidden' => true, 'aria-live' => true, 'data-*' => true,
		);

		$tags = array(
			'form', 'input', 'label', 'select', 'option', 'optgroup', 'textarea',
			'button', 'fieldset', 'legend', 'datalist', 'output',
			'p', 'div', 'span', 'br', 'hr', 'strong', 'b', 'em', 'i', 'small', 'code',
			'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
		);

		$allowed = array();
		foreach ( $tags as $tag ) {
			$allowed[ $tag ] = $attrs;
		}
		$allowed['a']   = $attrs + array( 'href' => true, 'target' => true, 'rel' => true );
		$allowed['img'] = $attrs + array( 'src' => true, 'alt' => true, 'width' => true, 'height' => true );

		/**
		 * Filter the HTML a second-factor provider may print on the 2FA screen.
		 *
		 * @param array<string,array<string,bool>> $allowed Allowed tags and attributes.
		 */
		return (array) apply_filters( 'rapls_passkey/second_factor_allowed_html', $allowed );
	}

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
			// The 2FA plugin's own markup, filtered to the form controls a second
			// factor needs. It is another plugin's output, not ours, so it is
			// allowlisted rather than trusted: a provider that wants JavaScript on
			// this screen should enqueue it, not print it here.
			echo wp_kses( $fields, self::provider_html() );
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
