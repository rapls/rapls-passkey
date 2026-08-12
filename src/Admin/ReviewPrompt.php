<?php
/**
 * One-time review request.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Credentials\CredentialRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Asks for a WordPress.org review once, and then never again.
 *
 * The conditions are deliberately narrow. It waits a week, because an opinion
 * formed in the first hour is not worth asking for, and it waits for at least
 * one passkey to exist, because someone who never got the plugin working has
 * nothing to review and every reason to resent being asked.
 *
 * It appears only on this plugin's own screens. A review request on somebody
 * else's settings page is the kind of thing Guideline 11 exists to stop, and
 * it is not worth the goodwill it costs. Whichever button is used — including
 * "no thanks" — the answer is recorded site-wide and the notice is gone for
 * good. There is no second attempt and no reminder.
 */
final class ReviewPrompt {

	/** Site option holding the outcome: unset, or a settled state. */
	private const OPTION = 'rapls_passkey_review_prompt';

	/** Option written by the activator, GMT 'Y-m-d H:i:s'. */
	private const ACTIVATED = 'rapls_passkey_activated_at';

	/** Days of use before asking. */
	private const AFTER_DAYS = 7;

	/** Query arg used to settle the prompt. */
	private const ARG = 'rapls_pk_review';

	/** Where the review is left. */
	private const URL = 'https://wordpress.org/support/plugin/rapls-passkey/reviews/#new-post';

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the notice and the dismissal handler.
	 */
	public function register(): void {
		add_action( 'admin_notices', array( $this, 'render' ) );
		add_action( 'admin_init', array( $this, 'handle_dismiss' ) );
	}

	/**
	 * Record the answer, then go wherever that answer points.
	 *
	 * Every button lands here first, including "Write a review" — otherwise the
	 * one person who did what was asked would be asked again on the next page
	 * load, which is the worst of the possible outcomes.
	 */
	public function handle_dismiss(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET[ self::ARG ] ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( self::ARG );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- verified above.
		$answer = sanitize_key( wp_unslash( $_GET[ self::ARG ] ) );

		update_option( self::OPTION, 'done', false );

		if ( 'go' === $answer ) {
			// Not wp_safe_redirect: the destination is this class's own constant,
			// never anything that arrived with the request.
			// phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
			wp_redirect( self::URL );
			exit;
		}

		wp_safe_redirect( remove_query_arg( array( self::ARG, '_wpnonce' ) ) );
		exit;
	}

	/**
	 * A nonced link back to the handler.
	 *
	 * @param string $answer 'go' to continue to WordPress.org, anything else to stay.
	 * @return string
	 */
	private function settle_url( string $answer ): string {
		return wp_nonce_url( add_query_arg( self::ARG, $answer ), self::ARG );
	}

	/**
	 * Print the request, if this is the one moment to print it.
	 */
	public function render(): void {
		if ( ! $this->should_ask() ) {
			return;
		}

		?>
		<div class="notice notice-info">
			<p>
				<strong><?php esc_html_e( 'Rapls Passkey', 'rapls-passkey' ); ?></strong>
				—
				<?php esc_html_e( 'You have been signing in with passkeys for a week now. If it has been working out, would you leave a review? It is the main way other people find the plugin.', 'rapls-passkey' ); ?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( $this->settle_url( 'go' ) ); ?>" target="_blank" rel="noopener noreferrer">
					<?php esc_html_e( 'Write a review', 'rapls-passkey' ); ?>
				</a>
				<a class="button" href="<?php echo esc_url( $this->settle_url( 'did' ) ); ?>">
					<?php esc_html_e( 'Already did', 'rapls-passkey' ); ?>
				</a>
				<a class="button" href="<?php echo esc_url( $this->settle_url( 'no' ) ); ?>">
					<?php esc_html_e( 'No thanks', 'rapls-passkey' ); ?>
				</a>
			</p>
			<p class="description">
				<?php esc_html_e( 'Asked once. Whichever you choose, this will not come back.', 'rapls-passkey' ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * Every condition that has to hold before asking.
	 *
	 * @return bool
	 */
	private function should_ask(): bool {
		/**
		 * Filter whether the review request may be shown at all. Return false to
		 * switch it off for good — for a site owner who does not want it, or for
		 * a build that ships without it.
		 *
		 * @param bool $enabled True by default.
		 */
		if ( ! (bool) apply_filters( 'rapls_passkey/show_review_prompt', true ) ) {
			return false;
		}

		if ( '' !== (string) get_option( self::OPTION, '' ) ) {
			return false;
		}

		// Only someone who could act on it, and only on this plugin's screens.
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}
		if ( ! $this->on_own_screen() ) {
			return false;
		}

		if ( ! $this->used_for_a_week() ) {
			return false;
		}

		// Nothing to review if no passkey was ever registered.
		return $this->repository->count_all() > 0;
	}

	/**
	 * Is the current screen one of this plugin's own?
	 *
	 * @return bool
	 */
	private function on_own_screen(): bool {
		if ( ! function_exists( 'get_current_screen' ) ) {
			return false;
		}
		$screen = get_current_screen();
		if ( null === $screen ) {
			return false;
		}
		return in_array(
			$screen->id,
			array(
				'settings_page_rapls-passkey',
				'users_page_' . CredentialsPage::SLUG,
			),
			true
		);
	}

	/**
	 * Has the plugin been active for the waiting period?
	 *
	 * @return bool
	 */
	private function used_for_a_week(): bool {
		$since = (string) get_option( self::ACTIVATED, '' );
		if ( '' === $since ) {
			return false;
		}
		$ts = strtotime( $since . ' UTC' );
		if ( false === $ts ) {
			return false;
		}
		return ( time() - $ts ) >= ( self::AFTER_DAYS * DAY_IN_SECONDS );
	}
}
