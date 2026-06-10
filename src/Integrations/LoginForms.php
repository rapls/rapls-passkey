<?php
/**
 * Passkey sign-in on third-party login forms (membership / e-commerce plugins).
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations;

use RaplsPasskey\Frontend\Shortcodes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Surfaces the passkey login button inside the login forms of popular plugins by
 * hooking each one's "after the login fields" action. Every hook only fires when
 * that plugin is active, so registering them all is inert on a site that has
 * none of them. WooCommerce has its own dedicated integration; this covers the
 * rest.
 *
 * The button reuses the same renderer and assets as [rapls_passkey_login], so
 * there is a single passkey ceremony to maintain. LoginPress and similar plugins
 * that merely restyle wp-login.php are already covered by the core login button.
 */
final class LoginForms {

	/**
	 * Integrations that have already rendered this request, keyed by integration
	 * id, to avoid a double button if a hook fires more than once.
	 *
	 * @var array<string,bool>
	 */
	private $done = array();

	/**
	 * @param Shortcodes $shortcodes Shared front-end renderer.
	 */
	public function __construct( private Shortcodes $shortcodes ) {}

	/**
	 * Integration id => the action hook that renders after that form's fields.
	 *
	 * @return array<string,string>
	 */
	public function integrations(): array {
		/**
		 * Filter the third-party login-form hooks the passkey button attaches to.
		 *
		 * @param array<string,string> $hooks Map of integration id => action hook.
		 */
		return (array) apply_filters(
			'rapls_passkey_login_form_hooks',
			array(
				'ultimate_member'        => 'um_after_login_fields',
				'memberpress'            => 'mepr-login-form-before-submit',
				'easy_digital_downloads' => 'edd_login_fields_after',
				'theme_my_login'         => 'tml_action_login',
			)
		);
	}

	/**
	 * Hook every integration's login form.
	 */
	public function register(): void {
		foreach ( $this->integrations() as $key => $hook ) {
			add_action(
				(string) $hook,
				function () use ( $key ) {
					$this->render( (string) $key );
				}
			);
		}
	}

	/**
	 * Render the passkey button for one integration (once per request, when
	 * logged out and not vetoed).
	 *
	 * @param string $key Integration id.
	 */
	public function render( string $key ): void {
		if ( isset( $this->done[ $key ] ) ) {
			return;
		}
		if ( is_user_logged_in() ) {
			return;
		}

		/**
		 * Toggle a single login-form integration.
		 *
		 * @param bool   $enabled Whether to show the passkey button here.
		 * @param string $key     Integration id (e.g. 'memberpress').
		 */
		if ( ! apply_filters( 'rapls_passkey_login_integration_enabled', true, $key ) ) {
			return;
		}

		$this->done[ $key ] = true;

		echo '<div class="rapls-pk-integration rapls-pk-integration-' . esc_attr( $key ) . '">';
		echo '<p class="rapls-pk-integration-heading">' . esc_html__( 'パスキーでログイン', 'rapls-passkey' ) . '</p>';
		// render_login() returns trusted, internally-escaped markup.
		echo $this->shortcodes->render_login( array() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '</div>';
	}
}
