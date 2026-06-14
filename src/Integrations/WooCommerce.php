<?php
/**
 * WooCommerce front-end integration.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations;

use RaplsPasskey\Frontend\Shortcodes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Surfaces passkey sign-in on WooCommerce's "My account" login screen (and,
 * when enabled, the checkout login). The hooks only fire when WooCommerce is
 * active, so no explicit dependency check is needed — registering them is inert
 * on a store-less site.
 *
 * The button reuses the same renderer and assets as [rapls_passkey_login], so
 * there is a single passkey ceremony to maintain.
 */
final class WooCommerce {

	/**
	 * @param Shortcodes $shortcodes Shared front-end renderer.
	 */
	public function __construct( private Shortcodes $shortcodes ) {}

	/**
	 * Hook the WooCommerce login surfaces.
	 */
	public function register(): void {
		add_action( 'woocommerce_before_customer_login_form', array( $this, 'render_prompt' ) );
		add_action( 'woocommerce_login_form_end', array( $this, 'render_prompt' ) );
	}

	/**
	 * Render the passkey login prompt above the WooCommerce login form.
	 */
	public function render_prompt(): void {
		if ( is_user_logged_in() ) {
			return;
		}

		/**
		 * Toggle the WooCommerce passkey login prompt.
		 *
		 * @param bool $enabled Whether to show the passkey prompt on WooCommerce.
		 */
		if ( ! apply_filters( 'rapls_passkey_woocommerce_enabled', true ) ) {
			return;
		}

		// Render only once per request even if several WooCommerce hooks fire.
		static $done = false;
		if ( $done ) {
			return;
		}
		$done = true;

		echo '<div class="rapls-pk-wc">';
		echo '<p class="rapls-pk-wc-heading">' . esc_html__( 'Sign in with a passkey', 'rapls-passkey' ) . '</p>';
		// render_login() returns trusted, internally-escaped markup.
		echo $this->shortcodes->render_login( array() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<p class="rapls-pk-wc-or">' . esc_html__( 'Or sign in with a password', 'rapls-passkey' ) . '</p>';
		echo '</div>';
	}
}
