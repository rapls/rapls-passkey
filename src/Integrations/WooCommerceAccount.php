<?php
/**
 * WooCommerce "My account" passkey management tab.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations;

use RaplsPasskey\Frontend\Shortcodes;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds a "Passkey" tab to the WooCommerce "My account" area where customers can
 * register and remove their passkeys, reusing the same renderer and assets as
 * [rapls_passkey_register]. Inert unless WooCommerce is active.
 */
final class WooCommerceAccount {

	/** Account endpoint slug. */
	private const ENDPOINT = 'rapls-passkeys';

	/**
	 * Option flag so rewrite rules are flushed only once per activation. Cleared
	 * on (de)activation (see Activator/Deactivator) so the endpoint's rewrite rule
	 * is regenerated after a deactivation that flushed the rules away — otherwise
	 * the My Account tab would 404 on reactivation.
	 */
	public const FLUSH_FLAG = 'rapls_passkey_wc_endpoint_flushed';

	/**
	 * @param Shortcodes $shortcodes Shared front-end renderer.
	 */
	public function __construct( private Shortcodes $shortcodes ) {}

	/**
	 * Hook the WooCommerce account endpoint, menu item and content.
	 */
	public function register(): void {
		add_action( 'init', array( $this, 'add_endpoint' ) );
		add_filter( 'woocommerce_get_query_vars', array( $this, 'query_var' ) );
		add_filter( 'woocommerce_account_menu_items', array( $this, 'menu_item' ) );
		add_action( 'woocommerce_account_' . self::ENDPOINT . '_endpoint', array( $this, 'render' ) );
	}

	/**
	 * Register the rewrite endpoint (and flush rules once) when WooCommerce is on.
	 */
	public function add_endpoint(): void {
		if ( ! function_exists( 'WC' ) ) {
			return;
		}
		add_rewrite_endpoint( self::ENDPOINT, EP_ROOT | EP_PAGES );

		if ( '1' !== get_option( self::FLUSH_FLAG ) ) {
			flush_rewrite_rules( false );
			update_option( self::FLUSH_FLAG, '1', false );
		}
	}

	/**
	 * Register the endpoint as a WooCommerce query var.
	 *
	 * @param array<string,string> $vars Query vars.
	 * @return array<string,string>
	 */
	public function query_var( $vars ): array {
		$vars = is_array( $vars ) ? $vars : array();
		$vars[ self::ENDPOINT ] = self::ENDPOINT;
		return $vars;
	}

	/**
	 * Insert the "Passkey" menu item just before "Logout".
	 *
	 * @param array<string,string> $items Menu items.
	 * @return array<string,string>
	 */
	public function menu_item( $items ): array {
		$items = is_array( $items ) ? $items : array();

		$logout = null;
		if ( isset( $items['customer-logout'] ) ) {
			$logout = $items['customer-logout'];
			unset( $items['customer-logout'] );
		}

		$items[ self::ENDPOINT ] = __( 'Passkey', 'rapls-passkey' );

		if ( null !== $logout ) {
			$items['customer-logout'] = $logout;
		}
		return $items;
	}

	/**
	 * Render the passkey management UI inside the account tab.
	 */
	public function render(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		echo '<h3>' . esc_html__( 'Passkey', 'rapls-passkey' ) . '</h3>';
		// render_register() returns trusted, internally-escaped markup.
		echo $this->shortcodes->render_register( array() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}
