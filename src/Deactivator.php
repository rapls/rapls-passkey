<?php
/**
 * Deactivation routine.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs on plugin deactivation. Keeps all user data; only transient runtime
 * state should be cleared here. Stored credentials are removed on uninstall.
 */
final class Deactivator {

	/**
	 * Stored credentials and options are intentionally preserved so reactivation
	 * is seamless. We do clear the WooCommerce account endpoint's rewrite rule and
	 * its one-time flush flag, so the rules do not keep a stale endpoint and the
	 * tab's rewrite rule is regenerated cleanly on reactivation.
	 */
	public static function deactivate(): void {
		delete_option( \RaplsPasskey\Integrations\WooCommerceAccount::FLUSH_FLAG );
		if ( function_exists( 'flush_rewrite_rules' ) ) {
			flush_rewrite_rules( false );
		}
	}
}
