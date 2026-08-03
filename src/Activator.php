<?php
/**
 * Activation routine.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

use RaplsPasskey\Credentials\Schema;

defined( 'ABSPATH' ) || exit;

/**
 * Runs on plugin activation: builds the credential table and records state.
 */
final class Activator {

	/**
	 * Create the custom table and store activation state.
	 */
	public static function activate(): void {
		// Installs on first activation and migrates when the schema version moves.
		Schema::maybe_upgrade();

		if ( false === get_option( 'rapls_passkey_activated_at' ) ) {
			add_option( 'rapls_passkey_activated_at', gmdate( 'Y-m-d H:i:s' ), '', false );
		}

		// Force the WooCommerce account endpoint's rewrite rule to be re-registered
		// and re-flushed on the next init, so it survives a deactivate/reactivate
		// cycle in which the rules were flushed away.
		delete_option( \RaplsPasskey\Integrations\WooCommerceAccount::FLUSH_FLAG );
	}
}
