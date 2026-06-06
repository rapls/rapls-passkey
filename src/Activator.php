<?php
/**
 * Activation routine.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

use RaplsPasskey\Credentials\Schema;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs on plugin activation: builds the credential table and records state.
 */
final class Activator {

	/**
	 * Create the custom table and store activation state.
	 */
	public static function activate(): void {
		Schema::install();
		update_option( 'rapls_passkey_schema_version', '1', false );

		if ( false === get_option( 'rapls_passkey_activated_at' ) ) {
			add_option( 'rapls_passkey_activated_at', gmdate( 'Y-m-d H:i:s' ), '', false );
		}
	}
}
