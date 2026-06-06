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
	 * No scheduled work or runtime state to tear down yet. Stored credentials
	 * and options are intentionally preserved so reactivation is seamless.
	 */
	public static function deactivate(): void {
	}
}
