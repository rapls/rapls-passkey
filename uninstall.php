<?php
/**
 * Uninstall cleanup.
 *
 * Removes the plugin's custom tables, options, transients and user meta. Runs
 * only when the user deletes the plugin from the admin. On multisite the
 * per-site data is cleaned on every site the plugin touched.
 *
 * @package RaplsPasskey
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/src/Credentials/Schema.php';

/**
 * Remove everything this plugin created for the current site.
 */
function rapls_passkey_uninstall_site(): void {
	global $wpdb;

	\RaplsPasskey\Credentials\Schema::drop();

	delete_option( 'rapls_passkey_activated_at' );
	delete_option( 'rapls_passkey_schema_version' );
	delete_option( 'rapls_passkey_settings' );
	delete_option( 'rapls_passkey_setup_done' );
	delete_option( 'rapls_passkey_wc_endpoint_flushed' );

	// Sweep the plugin's transients (all share the rapls_passkey_ prefix). They
	// are short-lived and WP expires them lazily, but a delete keeps uninstall tidy.
	$like    = $wpdb->esc_like( '_transient_rapls_passkey_' ) . '%';
	$timeout = $wpdb->esc_like( '_transient_timeout_rapls_passkey_' ) . '%';
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $like, $timeout ) ); // phpcs:ignore WordPress.DB

	// Per-user WebAuthn-handle creation locks, per-user registration locks, and
	// per-IP rate-limit counters (all raw options rather than transients).
	$handle_lock = $wpdb->esc_like( 'rapls_pk_handle_lock_' ) . '%';
	$reg_lock    = $wpdb->esc_like( 'rapls_pk_reg_lock_' ) . '%';
	$rate_rows   = $wpdb->esc_like( 'rapls_passkey_rl_' ) . '%';
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s", $handle_lock, $reg_lock, $rate_rows ) ); // phpcs:ignore WordPress.DB
}

// Remove per-user meta this plugin stored, for every user (global, not per-site).
foreach ( array( 'rapls_passkey_user_handle', 'rapls_pk_seen_devices', 'rapls_pk_upgrade_seen' ) as $meta_key ) {
	delete_metadata( 'user', 0, $meta_key, '', true );
}

if ( is_multisite() ) {
	foreach ( get_sites( array( 'number' => 0, 'fields' => 'ids' ) ) as $site_id ) {
		switch_to_blog( (int) $site_id );
		rapls_passkey_uninstall_site();
		restore_current_blog();
	}
} else {
	rapls_passkey_uninstall_site();
}
