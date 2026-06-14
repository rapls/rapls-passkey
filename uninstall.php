<?php
/**
 * Uninstall cleanup.
 *
 * Removes the plugin's custom table and options. Runs only when the user
 * deletes the plugin from the admin.
 *
 * @package RaplsPasskey
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

require_once __DIR__ . '/src/Credentials/Schema.php';

\RaplsPasskey\Credentials\Schema::drop();

delete_option( 'rapls_passkey_activated_at' );
delete_option( 'rapls_passkey_schema_version' );
delete_option( 'rapls_passkey_settings' );
delete_option( 'rapls_passkey_wc_endpoint_flushed' );

// Remove per-user meta this plugin stored, for every user.
foreach ( array( 'rapls_passkey_user_handle', 'rapls_pk_seen_devices', 'rapls_pk_upgrade_seen' ) as $meta_key ) {
	delete_metadata( 'user', 0, $meta_key, '', true );
}
