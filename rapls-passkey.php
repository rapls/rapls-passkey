<?php
/**
 * Plugin Name:       Rapls Passkey
 * Plugin URI:        https://wordpress.org/plugins/rapls-passkey/
 * Description:       Passwordless authentication for WordPress using passkeys (WebAuthn / FIDO2).
 * Version:           0.13.39
 * Requires at least: 6.0
 * Requires PHP:      8.2
 * Author:            Min
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       rapls-passkey
 * Domain Path:       /languages
 *
 * @package RaplsPasskey
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'RAPLS_PASSKEY_VERSION', '0.13.39' );
define( 'RAPLS_PASSKEY_FILE', __FILE__ );
define( 'RAPLS_PASSKEY_DIR', plugin_dir_path( __FILE__ ) );
define( 'RAPLS_PASSKEY_URL', plugin_dir_url( __FILE__ ) );
define( 'RAPLS_PASSKEY_BASENAME', plugin_basename( __FILE__ ) );

/*
 * Composer autoloader — present once `composer install` has run. It pulls in
 * web-auth/webauthn-lib (the WebAuthn verification core). Optional during early
 * development: the lightweight autoloader below covers the plugin's own classes,
 * and Plugin::boot() degrades with an admin notice when the library is absent.
 *
 * In a namespace-prefixed distribution build (bin/build-dist.sh) PHP-Scoper emits
 * `vendor/scoper-autoload.php`, which loads the scoped classes and registers the
 * function aliases for excluded symbols; prefer it when present.
 */
if ( file_exists( RAPLS_PASSKEY_DIR . 'vendor/scoper-autoload.php' ) ) {
	require RAPLS_PASSKEY_DIR . 'vendor/scoper-autoload.php';
} elseif ( file_exists( RAPLS_PASSKEY_DIR . 'vendor/autoload.php' ) ) {
	require RAPLS_PASSKEY_DIR . 'vendor/autoload.php';
}

/*
 * Lightweight PSR-4 autoloader for the plugin's own classes. Lets the plugin
 * run before `composer install` has generated the optimized autoloader.
 */
spl_autoload_register(
	static function ( $class ) {
		$prefix = 'RaplsPasskey\\';
		$len    = strlen( $prefix );
		if ( strncmp( $class, $prefix, $len ) !== 0 ) {
			return;
		}
		$relative = substr( $class, $len );
		$path     = RAPLS_PASSKEY_DIR . 'src/' . str_replace( '\\', '/', $relative ) . '.php';
		if ( file_exists( $path ) ) {
			require $path;
		}
	}
);

register_activation_hook( __FILE__, array( \RaplsPasskey\Activator::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \RaplsPasskey\Deactivator::class, 'deactivate' ) );

add_action(
	'plugins_loaded',
	static function () {
		\RaplsPasskey\Plugin::instance()->boot();
	}
);
