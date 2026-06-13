<?php
/**
 * Plugin Name:       Rapls Passkey
 * Plugin URI:        https://rapls.example/passkey
 * Description:       WordPress のログインをパスキー(WebAuthn / FIDO2)で行う、パスワードレス認証プラグイン。
 * Version:           0.6.0
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

define( 'RAPLS_PASSKEY_VERSION', '0.6.0' );
define( 'RAPLS_PASSKEY_FILE', __FILE__ );
define( 'RAPLS_PASSKEY_DIR', plugin_dir_path( __FILE__ ) );
define( 'RAPLS_PASSKEY_URL', plugin_dir_url( __FILE__ ) );
define( 'RAPLS_PASSKEY_BASENAME', plugin_basename( __FILE__ ) );

/*
 * Composer autoloader — present once `composer install` has run. It pulls in
 * web-auth/webauthn-lib (the WebAuthn verification core). Optional during early
 * development: the lightweight autoloader below covers the plugin's own classes,
 * and Plugin::boot() degrades with an admin notice when the library is absent.
 */
if ( file_exists( RAPLS_PASSKEY_DIR . 'vendor/autoload.php' ) ) {
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
