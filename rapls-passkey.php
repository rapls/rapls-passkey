<?php
/**
 * Plugin Name:       Rapls Passkey
 * Plugin URI:        https://raplsworks.com/plugins/rapls-passkey/
 * Description:       Passwordless authentication for WordPress using passkeys (WebAuthn / FIDO2).
 * Version:           0.13.70
 * Requires at least: 6.0
 * Requires PHP:      8.2
 * Author:            Rapls
 * Author URI:        https://raplsworks.com/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       rapls-passkey
 *
 * @package RaplsPasskey
 */

defined( 'ABSPATH' ) || exit;

/*
 * Stop here, before Composer's autoloader, when PHP is too old.
 *
 * vendor/composer/platform_check.php throws a RuntimeException the moment the
 * autoloader is required on PHP below 8.2, and nothing in WordPress catches it:
 * the throw happens inside wp-settings.php's plugin loading, so the whole site
 * goes white — front end included — rather than this one plugin declining to
 * run.
 *
 * The `Requires PHP` header does not cover this. WordPress reads it when
 * activating and when offering an update, and never again, so a site whose PHP
 * is lowered afterwards keeps loading the plugin. The same gap shows up where
 * the web server and the CLI are on different versions: Xserver manages them
 * separately, and WP-CLI on PHP 8.0 took a site down that served pages fine.
 *
 * PHP_VERSION_ID rather than version_compare(): it is an integer comparison,
 * with none of the string-ordering traps ("8.10" sorting below "8.9").
 */
if ( PHP_VERSION_ID < 80200 ) {
	add_action(
		'admin_notices',
		static function () {
			if ( ! current_user_can( 'activate_plugins' ) ) {
				return;
			}
			printf(
				'<div class="notice notice-error"><p>%s</p></div>',
				esc_html(
					sprintf(
						/* translators: 1: required PHP version, 2: the PHP version this server runs. */
						__( 'Rapls Passkey requires PHP %1$s or later. This server is running PHP %2$s, so the plugin is not running. Everything else on the site is unaffected.', 'rapls-passkey' ),
						'8.2',
						PHP_VERSION
					)
				)
			);
		}
	);
	// WP-CLI prints no admin notice, and silence there reads as "the plugin
	// loaded and did nothing" — which is the wrong conclusion to draw.
	if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( '\WP_CLI' ) ) {
		\WP_CLI::warning( 'Rapls Passkey is not running: PHP 8.2 or later is required, and this is PHP ' . PHP_VERSION . '.' );
	}
	return;
}

define( 'RAPLS_PASSKEY_VERSION', '0.13.70' );
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
