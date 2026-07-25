<?php
/**
 * PHP-Scoper configuration.
 *
 * Rewrites the bundled third-party libraries (web-auth/webauthn-lib, Symfony,
 * Brick, spomky-labs, ParagonIE, …) into the plugin-private namespace prefix
 * `RaplsPasskey\Vendor\…` at build time, so another plugin that bundles a
 * different version of the same library cannot collide with ours. The plugin's
 * own `src/` is scoped too, but only so its `use Webauthn\…` references are
 * rewritten — its own namespace, WordPress core, Composer's autoloader, and the
 * third-party plugins it merely *detects* at runtime are all left untouched.
 *
 * The committed source stays unscoped; only the distribution build produced by
 * bin/build-dist.sh is prefixed. See docs/vendor-prefixing.md.
 *
 * Run with the php-scoper PHAR (bin/php-scoper.phar). The WordPress exclude lists
 * are bundled under bin/scoper-excludes/ (committed) so the build never depends
 * on a dev Composer install.
 *
 * @package RaplsPasskey
 */

declare( strict_types=1 );

use Isolated\Symfony\Component\Finder\Finder;

// WordPress core symbols (class/interface/function/constant) must never be
// prefixed. The generated lists are bundled under bin/scoper-excludes/; fall back
// to the sniccowp package when it is installed (dev).
$wp_excludes = static function ( string $type ): array {
	$candidates = array(
		__DIR__ . '/bin/scoper-excludes/exclude-wordpress-' . $type . '.json',
		__DIR__ . '/vendor/sniccowp/php-scoper-wordpress-excludes/generated/exclude-wordpress-' . $type . '.json',
	);
	foreach ( $candidates as $file ) {
		if ( is_readable( $file ) ) {
			$data = json_decode( (string) file_get_contents( $file ), true );
			return is_array( $data ) ? $data : array();
		}
	}
	return array();
};

// Namespaces provided by the host at runtime, never bundled — must not be
// prefixed. (Composer is deliberately NOT excluded: it is prefixed so two plugins
// cannot collide on Composer\InstalledVersions; the patcher below fixes the one
// bootstrap string PHP-Scoper misses.)
$external_namespaces = array( 'WordfenceLS', 'WP_CLI' );

// Global (namespace-less) classes provided by other tools/plugins we only detect.
// WP-CLI exposes both a root `WP_CLI` class and a `WP_CLI\` namespace, so it is
// listed here (class) as well as in $external_namespaces (namespace). `WooCommerce`
// and `WC_*` are WooCommerce runtime classes.
$external_classes = array( 'Two_Factor_Core', 'WooCommerce', 'WP_CLI', '~^WC_~' );

// Global (namespace-less) FUNCTIONS provided by other plugins at runtime. `WC()`
// is WooCommerce's main-instance accessor; leaving it out would let PHP-Scoper
// prefix the `function_exists('WC')` guard AND emit a global `WC()` alias that
// forwards to a non-existent RaplsPasskey\Vendor\WC() (breaks WooCommerce
// detection and can fatal other plugins). Exclude WC and the wc_* family.
$external_functions = array( 'WC', '~^wc_~', '~^woocommerce~i' );

return array(
	'prefix' => 'RaplsPasskey\\Vendor',

	'finders' => array(
		// The plugin's own source (its `use Webauthn\…` references get rewritten;
		// its own `RaplsPasskey\…` namespace is left alone — see exclude-namespaces).
		Finder::create()->files()->ignoreVCS( true )->name( '*.php' )->in( 'src' ),
		// The bundled libraries, minus their dev/test/doc cruft.
		Finder::create()->files()->ignoreVCS( true )->name( '*.php' )
			->exclude( array( 'bin', 'doc', 'docs', 'test', 'tests', 'Tests', 'examples' ) )
			->in( 'vendor' ),
		// Root runtime files.
		Finder::create()->append( array( 'rapls-passkey.php', 'uninstall.php' ) ),
	),

	// Keep the plugin's own namespace, Composer's autoloader, and detected
	// third-party plugin namespaces unprefixed — only bundled libraries are scoped.
	'exclude-namespaces' => array_merge(
		array( '~^RaplsPasskey(\\\\|$)~' ),
		array_map( static fn ( $ns ) => '~^' . preg_quote( $ns, '~' ) . '(\\\\|$)~', $external_namespaces )
	),

	// WordPress (and the plugin's own constants) are external: do not prefix them.
	'exclude-classes'    => array_merge( $wp_excludes( 'classes' ), $wp_excludes( 'interfaces' ), $external_classes ),
	'exclude-functions'  => array_merge( $wp_excludes( 'functions' ), $external_functions ),
	'exclude-constants'  => array_merge(
		$wp_excludes( 'constants' ),
		array( '~^RAPLS_PASSKEY_~', 'ABSPATH' )
	),

	'patchers' => array(
		// PHP-Scoper prefixes `new \<prefix>\Composer\Autoload\ClassLoader` in the
		// generated vendor/composer/autoload_real.php, but leaves the string guard
		// in loadClassLoader() (`'Composer\Autoload\ClassLoader' === $class`)
		// unprefixed — so the bootstrap ClassLoader never loads and every scoped
		// class fails to resolve. Patch the guard to the prefixed name.
		static function ( string $file_path, string $prefix, string $contents ): string {
			if ( 'autoload_real.php' !== basename( $file_path ) ) {
				return $contents;
			}
			return str_replace(
				"'Composer\\\\Autoload\\\\ClassLoader'",
				"'" . str_replace( '\\', '\\\\', $prefix ) . "\\\\Composer\\\\Autoload\\\\ClassLoader'",
				$contents
			);
		},
	),
);
