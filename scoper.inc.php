<?php
/**
 * PHP-Scoper configuration.
 *
 * Rewrites the bundled third-party libraries (web-auth/webauthn-lib, Symfony,
 * Brick, spomky-labs, ParagonIE, …) into the plugin-private namespace prefix
 * `RaplsPasskey\Vendor\…` at build time, so another plugin that bundles a
 * different version of the same library cannot collide with ours (fatal errors
 * / signature mismatches). The committed source stays unscoped; only the
 * distribution build produced by bin/build-dist.sh is prefixed.
 *
 * Run with the php-scoper PHAR (bin/php-scoper.phar); the WordPress exclude lists
 * from sniccowp/php-scoper-wordpress-excludes are optional (see the fallback in
 * $wp_excludes below). See docs/vendor-prefixing.md.
 *
 * @package RaplsPasskey
 */

declare( strict_types=1 );

use Isolated\Symfony\Component\Finder\Finder;

// WordPress core symbols must never be prefixed. The sniccowp package ships the
// authoritative generated lists; if it is absent we fall back to empty lists
// (php-scoper still leaves undefined global functions/classes alone).
$wp_excludes = static function ( string $type ): array {
	$file = __DIR__ . '/vendor/sniccowp/php-scoper-wordpress-excludes/generated/exclude-wordpress-' . $type . '.json';
	if ( ! is_readable( $file ) ) {
		return array();
	}
	$data = json_decode( (string) file_get_contents( $file ), true );
	return is_array( $data ) ? $data : array();
};

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

	// Keep the plugin's own namespace unprefixed — only third-party code is scoped.
	'exclude-namespaces' => array( '~^RaplsPasskey(\\\\|$)~' ),

	// WordPress (and the plugin's own constants) are external: do not prefix them.
	'exclude-classes'    => $wp_excludes( 'classes' ),
	'exclude-functions'  => $wp_excludes( 'functions' ),
	'exclude-constants'  => array_merge(
		$wp_excludes( 'constants' ),
		array( '~^RAPLS_PASSKEY_~', 'ABSPATH' )
	),
);
