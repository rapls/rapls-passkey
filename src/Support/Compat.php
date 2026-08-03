<?php
/**
 * Coexistence with common login-security plugins.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Detects well-known security plugins (Wordfence, SiteGuard WP Plugin,
 * CloudSecure WP Security, …) so the admin can be told how rapls-passkey
 * coexists with them.
 *
 * Coexistence is by design, not by patching: the plugin only uses standard
 * login hooks (login_form / login_enqueue_scripts), fires do_action('wp_login')
 * on success so other plugins' alerts and logs still run, keeps its REST routes
 * under their own namespace, and exposes the `rapls_passkey_recaptcha_active`
 * filter so a site already running a login CAPTCHA can disable ours.
 */
final class Compat {

	/**
	 * Known plugins: label => [ class-or-constant checks, active_plugins slug ].
	 *
	 * @return array<string,array{checks:string[],slug:string}>
	 */
	private static function known(): array {
		return array(
			'Wordfence'               => array(
				'checks' => array( 'WORDFENCE_VERSION', 'wordfence' ),
				'slug'   => 'wordfence/',
			),
			'Wordfence Login Security' => array(
				'checks' => array( 'WordfenceLS\\Controller_Settings' ),
				'slug'   => 'wordfence-login-security/',
			),
			'SiteGuard WP Plugin'     => array(
				'checks' => array( 'SITEGUARD_PATH', 'SiteGuard_Base', 'SiteGuard' ),
				'slug'   => 'siteguard/',
			),
			'CloudSecure WP Security' => array(
				'checks' => array( 'IP_GEO_BLOCK_NAME' ),
				'slug'   => 'cloudsecure-wp-security/',
			),
			'Two-Factor'              => array(
				'checks' => array( 'Two_Factor_Core' ),
				'slug'   => 'two-factor/',
			),
			'WP 2FA'                  => array(
				'checks' => array( 'WP2FA\\WP2FA' ),
				'slug'   => 'wp-2fa/',
			),
		);
	}

	/**
	 * Names of detected, active security plugins.
	 *
	 * @return string[]
	 */
	public static function detect(): array {
		$active = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}

		$found = array();
		foreach ( self::known() as $label => $meta ) {
			if ( self::matches( $meta, $active ) ) {
				$found[] = $label;
			}
		}
		return $found;
	}

	/**
	 * Does a known plugin's class/constant exist, or its slug appear in the
	 * active-plugins list?
	 *
	 * @param array{checks:string[],slug:string} $meta   Plugin metadata.
	 * @param string[]                            $active Active plugin basenames.
	 * @return bool
	 */
	private static function matches( array $meta, array $active ): bool {
		foreach ( $meta['checks'] as $symbol ) {
			if ( defined( $symbol ) || class_exists( $symbol ) ) {
				return true;
			}
		}
		foreach ( $active as $basename ) {
			if ( 0 === strpos( (string) $basename, $meta['slug'] ) ) {
				return true;
			}
		}
		return false;
	}
}
