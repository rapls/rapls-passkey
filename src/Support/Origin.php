<?php
/**
 * Origin comparison helper.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Compares a request Origin/Referer against the site origin. Unlike a bare host
 * match, this normalises scheme and port so `http://example.com` and
 * `https://example.com`, or the same host on a different port, are treated as
 * distinct origins — the same rule WebAuthn itself applies.
 */
final class Origin {

	/**
	 * Does $source share this site's origin (scheme + host + effective port)?
	 *
	 * @param string $source A URL from the Origin or Referer header.
	 * @return bool
	 */
	public static function matches_site( string $source ): bool {
		$candidate = self::normalise( $source );
		if ( '' === $candidate ) {
			return false;
		}
		foreach ( array( home_url(), site_url() ) as $site ) {
			if ( self::normalise( (string) $site ) === $candidate ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Reduce a URL to `scheme://host:port`, filling in the default port for the
	 * scheme so an explicit-vs-implicit port does not cause a false mismatch.
	 * Returns '' when the URL has no scheme or host.
	 *
	 * @param string $url URL to normalise.
	 * @return string
	 */
	public static function normalise( string $url ): string {
		$scheme = wp_parse_url( $url, PHP_URL_SCHEME );
		$host   = wp_parse_url( $url, PHP_URL_HOST );
		if ( ! $scheme || ! $host ) {
			return '';
		}
		$scheme = strtolower( $scheme );
		$host   = strtolower( $host );
		$port   = wp_parse_url( $url, PHP_URL_PORT );
		if ( ! $port ) {
			$port = 'https' === $scheme ? 443 : ( 'http' === $scheme ? 80 : 0 );
		}
		return $scheme . '://' . $host . ':' . (int) $port;
	}
}
