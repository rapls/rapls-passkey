<?php
/**
 * Sending a cookie, as one call that can be observed.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

defined( 'ABSPATH' ) || exit;

/**
 * A seam around setcookie().
 */
final class Cookies {

	/**
	 * Send a cookie, and say whether it went.
	 *
	 * The callers care about the answer — a challenge whose token the browser
	 * never receives is a screen the user cannot complete — and on the CLI, and
	 * inside a packaged build where calls to PHP built-ins are fully qualified,
	 * setcookie() cannot be stood in for. One method can be.
	 *
	 * @param string              $name    Cookie name.
	 * @param string              $value   Value.
	 * @param array<string,mixed> $options Options (expires, path, …).
	 * @return bool False when headers have already gone out, or the send failed.
	 */
	public static function set( string $name, string $value, array $options ): bool {
		if ( headers_sent() ) {
			return false;
		}
		return setcookie( $name, $value, $options );
	}
}
