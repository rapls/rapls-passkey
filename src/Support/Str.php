<?php
/**
 * Small string helpers with safe fallbacks.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Multibyte-aware helpers that degrade gracefully where the mbstring extension
 * is unavailable (PHP can be built without it), so no code path fatals.
 */
final class Str {

	/**
	 * mb_substr() when available, otherwise substr(). Truncation falls back to a
	 * byte-wise cut, which is acceptable for length-capping display values.
	 *
	 * @param string   $text   Subject string.
	 * @param int      $start  Start offset.
	 * @param int|null $length Length, or null for "to the end".
	 * @return string
	 */
	public static function substr( string $text, int $start, ?int $length = null ): string {
		if ( function_exists( 'mb_substr' ) ) {
			return null === $length ? mb_substr( $text, $start ) : mb_substr( $text, $start, $length );
		}
		return null === $length ? substr( $text, $start ) : substr( $text, $start, $length );
	}
}
