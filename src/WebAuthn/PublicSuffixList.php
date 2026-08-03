<?php
/**
 * Public Suffix List matcher.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

defined( 'ABSPATH' ) || exit;

/**
 * Answers "is this domain a public suffix?" using the Mozilla Public Suffix List
 * (https://publicsuffix.org/). WebAuthn forbids a public suffix as the RP ID —
 * a credential bound to "com", "co.jp", "github.io" or "appspot.com" would be
 * shared across every site under it — and, as the PSL project itself states, the
 * registration boundary cannot be derived algorithmically, so the list is
 * required for a correct answer.
 *
 * A snapshot of the list ships in data/public_suffix_list.dat and is parsed once
 * per request. If that file is missing or unreadable, this degrades to a small
 * built-in heuristic (single-label hosts plus a short denylist) so RP ID
 * validation never hard-fails — the default RP ID (the site host) is safe either
 * way; the list only hardens against a misconfigured rapls_passkey_rp_id filter.
 */
final class PublicSuffixList {

	/**
	 * Parsed rules, or false before loading. Shape:
	 * [ 'normal' => set, 'wildcard' => set (parent domains), 'exception' => set ].
	 *
	 * @var array<string,array<string,bool>>|false|null
	 */
	private static $rules = null;

	/**
	 * Fallback multi-label public suffixes used only when the PSL file is absent.
	 * Deliberately short — it is a safety net, not a substitute for the list.
	 *
	 * @var string[]
	 */
	private const FALLBACK_DENY = array(
		'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'gr.jp',
		'com.au', 'net.au', 'org.au', 'co.uk', 'org.uk', 'me.uk',
		'com.br', 'co.kr', 'co.nz', 'co.za', 'com.cn', 'com.hk',
		'com.sg', 'com.tw', 'com.mx', 'co.in', 'com.tr',
	);

	/**
	 * Is $domain exactly a public suffix (i.e. not itself a registrable domain)?
	 *
	 * @param string $domain Lower-cased host with no trailing dot.
	 * @return bool
	 */
	public static function is_public_suffix( string $domain ): bool {
		$domain = strtolower( trim( $domain, " \t\n\r\0\x0B." ) );
		if ( '' === $domain ) {
			return false;
		}

		$rules = self::rules();
		if ( array() === $rules ) {
			return self::heuristic( $domain );
		}

		$labels = explode( '.', $domain );
		$suffix = self::public_suffix_labels( $labels, $rules );

		// $domain is a public suffix when it equals its own computed public suffix.
		return implode( '.', $suffix ) === $domain;
	}

	/**
	 * Compute the public-suffix labels of a domain per the PSL algorithm:
	 * an exception rule wins outright; otherwise the longest matching normal or
	 * wildcard rule prevails; with no match, the default rule "*" applies (the
	 * rightmost label).
	 *
	 * @param string[]                        $labels Domain labels (TLD last).
	 * @param array<string,array<string,bool>> $rules Parsed rule sets.
	 * @return string[] The public-suffix labels.
	 */
	private static function public_suffix_labels( array $labels, array $rules ): array {
		$n = count( $labels );

		// Exception rules take priority; the public suffix drops the rule's first label.
		for ( $i = 0; $i < $n; $i++ ) {
			$candidate = implode( '.', array_slice( $labels, $i ) );
			if ( isset( $rules['exception'][ $candidate ] ) ) {
				return array_slice( $labels, $i + 1 );
			}
		}

		$best = 0; // Number of labels in the matched public suffix.
		for ( $i = 0; $i < $n; $i++ ) {
			$count     = $n - $i;
			$candidate = implode( '.', array_slice( $labels, $i ) );
			if ( isset( $rules['normal'][ $candidate ] ) && $count > $best ) {
				$best = $count;
			}
			// A wildcard rule "*.parent" matches when the candidate's parent (its
			// labels minus the leftmost) is a registered wildcard base.
			if ( $count >= 2 ) {
				$parent = implode( '.', array_slice( $labels, $i + 1 ) );
				if ( isset( $rules['wildcard'][ $parent ] ) && $count > $best ) {
					$best = $count;
				}
			}
		}

		if ( 0 === $best ) {
			$best = 1; // Default rule "*": the rightmost label is the public suffix.
		}
		return array_slice( $labels, $n - $best );
	}

	/**
	 * Load and parse the bundled list once per request. Returns an empty array
	 * when the file is unavailable (callers then use the heuristic).
	 *
	 * @return array<string,array<string,bool>>
	 */
	private static function rules(): array {
		if ( null !== self::$rules ) {
			return self::$rules ?: array();
		}
		self::$rules = false;

		$path = defined( 'RAPLS_PASSKEY_DIR' ) ? RAPLS_PASSKEY_DIR . 'data/public_suffix_list.dat' : '';
		if ( '' === $path || ! is_readable( $path ) ) {
			return array();
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$contents = file_get_contents( $path );
		if ( false === $contents || '' === $contents ) {
			return array();
		}

		$rules = array(
			'normal'    => array(),
			'wildcard'  => array(),
			'exception' => array(),
		);
		foreach ( preg_split( '/\R/', $contents ) ?: array() as $line ) {
			$line = trim( $line );
			if ( '' === $line || 0 === strpos( $line, '//' ) ) {
				continue; // Blank line or comment.
			}
			// A rule may carry a trailing comment; the rule is the first token.
			$rule = strtolower( strtok( $line, " \t" ) );
			if ( '' === $rule ) {
				continue;
			}
			if ( '!' === $rule[0] ) {
				$rules['exception'][ substr( $rule, 1 ) ] = true;
			} elseif ( 0 === strpos( $rule, '*.' ) ) {
				$rules['wildcard'][ substr( $rule, 2 ) ] = true;
			} else {
				$rules['normal'][ $rule ] = true;
			}
		}

		self::$rules = $rules;
		return $rules;
	}

	/**
	 * The safety-net heuristic used only when the PSL file is unavailable.
	 *
	 * @param string $domain Lower-cased host.
	 * @return bool
	 */
	private static function heuristic( string $domain ): bool {
		if ( false === strpos( $domain, '.' ) ) {
			return true; // A single label is a TLD / public suffix.
		}
		return in_array( $domain, self::FALLBACK_DENY, true );
	}
}
