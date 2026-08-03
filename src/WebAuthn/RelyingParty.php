<?php
/**
 * Relying Party identity.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use Webauthn\PublicKeyCredentialRpEntity;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the WebAuthn Relying Party (RP) identity from the site.
 *
 * The RP ID is the registrable domain (host) the credentials are bound to, and
 * the origin is the scheme://host[:port] the browser ceremony runs against.
 * Both are derived from the site home URL so a single source drives them.
 */
final class RelyingParty {

	/**
	 * @param string $id     RP ID — the host, e.g. "example.com".
	 * @param string $name   Human-readable RP name shown by authenticators.
	 * @param string $origin Full origin, e.g. "https://example.com".
	 */
	public function __construct(
		private string $id,
		private string $name,
		private string $origin
	) {}

	/**
	 * Build from the WordPress site URL.
	 *
	 * @return RelyingParty
	 */
	public static function from_site(): RelyingParty {
		$home   = home_url();
		$host   = (string) wp_parse_url( $home, PHP_URL_HOST );
		$origin = self::browser_origin( $home );

		$name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $name ) {
			$name = $host;
		}

		/**
		 * Filter the RP ID. Must be the host, a registrable parent domain of it
		 * (e.g. "example.com" for "site1.example.com"), or — with Related Origin
		 * Requests configured — a shared cross-domain RP ID. Note that sharing the
		 * RP ID only aligns the WebAuthn protocol; a passkey is still usable on
		 * another site only when that site shares the same user and stored
		 * credential (see the Pro plugin's related-origins notes).
		 *
		 * @param string $host The site host (default RP ID).
		 * @param string $home The site home URL.
		 */
		$id = (string) apply_filters( 'rapls_passkey_rp_id', $host, $home );

		// The RP ID must be the site host or a registrable parent of it (e.g.
		// "example.com" for "site1.example.com"); anything else would make every
		// passkey fail to register/verify. Fall back to the host on a bad value.
		if ( ! self::is_valid_rp_id( $id, $host ) ) {
			$id = $host;
		}

		/**
		 * Filter the RP display name shown by authenticators.
		 *
		 * @param string $name Default RP name.
		 */
		$name = (string) apply_filters( 'rapls_passkey_rp_name', $name );

		return new self( $id, $name, $origin );
	}

	/**
	 * Whether $id is a valid RP ID for the given host: equal to it, or a
	 * registrable parent domain (a dot-bounded suffix) of it.
	 *
	 * @param string $id   Candidate RP ID.
	 * @param string $host Site host.
	 * @return bool
	 */
	public static function is_valid_rp_id( string $id, string $host ): bool {
		$id   = strtolower( trim( $id ) );
		$host = strtolower( trim( $host ) );
		if ( '' === $id || '' === $host ) {
			return false;
		}
		// WebAuthn forbids a public suffix as the RP ID (a passkey bound to "com" or
		// "co.jp" would be shared across every site under it). localhost is exempt
		// for local development.
		if ( 'localhost' !== $id && self::is_public_suffix( $id ) ) {
			return false;
		}
		if ( $id === $host ) {
			return true;
		}
		// A parent domain: host must end with ".{$id}".
		$suffix = '.' . $id;
		if ( substr( $host, - strlen( $suffix ) ) === $suffix ) {
			return true;
		}
		// Related Origin Requests: a member site legitimately uses a shared RP ID on
		// a different registrable domain. Accept it when this site's own origin is
		// one of the authorized related origins (the browser still enforces the RP
		// ID's /.well-known/webauthn manifest, so a rogue value cannot be used).
		return self::host_in_related_origins( $host );
	}

	/**
	 * The authorized cross-domain origins (Related Origin Requests), normalised to
	 * browser origin form. Empty unless a site opts in via the filter (Pro's
	 * "related origins" setting wires it).
	 *
	 * @return string[]
	 */
	public static function related_origins(): array {
		/**
		 * Origins authorized to use this site's passkeys cross-domain (Related
		 * Origin Requests). Each is a full origin, e.g. "https://shop.example".
		 *
		 * @param string[] $origins Authorized origins.
		 */
		$raw = (array) apply_filters( 'rapls_passkey/related_origins', array() );

		$out = array();
		foreach ( $raw as $origin ) {
			$norm = self::browser_origin( (string) $origin );
			if ( '' !== $norm && ! in_array( $norm, $out, true ) ) {
				$out[] = $norm;
			}
		}
		return $out;
	}

	/**
	 * Is $host the host of one of the authorized related origins?
	 *
	 * @param string $host Host to check.
	 * @return bool
	 */
	private static function host_in_related_origins( string $host ): bool {
		foreach ( self::related_origins() as $origin ) {
			if ( strtolower( (string) wp_parse_url( $origin, PHP_URL_HOST ) ) === $host ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether $id is a public suffix and therefore forbidden as an RP ID. The
	 * authoritative answer comes from the bundled Public Suffix List; a site can
	 * add further suffixes with the rapls_passkey_rp_id_public_suffixes filter.
	 *
	 * @param string $id Candidate RP ID (lower-cased).
	 * @return bool
	 */
	private static function is_public_suffix( string $id ): bool {
		if ( PublicSuffixList::is_public_suffix( $id ) ) {
			return true;
		}
		/** Filter: extra public suffixes an RP ID may not be set to. */
		$deny = (array) apply_filters( 'rapls_passkey_rp_id_public_suffixes', array() );
		return in_array( $id, array_map( 'strtolower', array_map( 'strval', $deny ) ), true );
	}

	/**
	 * RP ID (host).
	 *
	 * @return string
	 */
	public function id(): string {
		return $this->id;
	}

	/**
	 * RP display name.
	 *
	 * @return string
	 */
	public function name(): string {
		return $this->name;
	}

	/**
	 * Full origin (scheme://host[:port]).
	 *
	 * @return string
	 */
	public function origin(): string {
		return $this->origin;
	}

	/**
	 * All origins the WebAuthn verifier should accept for this site. This is the
	 * primary origin (from the Site Address / home_url) plus the WordPress Address
	 * (site_url) origin when it differs — so an install whose login screen runs on
	 * a different scheme/host/port than the public site still verifies, matching
	 * the REST same-origin gate (Support\Origin::matches_site) exactly.
	 *
	 * @return string[] Unique browser-formatted origins (default ports omitted).
	 */
	public function allowed_origins(): array {
		$origins = array( $this->origin );
		if ( function_exists( 'site_url' ) ) {
			$site = self::browser_origin( (string) site_url() );
			if ( '' !== $site && ! in_array( $site, $origins, true ) ) {
				$origins[] = $site;
			}
		}
		// Authorized cross-domain origins (Related Origin Requests) so an assertion
		// carried out from a member domain verifies against the shared RP ID.
		foreach ( self::related_origins() as $origin ) {
			if ( ! in_array( $origin, $origins, true ) ) {
				$origins[] = $origin;
			}
		}
		return $origins;
	}

	/**
	 * Reduce a URL to a browser-formatted origin (scheme://host[:port]), omitting
	 * the default port for the scheme so it matches what a browser sends in the
	 * Origin header.
	 *
	 * @param string $url URL to reduce.
	 * @return string Origin, or '' if the URL lacks a host.
	 */
	private static function browser_origin( string $url ): string {
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		if ( '' === $host ) {
			return '';
		}
		$scheme = (string) ( wp_parse_url( $url, PHP_URL_SCHEME ) ?: 'https' );
		$port   = wp_parse_url( $url, PHP_URL_PORT );
		$origin = $scheme . '://' . $host;
		$default = 'https' === $scheme ? 443 : ( 'http' === $scheme ? 80 : 0 );
		if ( $port && (int) $port !== $default ) {
			$origin .= ':' . (int) $port;
		}
		return $origin;
	}

	/**
	 * The library RP entity used when building creation options.
	 *
	 * @return PublicKeyCredentialRpEntity
	 */
	public function entity(): PublicKeyCredentialRpEntity {
		return PublicKeyCredentialRpEntity::create( $this->name, $this->id );
	}
}
