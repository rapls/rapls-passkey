<?php
/**
 * Relying Party identity.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use Webauthn\PublicKeyCredentialRpEntity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

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
		$scheme = (string) ( wp_parse_url( $home, PHP_URL_SCHEME ) ?: 'https' );
		$port   = wp_parse_url( $home, PHP_URL_PORT );

		$origin = $scheme . '://' . $host;
		if ( $port ) {
			$origin .= ':' . $port;
		}

		$name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' === $name ) {
			$name = $host;
		}

		return new self( $host, $name, $origin );
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
	 * The library RP entity used when building creation options.
	 *
	 * @return PublicKeyCredentialRpEntity
	 */
	public function entity(): PublicKeyCredentialRpEntity {
		return PublicKeyCredentialRpEntity::create( $this->name, $this->id );
	}
}
