<?php
/**
 * Short-lived, single-use ceremony state store.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use ParagonIE\ConstantTime\Base64UrlSafe;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Holds the pending ceremony options (which contain the challenge) server-side
 * between the "options" and "verify" requests.
 *
 * A random opaque state id is handed to the browser; the options JSON is kept in
 * a transient keyed by that id. Reading consumes the entry (single use), and the
 * transient TTL caps the ceremony lifetime — together these defeat challenge
 * replay without coupling to PHP sessions.
 */
final class ChallengeStore {

	/** Transient key prefix. */
	private const PREFIX = 'rapls_passkey_cer_';

	/** Ceremony lifetime in seconds (covers slower cross-device ceremonies). */
	private const TTL = 600;

	/**
	 * Persist ceremony options and return the opaque state id.
	 *
	 * @param string $payload Options JSON to retrieve later.
	 * @return string State id handed to the browser.
	 */
	public function put( string $payload ): string {
		$state = Base64UrlSafe::encodeUnpadded( random_bytes( 32 ) );
		set_transient( self::PREFIX . $state, $payload, self::TTL );
		return $state;
	}

	/**
	 * Fetch and delete the stored options for a state id (single use).
	 *
	 * @param string $state State id from the browser.
	 * @return string|null Stored options JSON, or null if absent/expired.
	 */
	public function take( string $state ): ?string {
		if ( '' === $state || ! preg_match( '/^[A-Za-z0-9_-]{1,128}$/', $state ) ) {
			return null;
		}
		$key     = self::PREFIX . $state;
		$payload = get_transient( $key );
		delete_transient( $key );

		return is_string( $payload ) ? $payload : null;
	}
}
