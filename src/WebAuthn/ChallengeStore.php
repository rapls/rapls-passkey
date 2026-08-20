<?php
/**
 * Short-lived, single-use ceremony state store.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use ParagonIE\ConstantTime\Base64UrlSafe;
use RaplsPasskey\Support\OneTimeStore;

defined( 'ABSPATH' ) || exit;

/**
 * Holds the pending ceremony options (which contain the challenge) server-side
 * between the "options" and "verify" requests.
 *
 * A random opaque state id is handed to the browser; the options JSON is kept
 * against that id. Reading consumes the entry (single use), and the lifetime is
 * capped — together these defeat challenge replay without coupling to PHP
 * sessions.
 *
 * The state lives in {@see OneTimeStore}, which addresses the database directly,
 * rather than in a transient. A transient goes to the object cache when one is
 * installed, and an object cache is not guaranteed to be shared between PHP
 * workers: the ceremony written while answering `login/options` was then missing
 * when a different worker answered `login/verify`, and a correct passkey was
 * refused as expired. The single-use claim had the same dependency and could be
 * won twice. See OneTimeStore for the full account.
 */
final class ChallengeStore {

	/** Ceremony lifetime in seconds (covers slower cross-device ceremonies). */
	private const TTL = 600;

	/**
	 * Persist ceremony options and return the opaque state id.
	 *
	 * The id is only worth anything if the ceremony behind it was actually stored:
	 * handing one out regardless produces options the browser can act on and the
	 * server can never verify — a registration whose credential is created on the
	 * authenticator and then rejected here, leaving the user with a passkey that
	 * belongs to nothing. So a store that says it failed makes this throw, and the
	 * caller turns that into a refusal.
	 *
	 * @param string $payload Options JSON to retrieve later.
	 * @return string State id handed to the browser.
	 * @throws \RuntimeException When the ceremony could not be stored.
	 */
	public function put( string $payload ): string {
		$state = Base64UrlSafe::encodeUnpadded( random_bytes( 32 ) );
		if ( ! OneTimeStore::put( $state, $payload, self::TTL ) ) {
			throw new \RuntimeException( 'ceremony_not_stored' );
		}
		return $state;
	}

	/**
	 * Fetch and delete the stored options for a state id (single use).
	 *
	 * The claim is atomic across concurrent requests, so two verifies submitted
	 * with the same state cannot both consume one challenge: exactly one caller
	 * wins the delete race and receives the payload; the loser gets null.
	 *
	 * @param string $state State id from the browser.
	 * @return string|null Stored options JSON, or null if absent/expired/lost the race.
	 */
	public function take( string $state ): ?string {
		if ( '' === $state || ! preg_match( '/^[A-Za-z0-9_-]{1,128}$/', $state ) ) {
			return null;
		}
		return OneTimeStore::take( $state );
	}
}
