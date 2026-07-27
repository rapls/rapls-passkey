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
		if ( ! set_transient( self::PREFIX . $state, $payload, self::TTL ) ) {
			throw new \RuntimeException( 'ceremony_not_stored' );
		}
		return $state;
	}

	/**
	 * Fetch and delete the stored options for a state id (single use).
	 *
	 * The claim is atomic across concurrent requests, so two verifies submitted
	 * with the same state cannot both consume one challenge: exactly one caller
	 * wins the delete/add race and receives the payload; the loser gets null.
	 *
	 * @param string $state State id from the browser.
	 * @return string|null Stored options JSON, or null if absent/expired/lost the race.
	 */
	public function take( string $state ): ?string {
		if ( '' === $state || ! preg_match( '/^[A-Za-z0-9_-]{1,128}$/', $state ) ) {
			return null;
		}
		$key     = self::PREFIX . $state;
		$payload = get_transient( $key );
		if ( ! is_string( $payload ) ) {
			return null;
		}

		return $this->claim( $key ) ? $payload : null;
	}

	/**
	 * Atomically claim (consume) a challenge entry. Returns true only for the
	 * single caller that won the race.
	 *
	 * @param string $key Transient key.
	 * @return bool
	 */
	private function claim( string $key ): bool {
		if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
			// A persistent object cache is shared across PHP processes, so an
			// atomic add on a lock key decides the single winner.
			$won = wp_cache_add( 'claim_' . $key, 1, 'rapls_passkey', self::TTL );
			delete_transient( $key );
			return (bool) $won;
		}

		// DB-backed transients: an affected-row DELETE is the atomic claim.
		global $wpdb;
		if ( ! isset( $wpdb ) || ! is_object( $wpdb ) || ! method_exists( $wpdb, 'delete' ) ) {
			// No usable DB layer (e.g. a minimal CLI context): best-effort delete.
			delete_transient( $key );
			return true;
		}
		$rows = $wpdb->delete( $wpdb->options, array( 'option_name' => '_transient_' . $key ) ); // phpcs:ignore WordPress.DB
		$wpdb->delete( $wpdb->options, array( 'option_name' => '_transient_timeout_' . $key ) ); // phpcs:ignore WordPress.DB
		if ( false === $rows ) {
			// A query error must not let a challenge be replayed — fail closed. The
			// worst case is a single failed login the user can simply retry.
			delete_transient( $key );
			return false;
		}
		return $rows > 0;
	}
}
