<?php
/**
 * REST endpoints for the registration and authentication ceremonies.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Rest;

use ParagonIE\ConstantTime\Base64UrlSafe;
use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Credentials\UserHandle;
use RaplsPasskey\WebAuthn\AssertionManager;
use RaplsPasskey\Support\RateLimit;
use RaplsPasskey\Support\Settings;
use RaplsPasskey\Support\Str;
use RaplsPasskey\WebAuthn\Codec;
use RaplsPasskey\WebAuthn\RegistrationManager;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the four ceremony endpoints plus credential deletion under the
 * `rapls-passkey/v1` namespace.
 */
final class Endpoints {

	/** REST namespace. */
	private const NS = 'rapls-passkey/v1';

	/** How many entries a username-bearing allow-list always contains. */
	private const ALLOW_LIST_SIZE = 4;

	/**
	 * @param RegistrationManager  $registration Registration ceremony.
	 * @param AssertionManager     $assertion    Authentication ceremony.
	 * @param CredentialRepository $repository   Credential storage.
	 * @param Codec                $codec        Serialisation bridge.
	 */
	public function __construct(
		private RegistrationManager $registration,
		private AssertionManager $assertion,
		private CredentialRepository $repository,
		private Codec $codec
	) {}

	/**
	 * Hook route registration.
	 */
	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Declare the routes.
	 */
	public function register_routes(): void {
		register_rest_route(
			self::NS,
			'/register/options',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'register_options' ),
				'permission_callback' => array( $this, 'require_logged_in' ),
			)
		);
		register_rest_route(
			self::NS,
			'/register/verify',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'register_verify' ),
				'permission_callback' => array( $this, 'require_logged_in' ),
			)
		);
		register_rest_route(
			self::NS,
			'/login/options',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'login_options' ),
				'permission_callback' => array( $this, 'public_login_gate_strict' ),
			)
		);
		register_rest_route(
			self::NS,
			'/login/verify',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'login_verify' ),
				'permission_callback' => array( $this, 'public_login_gate' ),
			)
		);
		register_rest_route(
			self::NS,
			'/credentials/(?P<id>\d+)',
			array(
				array(
					'methods'             => WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'delete_credential' ),
					'permission_callback' => array( $this, 'require_logged_in' ),
				),
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'update_credential' ),
					'permission_callback' => array( $this, 'require_logged_in' ),
				),
			)
		);
	}

	// --- Permission callbacks ------------------------------------------------

	/**
	 * Logged-in gate. WordPress core also enforces the X-WP-Nonce cookie nonce
	 * for these routes.
	 *
	 * @return bool
	 */
	public function require_logged_in(): bool {
		return is_user_logged_in();
	}

	/**
	 * Public gate for the anonymous login routes.
	 *
	 * The login ceremony must work whether or not a user is currently logged in,
	 * so it cannot rely on a user-bound WordPress nonce. CSRF is instead defeated
	 * by WebAuthn itself (origin binding, a single-use server challenge, and the
	 * need for the authenticator's private key). We add a same-origin check and a
	 * per-IP rate limit as defence in depth.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool|WP_Error
	 */
	public function public_login_gate( WP_REST_Request $request ) {
		return $this->login_gate( $request, false );
	}

	/**
	 * Stricter gate for the pre-verify login step (/login/options): a request
	 * with no Origin and no Referer is rejected. The verify step stays lenient
	 * because WebAuthn binds the ceremony to the real origin there.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool|WP_Error
	 */
	public function public_login_gate_strict( WP_REST_Request $request ) {
		return $this->login_gate( $request, true );
	}

	/**
	 * Shared login gate: same-origin (optionally strict) plus a per-IP rate limit.
	 *
	 * The rate limit is checked here read-only. It is only *incremented* on a
	 * failed assertion (see {@see login_verify}) — never on /login/options, which
	 * the browser legitimately calls several times per page (autofill / conditional
	 * UI). Counting option requests would otherwise exhaust a small limit before
	 * the user even submits a passkey. A successful login clears the counter.
	 *
	 * @param WP_REST_Request $request Request.
	 * @param bool            $strict  Reject when Origin and Referer are both absent.
	 * @return bool|WP_Error
	 */
	private function login_gate( WP_REST_Request $request, bool $strict ) {
		if ( ! $this->same_origin( $request, $strict ) ) {
			return new WP_Error( 'rapls_passkey_bad_origin', __( 'Invalid request.', 'rapls-passkey' ), array( 'status' => 403 ) );
		}
		if ( $this->rate_limited( 'login' ) ) {
			return new WP_Error( 'rapls_passkey_rate_limited', __( 'Too many attempts. Please try again later.', 'rapls-passkey' ), array( 'status' => 429 ) );
		}
		return true;
	}

	/**
	 * Confirm the request originates from this site (Origin/Referer host match).
	 * When not strict, both headers absent is allowed — WebAuthn still binds the
	 * ceremony to the real origin during verification.
	 *
	 * @param WP_REST_Request $request Request.
	 * @param bool            $strict  Reject when Origin and Referer are both absent.
	 * @return bool
	 */
	private function same_origin( WP_REST_Request $request, bool $strict = false ): bool {
		$source = $request->get_header( 'origin' );
		if ( ! $source ) {
			$source = $request->get_header( 'referer' );
		}
		if ( ! $source ) {
			return ! $strict;
		}

		return \RaplsPasskey\Support\Origin::matches_site( (string) $source );
	}

	// --- Registration --------------------------------------------------------

	/**
	 * Issue creation options for the current user.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function register_options( WP_REST_Request $request ) {
		$user = $this->enrolment_target( $request );
		if ( $user instanceof WP_Error ) {
			return $user;
		}

		$limit = $this->limit_error( (int) $user->ID );
		if ( null !== $limit ) {
			return $limit;
		}

		// Build the exclude list from the user's existing credentials. A single
		// corrupt row must not break enrolment of a new passkey, so decode each row
		// in isolation and skip (and flag) any that cannot be parsed — the worst
		// case is that one unusable credential is missing from the exclude list.
		$records = array();
		foreach ( $this->repository->find_by_user( (int) $user->ID ) as $credential ) {
			try {
				$records[] = $this->codec->record_from_json( $credential->record_json );
			} catch ( \Throwable $e ) {
				// One corrupt row must not stop a user from enrolling a replacement
				// passkey; skip it (the worst case is it is missing from the exclude
				// list) and note it for review rather than returning a 500.
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					error_log( '[rapls-passkey] register/options: skipping unreadable credential #' . $credential->id ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				}
			}
		}

		$result = $this->registration->create_options(
			(int) $user->ID,
			$user->user_login,
			$user->display_name,
			$records
		);

		return rest_ensure_response( $result );
	}

	/**
	 * Verify and store a newly registered credential.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function register_verify( WP_REST_Request $request ) {
		// Re-resolved (and re-authorised) here rather than trusted from the options
		// step, so a caller cannot swap the owner in between.
		$owner = $this->enrolment_target( $request );
		if ( $owner instanceof WP_Error ) {
			return $owner;
		}
		$owner_id = (int) $owner->ID;
		$actor_id = (int) wp_get_current_user()->ID;

		$limit = $this->limit_error( $owner_id );
		if ( null !== $limit ) {
			return $limit;
		}

		$state           = (string) $request->get_param( 'state' );
		$credential_json = $this->credential_json( $request );
		$label           = sanitize_text_field( (string) $request->get_param( 'label' ) );
		if ( '' === $label ) {
			$label = null;
		} else {
			$label = \RaplsPasskey\Support\Str::substr( $label, 0, 100 );
		}

		try {
			$record = $this->registration->verify( $state, $credential_json );
		} catch ( \Throwable $e ) {
			return $this->fail( 'rapls_passkey_register_failed', __( 'Failed to register the passkey.', 'rapls-passkey' ), 400, 'verify: ' . $e->getMessage() );
		}

		// Bind the credential to the user the ceremony was actually built for. The
		// verified record carries the userHandle from the creation options, so it
		// must match the (re-resolved) owner — otherwise a caller who is allowed to
		// enrol for others could fetch options for user A and then save the
		// resulting credential to user B. Compared in constant time.
		$expected_handle = UserHandle::raw( $owner_id );
		if ( '' === $expected_handle || ! hash_equals( $expected_handle, (string) $record->userHandle ) ) {
			return $this->fail( 'rapls_passkey_register_failed', __( 'Failed to register the passkey.', 'rapls-passkey' ), 400, 'owner_handle_mismatch: owner=' . $owner_id );
		}

		$credential_id = Base64UrlSafe::encodeUnpadded( $record->publicKeyCredentialId );
		if ( null !== $this->repository->find_by_credential_id( $credential_id ) ) {
			return new WP_Error( 'rapls_passkey_already_registered', __( 'This passkey is already registered.', 'rapls-passkey' ), array( 'status' => 409 ) );
		}

		/**
		 * Let a policy (e.g. Pro's authenticator policy) veto a credential before
		 * it is stored. Return a WP_Error to reject; any non-error value allows it.
		 *
		 * @param mixed                     $veto    Null by default; a WP_Error rejects.
		 * @param \Webauthn\CredentialRecord $record  The verified credential record.
		 * @param array                     $context Registration context: owner_id
		 *        (the user the passkey is for), actor_id (who is registering it), and
		 *        'context' => 'register'. Lets a policy scope rules to the real owner
		 *        rather than the current user (which differs for admin enrolment).
		 */
		$veto = apply_filters(
			'rapls_passkey/registration_policy',
			null,
			$record,
			array(
				'owner_id' => $owner_id,
				'actor_id' => $actor_id,
				'context'  => 'register',
			)
		);
		if ( is_wp_error( $veto ) ) {
			return $veto;
		}

		// Store the credential, enforcing the per-user cap with a DATABASE CONSTRAINT
		// rather than an application lock: each passkey claims a numbered slot under
		// a UNIQUE (user_id, slot_no) index, and when a cap is configured only slots
		// 1..cap are ever offered. Two concurrent registrations cannot both take the
		// same slot, so the cap is exact no matter how many requests race — and
		// unlike a session-scoped lock (GET_LOCK) or a transaction row lock, the
		// guarantee does not evaporate when WordPress transparently reconnects and
		// replays a statement, when a db.php drop-in routes queries to another
		// server, or when the table is not InnoDB.
		$id = $this->store_credential( $owner_id, $credential_id, $record, $label );
		if ( $id instanceof WP_Error ) {
			return $id;
		}

		AuditLog::record(
			AuditLog::REGISTERED,
			$owner_id,
			'id=' . $id . ( $owner_id === $actor_id ? '' : ' by-admin=' . $actor_id )
		);

		/**
		 * Fires after a passkey is registered and stored.
		 *
		 * @param int         $user_id User the passkey belongs to.
		 * @param int         $id      Stored credential row id.
		 * @param string|null $label   Optional passkey label.
		 */
		do_action( 'rapls_passkey/credential_registered', $owner_id, $id, $label );

		return rest_ensure_response(
			array(
				'success'    => true,
				'credential' => array(
					'id'         => $id,
					'label'      => $label,
					'created_at' => gmdate( 'Y-m-d H:i:s' ),
				),
			)
		);
	}

	// --- Authentication ------------------------------------------------------

	/**
	 * Issue request options.
	 *
	 * When a username is supplied, that account's credentials are allow-listed so
	 * a non-discoverable authenticator (a security key with no resident key) can
	 * still be used. That allow-list is exactly what would otherwise answer "does
	 * this account exist, and does it hold a passkey?" to anyone who asks — a real
	 * account returned descriptors and an unknown one returned none. So a username
	 * with nothing behind it now gets DECOY descriptors instead: derived from the
	 * name and a site secret, so they are stable per site (repeat probes agree),
	 * unlinkable across sites, and indistinguishable from real ones. No assertion
	 * can be produced for them, and verification matches the signature against
	 * stored credentials, never against this list.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function login_options( WP_REST_Request $request ): WP_REST_Response {
		$username = sanitize_text_field( (string) $request->get_param( 'username' ) );
		$records  = array();
		$decoys   = array();

		if ( '' !== $username && self::allow_list_enabled() ) {
			// By login name only. Accepting an email address as well would let anyone
			// confirm that a name and an address belong to the same account, because
			// both would return that account's credential ids.
			$user = get_user_by( 'login', $username );
			if ( $user && $this->login_options_enumeration_ok() ) {
				// Suspended passkeys are not offered: the browser must not put a
				// credential in the picker that the server would then reject.
				foreach ( $this->repository->find_active_by_user( (int) $user->ID ) as $credential ) {
					try {
						$records[] = $this->codec->record_from_json( $credential->record_json );
					} catch ( \Throwable $e ) {
						// One corrupt row must not break the whole picker; skip it and
						// note it for review rather than returning a 500.
						if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
							error_log( '[rapls-passkey] login/options: skipping unreadable credential #' . $credential->id ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
						}
					}
				}
			}

			// Pad to a FIXED number of entries, so the size of the answer says nothing
			// about the account. Real entries come first; the rest are fabricated.
			$decoys = $this->decoy_credential_ids( $username, max( 0, self::ALLOW_LIST_SIZE - count( $records ) ) );
		}

		// A caller (e.g. Pro's step-up confirmation) may RAISE the requirement to
		// user-verification=required so the login counts as MFA; it can only
		// strengthen it, never weaken the site's setting. A site can turn this
		// client-driven elevation off with the filter.
		$uv = null;
		if ( 'required' === (string) $request->get_param( 'uv' )
			&& (bool) apply_filters( 'rapls_passkey/allow_uv_elevation', true, $request ) ) {
			$uv = 'required';
		}

		return rest_ensure_response( $this->assertion->create_options( $records, $uv, $decoys ) );
	}

	/**
	 * Whether a username may be answered with an allow-list at all.
	 *
	 * OFF by default, which makes the anonymous options response identical for
	 * every input and so says nothing about any account. Sign-in then relies on
	 * discoverable credentials — the browser's own passkey picker — which is how
	 * passkeys are meant to work and needs no username at all.
	 *
	 * A site that must support non-resident authenticators (older security keys
	 * that store nothing themselves, and so can only be used when the server names
	 * the credential) can turn it on. The response is then padded and stripped as
	 * far as it can be, but a site enabling this accepts that a determined caller
	 * can still learn something: real credential ids vary in length, and a
	 * fabricated one cannot match every property of a real one.
	 *
	 * @return bool
	 */
	private static function allow_list_enabled(): bool {
		/**
		 * Answer username-bearing /login/options with an allow-list.
		 *
		 * @param bool $enabled False by default (discoverable credentials only).
		 */
		return (bool) apply_filters( 'rapls_passkey/username_allow_list', false );
	}

	/**
	 * Plausible credential ids to pad an allow-list with.
	 *
	 * Derived with HMAC from the name and the site's auth salt: the same name
	 * always yields the same ids on this site (so asking twice cannot expose them
	 * as fabricated), a different site yields different ids for the same name (so
	 * they cannot be correlated), and nobody without the salt can tell them from
	 * real credential ids. Lengths are drawn from the sizes real authenticators
	 * produce rather than being fixed.
	 *
	 * @param string $username The name that was asked about.
	 * @param int    $count    How many to produce.
	 * @return string[] Raw credential-id bytes.
	 */
	private function decoy_credential_ids( string $username, int $count ): array {
		if ( $count <= 0 ) {
			return array();
		}
		$seed    = hash_hmac( 'sha256', strtolower( $username ), wp_salt( 'auth' ), true );
		$lengths = array( 16, 20, 32, 64 );

		$ids = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$material = hash_hmac( 'sha512', 'rapls-decoy-' . $i, $seed, true );
			$length   = $lengths[ ord( $material[0] ) % count( $lengths ) ];
			$ids[]    = substr( str_repeat( $material, 2 ), 0, $length );
		}
		return $ids;
	}

	/**
	 * Verify an assertion and, on success, log the owner in.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function login_verify( WP_REST_Request $request ) {
		// Consume one attempt from the per-IP budget BEFORE doing any verification
		// work. Reading the counter in the gate and incrementing only after a failed
		// assertion is a check-then-act: with the counter one below the limit, any
		// number of simultaneous requests all read "under the limit" and all proceed
		// to verify. Incrementing first makes admission atomic — exactly one request
		// can receive the last remaining count — and it also caps the signature
		// verification work an attacker can start in parallel. A successful login
		// clears the counter, so genuine users never accumulate.
		$admit = $this->rate_admit( 'login' );
		if ( null !== $admit ) {
			return $admit;
		}

		$state           = (string) $request->get_param( 'state' );
		$credential_json = $this->credential_json( $request );

		try {
			$credential_id = $this->codec->credential_id_from_json( $credential_json );
		} catch ( \Throwable $e ) {
			return $this->login_fail( 'parse: ' . $e->getMessage() );
		}

		$stored = $this->repository->find_by_credential_id( $credential_id );
		if ( null === $stored ) {
			return $this->login_fail( 'credential_not_found: ' . $credential_id );
		}
		// A suspended passkey must not sign anyone in, even when the browser still
		// holds it (usernameless login never sent an allow-list to filter it out).
		if ( ! $stored->active ) {
			return $this->login_fail( 'credential_suspended: ' . $credential_id );
		}

		try {
			$record  = $this->codec->record_from_json( $stored->record_json );
			$updated = $this->assertion->verify( $state, $credential_json, $record );
		} catch ( \Throwable $e ) {
			// A signature-counter regression can mean a cloned authenticator; flag
			// it for review rather than swallowing it as a generic failure.
			if ( $this->is_counter_error( $e ) ) {
				AuditLog::record( AuditLog::COUNTER_MISMATCH, (int) $stored->user_id, 'cred=' . $stored->id );
				/**
				 * Fires when an assertion fails the signature-counter check (possible
				 * cloned or malfunctioning authenticator).
				 *
				 * @param int $user_id       User the credential belongs to.
				 * @param int $credential_id Stored credential row id.
				 */
				do_action( 'rapls_passkey/counter_mismatch', (int) $stored->user_id, (int) $stored->id );
			}
			return $this->login_fail( 'verify: ' . $e->getMessage() );
		}

		// Persist the advanced counter atomically. If it did not commit (a
		// concurrent assertion already advanced the counter, or a DB error), refuse
		// the login rather than signing in on stale state.
		if ( $this->repository->touch( $stored->id, $this->codec->record_to_json( $updated ), $updated->counter ) < 1 ) {
			return $this->login_fail( 'counter_not_advanced: cred=' . $stored->id );
		}

		$user = get_user_by( 'id', $stored->user_id );
		if ( ! $user ) {
			return $this->login_fail( 'user_not_found: ' . $stored->user_id );
		}

		$remember = (bool) $request->get_param( 'rememberme' );
		// Pass whether the assertion performed user verification, so a possession-
		// only passkey login does not silently satisfy the site's 2FA (F-05).
		$blocked  = \RaplsPasskey\Security\AuthSession::login( $user, 'login', $remember, false, $this->assertion->user_verified() );
		if ( $blocked instanceof WP_Error ) {
			return $blocked;
		}

		// A successful login should not count against the per-IP attempt limit, so
		// clear the counter (covering this verify and its preceding options call).
		$this->rate_clear( 'login' );

		AuditLog::record( AuditLog::LOGIN, (int) $user->ID, 'cred=' . $stored->id );

		$requested = trim( (string) $request->get_param( 'redirect_to' ) );
		$redirect  = '' !== $requested ? wp_validate_redirect( $requested, admin_url() ) : admin_url();
		if ( '' === $redirect ) {
			// wp_validate_redirect() treats an empty/relative location as valid and
			// returns it unchanged, so guard against an empty result explicitly.
			$redirect = admin_url();
		}

		return rest_ensure_response(
			array(
				'success'  => true,
				'redirect' => $redirect,
			)
		);
	}

	/**
	 * Whose passkey is being registered — normally the caller, but an administrator
	 * may enrol on another user's behalf (handing over a pre-configured security key,
	 * or sitting with someone during onboarding).
	 *
	 * Off unless a site opts in, because it lets the administrator hold a credential
	 * to someone else's account. That is not new power — an administrator can already
	 * reset anyone's password — but it is quieter, so it is gated three ways: the
	 * opt-in filter, the per-user edit_user capability, and the registration
	 * notification, which still goes to the account's owner.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return \WP_User|WP_Error
	 */
	private function enrolment_target( WP_REST_Request $request ) {
		$current   = wp_get_current_user();
		$requested = (int) $request->get_param( 'user' );

		if ( $requested <= 0 || $requested === (int) $current->ID ) {
			return $current;
		}

		/**
		 * Allow an administrator to register a passkey on another user's behalf.
		 *
		 * @param bool $allowed False by default. Rapls Passkey Pro turns this on from
		 *                      its "Administrator enrolment" setting.
		 */
		if ( ! apply_filters( 'rapls_passkey/allow_admin_enrolment', false ) ) {
			return new WP_Error(
				'rapls_passkey_forbidden',
				__( 'Registering a passkey for another user is not enabled on this site.', 'rapls-passkey' ),
				array( 'status' => 403 )
			);
		}

		if ( ! current_user_can( 'edit_user', $requested ) ) {
			return new WP_Error(
				'rapls_passkey_forbidden',
				__( 'You do not have permission to register a passkey for that user.', 'rapls-passkey' ),
				array( 'status' => 403 )
			);
		}

		$target = get_user_by( 'id', $requested );
		if ( ! $target ) {
			return new WP_Error(
				'rapls_passkey_not_found',
				__( 'That user does not exist.', 'rapls-passkey' ),
				array( 'status' => 404 )
			);
		}

		return $target;
	}

	// --- Credential management ----------------------------------------------

	/**
	 * Update a credential: rename it, and/or suspend and resume it.
	 *
	 * Renaming is owner-only — a name is a label the user chose for their own device
	 * and there is no admin case for rewriting it. Suspending is also allowed to a
	 * user who can edit the owner, so an administrator can cut off a lost device
	 * without destroying the credential.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function update_credential( WP_REST_Request $request ) {
		$id      = (int) $request->get_param( 'id' );
		$user_id = (int) wp_get_current_user()->ID;

		$credential = $this->repository->find_by_id( $id );
		if ( null === $credential ) {
			return new WP_Error(
				'rapls_passkey_not_found',
				__( 'That passkey no longer exists.', 'rapls-passkey' ),
				array( 'status' => 404 )
			);
		}

		$is_owner = (int) $credential->user_id === $user_id;
		$is_admin = ! $is_owner && current_user_can( 'edit_user', (int) $credential->user_id );

		if ( ! $is_owner && ! $is_admin ) {
			return new WP_Error(
				'rapls_passkey_forbidden',
				__( 'You do not have permission to change this passkey.', 'rapls-passkey' ),
				array( 'status' => 403 )
			);
		}

		if ( null !== $request->get_param( 'label' ) ) {
			if ( ! $is_owner ) {
				return new WP_Error(
					'rapls_passkey_forbidden',
					__( 'You do not have permission to rename this passkey.', 'rapls-passkey' ),
					array( 'status' => 403 )
				);
			}

			$label = sanitize_text_field( (string) $request->get_param( 'label' ) );
			$label = Str::substr( $label, 0, 191 ); // The column is varchar(191).
			$label = '' === trim( $label ) ? null : $label;

			if ( ! $this->repository->rename( $id, $user_id, $label ) ) {
				return new WP_Error(
					'rapls_passkey_forbidden',
					__( 'You do not have permission to rename this passkey.', 'rapls-passkey' ),
					array( 'status' => 403 )
				);
			}

			$credential->label = $label;
			AuditLog::record( AuditLog::RENAMED, (int) $credential->user_id, 'id=' . $id );
		}

		if ( null !== $request->get_param( 'active' ) ) {
			$active = (bool) $request->get_param( 'active' );
			$scope  = $is_owner ? $user_id : null; // The admin path is already authorised above.

			if ( ! $this->repository->set_active( $id, $scope, $active ) ) {
				return new WP_Error(
					'rapls_passkey_forbidden',
					__( 'You do not have permission to change this passkey.', 'rapls-passkey' ),
					array( 'status' => 403 )
				);
			}

			$credential->active = $active;
			AuditLog::record(
				$active ? AuditLog::RESUMED : AuditLog::SUSPENDED,
				(int) $credential->user_id,
				'id=' . $id . ( $is_owner ? '' : ' by-admin=' . $user_id )
			);
		}

		return rest_ensure_response(
			array(
				'success' => true,
				'label'   => $credential->label,
				'active'  => $credential->active,
			)
		);
	}

	/**
	 * Delete a credential. Users may remove their own; users with the `edit_users`
	 * capability may remove anyone's (for admin management on the profile screen).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function delete_credential( WP_REST_Request $request ) {
		$id      = (int) $request->get_param( 'id' );
		$user_id = (int) wp_get_current_user()->ID;

		// Owner path: remove one's own credential.
		if ( $this->repository->delete( $id, $user_id ) ) {
			AuditLog::record( AuditLog::REMOVED, $user_id, 'id=' . $id );
			/**
			 * Fires after a passkey is removed.
			 *
			 * @param int $user_id  User the passkey belonged to.
			 * @param int $id       Removed credential row id.
			 * @param int $by_admin Admin user id if removed by an admin, else 0.
			 */
			do_action( 'rapls_passkey/credential_deleted', $user_id, $id, 0 );
			return rest_ensure_response( array( 'success' => true ) );
		}

		// Admin path: remove another user's credential. Authorise against the
		// specific target user (not the blanket edit_users), so per-user/multisite
		// capability rules are respected.
		$credential = $this->repository->find_by_id( $id );
		if ( null !== $credential && current_user_can( 'edit_user', (int) $credential->user_id ) ) {
			$deleted = $this->repository->delete_by_id( $id );
			if ( $deleted ) {
				AuditLog::record(
					AuditLog::REMOVED,
					(int) $credential->user_id,
					'id=' . $id . ' by-admin=' . $user_id
				);
				/** This filter-style action documents who removed the passkey (admin path). */
				do_action( 'rapls_passkey/credential_deleted', (int) $credential->user_id, $id, $user_id );
			}
			return rest_ensure_response( array( 'success' => $deleted ) );
		}

		return new WP_Error(
			'rapls_passkey_forbidden',
			__( 'You do not have permission to delete this passkey.', 'rapls-passkey' ),
			array( 'status' => 403 )
		);
	}

	// --- Helpers -------------------------------------------------------------

	/**
	 * Return a WP_Error when the user is at the configured passkey limit, else
	 * null. A limit of 0 means unlimited.
	 *
	 * @param int $user_id User id.
	 * @return WP_Error|null
	 */
	private function limit_error( int $user_id ): ?WP_Error {
		$max = Settings::max_passkeys();
		if ( $max <= 0 ) {
			return null;
		}
		// count_by_user() returns -1 on a database error (as opposed to find_by_user(),
		// which maps a failed query to an empty array that reads as "under the limit").
		// Fail closed: if the count cannot be trusted, do not let a registration slip
		// past the cap.
		$count = $this->repository->count_by_user( $user_id );
		if ( $count < 0 ) {
			return $this->fail( 'rapls_passkey_store_failed', __( 'Failed to save the passkey.', 'rapls-passkey' ), 503, 'limit-count-db-error' );
		}
		if ( $count < $max ) {
			return null;
		}
		return $this->limit_reached( $max );
	}

	/**
	 * Store a verified credential in a numbered slot, enforcing the per-user cap
	 * through the UNIQUE (user_id, slot_no) index.
	 *
	 * The loop is the whole mechanism: read which slots the user occupies, offer the
	 * lowest free one within the cap, and try to claim it. A concurrent registration
	 * that claimed it first makes the insert fail on the unique index (-1), and we
	 * simply try the next free slot. When a cap is set, only slots 1..cap are ever
	 * offered, so no amount of concurrency can push the user past it. Nothing here
	 * depends on holding a connection, a session, or a transaction.
	 *
	 * @param int         $user_id       Owning user id.
	 * @param string      $credential_id Base64url credential id.
	 * @param object      $record        Verified credential record.
	 * @param string|null $label         Optional label.
	 * @return int|WP_Error Stored row id, or an error.
	 */
	private function store_credential( int $user_id, string $credential_id, $record, ?string $label ) {
		$max = Settings::max_passkeys();

		// The cap is the index's job. If the index is not there (an upgrade that
		// could not create it), a configured cap cannot be guaranteed — refuse
		// rather than register unprotected.
		if ( $max > 0 && ! Schema::cap_enforceable() ) {
			return $this->fail( 'rapls_passkey_store_failed', __( 'Failed to save the passkey.', 'rapls-passkey' ), 503, 'slot-index-missing' );
		}

		$record_json = $this->codec->record_to_json( $record );

		for ( $attempt = 0; $attempt < 12; $attempt++ ) {
			$used = $this->repository->used_slots( $user_id );
			if ( null === $used ) {
				// Cannot tell which slots are free — fail closed.
				return $this->fail( 'rapls_passkey_store_failed', __( 'Failed to save the passkey.', 'rapls-passkey' ), 503, 'slot-read-failed' );
			}

			$slot = self::first_free_slot( $used, $max );
			if ( 0 === $slot ) {
				return $this->limit_reached( $max );
			}

			$id = $this->repository->insert_in_slot( $user_id, $slot, $credential_id, $record_json, $record->counter, $label );
			if ( $id > 0 ) {
				return $id;
			}
			if ( 0 === $id ) {
				return new WP_Error( 'rapls_passkey_store_failed', __( 'Failed to save the passkey.', 'rapls-passkey' ), array( 'status' => 500 ) );
			}
			// -1: another registration took that slot first — try the next free one.
		}

		// Every attempt lost a race. With a cap that means the cap is now full.
		if ( $max > 0 ) {
			return $this->limit_reached( $max );
		}
		return $this->fail( 'rapls_passkey_store_failed', __( 'Failed to save the passkey.', 'rapls-passkey' ), 503, 'slot-contention' );
	}

	/**
	 * The lowest slot number not in $used, or 0 when a cap is set and every slot
	 * 1..$max is taken.
	 *
	 * @param int[] $used Occupied slot numbers.
	 * @param int   $max  Cap (0 = unlimited).
	 * @return int
	 */
	private static function first_free_slot( array $used, int $max ): int {
		$ceiling = $max > 0 ? $max : count( $used ) + 1;
		for ( $slot = 1; $slot <= $ceiling; $slot++ ) {
			if ( ! in_array( $slot, $used, true ) ) {
				return $slot;
			}
		}
		return 0;
	}

	/**
	 * The "you already have the maximum number of passkeys" error.
	 *
	 * @param int $max Configured maximum.
	 * @return WP_Error
	 */
	private function limit_reached( int $max ): WP_Error {
		return new WP_Error(
			'rapls_passkey_limit_reached',
			sprintf(
				/* translators: %d: maximum number of passkeys. */
				__( 'You can register at most %d passkeys. Remove an unused passkey before registering a new one.', 'rapls-passkey' ),
				$max
			),
			array( 'status' => 409 )
		);
	}

	/**
	 * Normalise the `credential` body param (sent as an object) to a JSON string.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return string
	 */
	private function credential_json( WP_REST_Request $request ): string {
		$credential = $request->get_param( 'credential' );
		if ( is_string( $credential ) ) {
			return $credential;
		}
		return (string) wp_json_encode( $credential );
	}

	/**
	 * Build an error response. The user-facing message stays generic (no oracle),
	 * but the real reason is logged and, when WP_DEBUG is on, returned as `reason`
	 * to aid local debugging.
	 *
	 * @param string      $code    Error code.
	 * @param string      $message User-facing message.
	 * @param int         $status  HTTP status.
	 * @param string|null $reason  Internal reason (logged; exposed only with WP_DEBUG).
	 * @return WP_Error
	 */
	private function fail( string $code, string $message, int $status, ?string $reason = null ): WP_Error {
		// The internal reason is only ever written to the server log — never
		// returned to the client, even under WP_DEBUG, so a production site left
		// with WP_DEBUG on cannot leak credential ids or library errors to callers.
		if ( null !== $reason && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[rapls-passkey] ' . $code . ' — ' . $reason ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
		return new WP_Error( $code, $message, array( 'status' => $status ) );
	}

	/**
	 * A failed assertion. The attempt was already counted when the request was
	 * admitted (see {@see rate_admit}), so this only shapes the response — counting
	 * again here would charge one attempt twice.
	 *
	 * @param string $reason Internal reason (logged; exposed only with WP_DEBUG).
	 * @return WP_Error
	 */
	private function login_fail( string $reason ): WP_Error {
		return $this->fail( 'rapls_passkey_login_failed', __( 'Passkey authentication failed.', 'rapls-passkey' ), 400, $reason );
	}

	/**
	 * Whether a verification exception is a signature-counter regression (which
	 * web-auth raises as a CounterException / a message mentioning the counter).
	 *
	 * @param \Throwable $e The thrown exception.
	 * @return bool
	 */
	private function is_counter_error( \Throwable $e ): bool {
		if ( false !== strpos( get_class( $e ), 'Counter' ) ) {
			return true;
		}
		return false !== stripos( $e->getMessage(), 'counter' );
	}

	/**
	 * Throttle username-bearing /login/options lookups per IP, to blunt scripted
	 * enumeration of which accounts hold passkeys (and their credential ids).
	 *
	 * Usernameless autofill (discoverable credentials) sends no username and is
	 * never throttled here. The cap is generous so ordinary logins — even from a
	 * shared office IP — are unaffected; only wordlist-style probing hits it. On
	 * the cap the caller returns empty options (as if the user were unknown),
	 * which reveals nothing and does not break the client.
	 *
	 * @return bool True to proceed with the per-user credential lookup.
	 */
	private function login_options_enumeration_ok(): bool {
		/** Filter: max username-bearing /login/options lookups per IP per window (0 disables). */
		$max = (int) apply_filters( 'rapls_passkey/login_options_max', 50 );
		if ( $max <= 0 ) {
			return true;
		}
		// One of exactly $max slots per window, enforced by the database: concurrent
		// username-bearing lookups cannot all slip under the cap, and a claim that
		// cannot be confirmed counts as refused, so the guard fails closed (returns
		// empty options, exactly as it does for an unknown user).
		return 0 !== RateLimit::admit( $this->rate_logical_key( 'login_options' ), (int) Settings::login_rate_window(), $max );
	}

	/**
	 * Whether the per-IP attempt counter for a bucket has reached the configured
	 * limit. Read-only: it never increments, so it is safe to call from the gate
	 * on every request (including /login/options). A limit of 0 disables it.
	 *
	 * @param string $bucket Action bucket.
	 * @return bool True when the request should be blocked (429).
	 */
	private function rate_limited( string $bucket ): bool {
		$max = Settings::login_rate_max();
		if ( $max <= 0 ) {
			return false;
		}
		// ADVISORY ONLY — an early 429 that saves the request some work. This is a
		// read, so a replica may answer with a stale value; the decision that has to
		// hold is rate_admit(), which the verify route calls before doing anything
		// and which the database enforces. A stale read here can only let a request
		// reach that authoritative check.
		return RateLimit::used( $this->rate_logical_key( $bucket ), (int) Settings::login_rate_window() ) >= $max;
	}

	/**
	 * Atomically admit one attempt from the per-IP budget, or refuse with 429.
	 *
	 * This is the check-and-act done as a single atomic increment: the counter is
	 * consumed FIRST and the resulting value decides admission, so of N simultaneous
	 * requests arriving with one attempt left, exactly one is admitted. (Reading the
	 * count and only incrementing after a failure lets all N through, because they
	 * all read the same under-limit value.) On a database error incr() returns
	 * OVERFLOW, which is above every limit, so admission fails closed.
	 *
	 * @param string $bucket Action bucket.
	 * @return WP_Error|null 429 error when the attempt is refused, null to proceed.
	 */
	private function rate_admit( string $bucket ): ?WP_Error {
		$max = Settings::login_rate_max();
		if ( $max <= 0 ) {
			return null;
		}
		// admit() claims one of exactly $max slots, enforced by the unique index on
		// the row it inserts. Nothing is decided from a value that was read, so a
		// replica serving a stale count (or a window boundary) cannot let a batch
		// through; being unable to confirm the claim returns 0, which blocks.
		if ( 0 === RateLimit::admit( $this->rate_logical_key( $bucket ), (int) Settings::login_rate_window(), $max ) ) {
			return new WP_Error( 'rapls_passkey_rate_limited', __( 'Too many attempts. Please try again later.', 'rapls-passkey' ), array( 'status' => 429 ) );
		}
		return null;
	}

	/**
	 * Clear the per-IP counter for a bucket (called after a successful login so
	 * successes do not accumulate toward the attempt limit).
	 *
	 * @param string $bucket Action bucket.
	 */
	private function rate_clear( string $bucket ): void {
		RateLimit::clear( $this->rate_logical_key( $bucket ) );
	}

	/**
	 * Logical key for a per-IP rate-limit bucket, passed to the shared {@see
	 * RateLimit}. It turns the key into the option names holding that bucket's
	 * attempt slots for the current window
	 * (`rapls_passkey_ra_<md5(key)>_<window-end>_<slot>`).
	 *
	 * @param string $bucket Action bucket.
	 * @return string
	 */
	private function rate_logical_key( string $bucket ): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';
		return $bucket . '|' . $ip;
	}
}
