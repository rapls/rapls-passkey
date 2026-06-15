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
use RaplsPasskey\WebAuthn\AssertionManager;
use RaplsPasskey\Support\Settings;
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
				'permission_callback' => array( $this, 'public_login_gate' ),
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
				'methods'             => WP_REST_Server::DELETABLE,
				'callback'            => array( $this, 'delete_credential' ),
				'permission_callback' => array( $this, 'require_logged_in' ),
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
		if ( ! $this->same_origin( $request ) ) {
			return new WP_Error( 'rapls_passkey_bad_origin', __( 'Invalid request.', 'rapls-passkey' ), array( 'status' => 403 ) );
		}
		if ( ! $this->rate_ok( 'login', 30, 300 ) ) {
			return new WP_Error( 'rapls_passkey_rate_limited', __( 'Too many attempts. Please try again later.', 'rapls-passkey' ), array( 'status' => 429 ) );
		}
		return true;
	}

	/**
	 * Confirm the request originates from this site (Origin/Referer host match).
	 * Absent both headers we allow it — WebAuthn still binds the ceremony to the
	 * real origin during verification.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return bool
	 */
	private function same_origin( WP_REST_Request $request ): bool {
		$source = $request->get_header( 'origin' );
		if ( ! $source ) {
			$source = $request->get_header( 'referer' );
		}
		if ( ! $source ) {
			return true;
		}

		$source_host = wp_parse_url( $source, PHP_URL_HOST );
		$allowed     = array(
			wp_parse_url( home_url(), PHP_URL_HOST ),
			wp_parse_url( site_url(), PHP_URL_HOST ),
		);

		return in_array( $source_host, $allowed, true );
	}

	// --- Registration --------------------------------------------------------

	/**
	 * Issue creation options for the current user.
	 *
	 * @return WP_REST_Response|WP_Error
	 */
	public function register_options() {
		$user = wp_get_current_user();

		$limit = $this->limit_error( (int) $user->ID );
		if ( null !== $limit ) {
			return $limit;
		}

		$records = array();
		foreach ( $this->repository->find_by_user( (int) $user->ID ) as $credential ) {
			$records[] = $this->codec->record_from_json( $credential->record_json );
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
		$limit = $this->limit_error( (int) wp_get_current_user()->ID );
		if ( null !== $limit ) {
			return $limit;
		}

		$state           = (string) $request->get_param( 'state' );
		$credential_json = $this->credential_json( $request );
		$label           = sanitize_text_field( (string) $request->get_param( 'label' ) );
		if ( '' === $label ) {
			$label = null;
		} else {
			$label = function_exists( 'mb_substr' ) ? mb_substr( $label, 0, 100 ) : substr( $label, 0, 100 );
		}

		try {
			$record = $this->registration->verify( $state, $credential_json );
		} catch ( \Throwable $e ) {
			return $this->fail( 'rapls_passkey_register_failed', __( 'Failed to register the passkey.', 'rapls-passkey' ), 400, 'verify: ' . $e->getMessage() );
		}

		$credential_id = Base64UrlSafe::encodeUnpadded( $record->publicKeyCredentialId );
		if ( null !== $this->repository->find_by_credential_id( $credential_id ) ) {
			return new WP_Error( 'rapls_passkey_already_registered', __( 'This passkey is already registered.', 'rapls-passkey' ), array( 'status' => 409 ) );
		}

		/**
		 * Let a policy (e.g. Pro's authenticator policy) veto a credential before
		 * it is stored. Return a WP_Error to reject; any non-error value allows it.
		 *
		 * @param mixed                     $veto   Null by default; a WP_Error rejects.
		 * @param \Webauthn\CredentialRecord $record The verified credential record.
		 */
		$veto = apply_filters( 'rapls_passkey/registration_policy', null, $record );
		if ( is_wp_error( $veto ) ) {
			return $veto;
		}

		// Re-check the per-user limit right before storing, to close the race
		// between the options request and this verify (two near-simultaneous
		// registrations could both have passed the initial check).
		$limit = $this->limit_error( (int) wp_get_current_user()->ID );
		if ( null !== $limit ) {
			return $limit;
		}

		$id = $this->repository->insert(
			(int) wp_get_current_user()->ID,
			$credential_id,
			$this->codec->record_to_json( $record ),
			$record->counter,
			$label
		);

		if ( 0 === $id ) {
			return new WP_Error( 'rapls_passkey_store_failed', __( 'Failed to save the passkey.', 'rapls-passkey' ), array( 'status' => 500 ) );
		}

		AuditLog::record( AuditLog::REGISTERED, (int) wp_get_current_user()->ID, 'id=' . $id );

		/**
		 * Fires after a passkey is registered and stored.
		 *
		 * @param int         $user_id User the passkey belongs to.
		 * @param int         $id      Stored credential row id.
		 * @param string|null $label   Optional passkey label.
		 */
		do_action( 'rapls_passkey/credential_registered', (int) wp_get_current_user()->ID, $id, $label );

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
	 * Issue request options. When a username is supplied its credentials are
	 * allow-listed; unknown users still receive options (no enumeration).
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public function login_options( WP_REST_Request $request ): WP_REST_Response {
		$username = sanitize_text_field( (string) $request->get_param( 'username' ) );
		$records  = array();

		if ( '' !== $username ) {
			$user = get_user_by( 'login', $username );
			if ( ! $user && is_email( $username ) ) {
				$user = get_user_by( 'email', $username );
			}
			if ( $user ) {
				foreach ( $this->repository->find_by_user( (int) $user->ID ) as $credential ) {
					$records[] = $this->codec->record_from_json( $credential->record_json );
				}
			}
		}

		return rest_ensure_response( $this->assertion->create_options( $records ) );
	}

	/**
	 * Verify an assertion and, on success, log the owner in.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function login_verify( WP_REST_Request $request ) {
		$state           = (string) $request->get_param( 'state' );
		$credential_json = $this->credential_json( $request );

		try {
			$credential_id = $this->codec->credential_id_from_json( $credential_json );
		} catch ( \Throwable $e ) {
			return $this->fail( 'rapls_passkey_login_failed', __( 'Passkey authentication failed.', 'rapls-passkey' ), 400, 'parse: ' . $e->getMessage() );
		}

		$stored = $this->repository->find_by_credential_id( $credential_id );
		if ( null === $stored ) {
			return $this->fail( 'rapls_passkey_login_failed', __( 'Passkey authentication failed.', 'rapls-passkey' ), 400, 'credential_not_found: ' . $credential_id );
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
			return $this->fail( 'rapls_passkey_login_failed', __( 'Passkey authentication failed.', 'rapls-passkey' ), 400, 'verify: ' . $e->getMessage() );
		}

		$this->repository->touch( $stored->id, $this->codec->record_to_json( $updated ), $updated->counter );

		$user = get_user_by( 'id', $stored->user_id );
		if ( ! $user ) {
			return $this->fail( 'rapls_passkey_login_failed', __( 'Passkey authentication failed.', 'rapls-passkey' ), 400, 'user_not_found: ' . $stored->user_id );
		}

		$remember = (bool) $request->get_param( 'rememberme' );
		$blocked  = \RaplsPasskey\Security\AuthSession::login( $user, 'login', $remember );
		if ( $blocked instanceof WP_Error ) {
			return $blocked;
		}

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

	// --- Credential management ----------------------------------------------

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
		if ( count( $this->repository->find_by_user( $user_id ) ) < $max ) {
			return null;
		}
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
		$data = array( 'status' => $status );
		if ( null !== $reason && defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[rapls-passkey] ' . $code . ' — ' . $reason ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			$data['reason'] = $reason;
		}
		return new WP_Error( $code, $message, $data );
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
	 * Simple per-IP fixed-window rate limit backed by a transient.
	 *
	 * @param string $bucket Action bucket.
	 * @param int    $max    Max requests per window.
	 * @param int    $window Window length in seconds.
	 * @return bool True when the request is within budget.
	 */
	private function rate_ok( string $bucket, int $max, int $window ): bool {
		$ip  = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : 'unknown';
		$key = 'rapls_passkey_rl_' . md5( $bucket . '|' . $ip );
		$n   = (int) get_transient( $key );
		if ( $n >= $max ) {
			return false;
		}
		set_transient( $key, $n + 1, $window );
		return true;
	}
}
