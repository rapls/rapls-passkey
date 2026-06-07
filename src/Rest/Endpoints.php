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
			return new WP_Error( 'rapls_passkey_bad_origin', __( '不正なリクエストです。', 'rapls-passkey' ), array( 'status' => 403 ) );
		}
		if ( ! $this->rate_ok( 'login', 30, 300 ) ) {
			return new WP_Error( 'rapls_passkey_rate_limited', __( '試行回数が多すぎます。しばらくしてからお試しください。', 'rapls-passkey' ), array( 'status' => 429 ) );
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
		$label           = '' !== $label ? mb_substr( $label, 0, 100 ) : null;

		try {
			$record = $this->registration->verify( $state, $credential_json );
		} catch ( \Throwable $e ) {
			return $this->fail( 'rapls_passkey_register_failed', __( 'パスキーの登録に失敗しました。', 'rapls-passkey' ), 400, 'verify: ' . $e->getMessage() );
		}

		$credential_id = Base64UrlSafe::encodeUnpadded( $record->publicKeyCredentialId );
		if ( null !== $this->repository->find_by_credential_id( $credential_id ) ) {
			return new WP_Error( 'rapls_passkey_already_registered', __( 'このパスキーはすでに登録されています。', 'rapls-passkey' ), array( 'status' => 409 ) );
		}

		$id = $this->repository->insert(
			(int) wp_get_current_user()->ID,
			$credential_id,
			$this->codec->record_to_json( $record ),
			$record->counter,
			$label
		);

		if ( 0 === $id ) {
			return new WP_Error( 'rapls_passkey_store_failed', __( 'パスキーの保存に失敗しました。', 'rapls-passkey' ), array( 'status' => 500 ) );
		}

		AuditLog::record( AuditLog::REGISTERED, (int) wp_get_current_user()->ID, 'id=' . $id );

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
			return $this->fail( 'rapls_passkey_login_failed', __( 'パスキーでの認証に失敗しました。', 'rapls-passkey' ), 400, 'parse: ' . $e->getMessage() );
		}

		$stored = $this->repository->find_by_credential_id( $credential_id );
		if ( null === $stored ) {
			return $this->fail( 'rapls_passkey_login_failed', __( 'パスキーでの認証に失敗しました。', 'rapls-passkey' ), 400, 'credential_not_found: ' . $credential_id );
		}

		try {
			$record  = $this->codec->record_from_json( $stored->record_json );
			$updated = $this->assertion->verify( $state, $credential_json, $record );
		} catch ( \Throwable $e ) {
			return $this->fail( 'rapls_passkey_login_failed', __( 'パスキーでの認証に失敗しました。', 'rapls-passkey' ), 400, 'verify: ' . $e->getMessage() );
		}

		$this->repository->touch( $stored->id, $this->codec->record_to_json( $updated ), $updated->counter );

		$user = get_user_by( 'id', $stored->user_id );
		if ( ! $user ) {
			return $this->fail( 'rapls_passkey_login_failed', __( 'パスキーでの認証に失敗しました。', 'rapls-passkey' ), 400, 'user_not_found: ' . $stored->user_id );
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, true );
		do_action( 'wp_login', $user->user_login, $user );

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
			return rest_ensure_response( array( 'success' => true ) );
		}

		// Admin path: remove another user's credential.
		if ( current_user_can( 'edit_users' ) ) {
			$credential = $this->repository->find_by_id( $id );
			if ( null === $credential ) {
				return rest_ensure_response( array( 'success' => false ) );
			}
			$deleted = $this->repository->delete_by_id( $id );
			if ( $deleted ) {
				AuditLog::record(
					AuditLog::REMOVED,
					(int) $credential->user_id,
					'id=' . $id . ' by-admin=' . $user_id
				);
			}
			return rest_ensure_response( array( 'success' => $deleted ) );
		}

		return new WP_Error(
			'rapls_passkey_forbidden',
			__( 'このパスキーを削除する権限がありません。', 'rapls-passkey' ),
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
				__( '登録できるパスキーは最大 %d 個です。不要なパスキーを削除してから登録してください。', 'rapls-passkey' ),
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
