<?php
/**
 * Keep the plugin's public passkey REST endpoints reachable when a security
 * plugin restricts the REST API to logged-in users.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Security;

use WP_Error;
use WP_REST_Request;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Several Japanese-market security plugins (CloudSecure WP Security, SiteGuard,
 * Really Simple SSL, Wordfence, …) can lock the whole REST API down to
 * authenticated users. That breaks passwordless login, because the passkey
 * ceremonies *must* run before the visitor is logged in — and, for Pro's
 * cross-device flow, from a phone that carries no auth cookie at all.
 *
 * This allowlist re-opens **only** this plugin's own namespace. It never
 * weakens the per-route permission callbacks: registration and credential
 * deletion still require `is_user_logged_in()` / capability checks. All we do
 * is clear a blanket "REST is for logged-in users only" error for our routes so
 * those per-route checks get a chance to run.
 */
final class RestAccess {

	/**
	 * REST namespace prefix this guard re-opens (e.g. `rapls-passkey/v1`).
	 *
	 * @var string
	 */
	private string $namespace;

	/**
	 * @param string $namespace REST namespace prefix to allowlist.
	 */
	public function __construct( string $namespace = 'rapls-passkey/v1' ) {
		$this->namespace = $namespace;
	}

	/**
	 * Register the allowlist filters at the lowest priority so they run after
	 * the security plugin's own blocker and get the final say.
	 */
	public function register(): void {
		add_filter( 'rest_authentication_errors', array( $this, 'allow_authentication' ), PHP_INT_MAX );
		add_filter( 'rest_pre_dispatch', array( $this, 'allow_pre_dispatch' ), PHP_INT_MAX, 3 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'allow_before_callbacks' ), PHP_INT_MAX, 3 );
	}

	/**
	 * Clear a blanket authentication error for our routes.
	 *
	 * Returning `true` marks the *request* as authenticated; it does not log the
	 * visitor in, so each route's own permission callback still applies.
	 *
	 * @param mixed $result Existing authentication result (true|WP_Error|null).
	 * @return mixed
	 */
	public function allow_authentication( $result ) {
		if ( is_wp_error( $result ) && $this->current_route_is_ours() ) {
			return true;
		}
		return $result;
	}

	/**
	 * Clear a pre-dispatch short-circuit error for our routes.
	 *
	 * @param mixed           $result  Response to short-circuit with, or null.
	 * @param mixed           $server  REST server (unused).
	 * @param WP_REST_Request $request Current request.
	 * @return mixed Null lets normal dispatch proceed.
	 */
	public function allow_pre_dispatch( $result, $server, $request ) {
		if ( is_wp_error( $result ) && $this->request_is_ours( $request ) ) {
			return null;
		}
		return $result;
	}

	/**
	 * Clear a before-callbacks error for our routes (e.g. Really Simple SSL).
	 *
	 * @param mixed           $response Response or WP_Error.
	 * @param array           $handler  Route handler (unused).
	 * @param WP_REST_Request $request  Current request.
	 * @return mixed Null lets the route callback run.
	 */
	public function allow_before_callbacks( $response, $handler, $request ) {
		if ( is_wp_error( $response ) && $this->request_is_ours( $request ) ) {
			return null;
		}
		return $response;
	}

	/**
	 * Does the given request target our namespace?
	 *
	 * @param mixed $request REST request (may be any type defensively).
	 * @return bool
	 */
	private function request_is_ours( $request ): bool {
		if ( $request instanceof WP_REST_Request ) {
			return $this->route_matches( (string) $request->get_route() );
		}
		return $this->current_route_is_ours();
	}

	/**
	 * Inspect the current request (used where no WP_REST_Request is passed).
	 *
	 * @return bool
	 */
	private function current_route_is_ours(): bool {
		$route = '';
		if ( isset( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			$route = (string) $GLOBALS['wp']->query_vars['rest_route'];
		}
		if ( '' === $route && isset( $_SERVER['REQUEST_URI'] ) ) {
			$route = (string) wp_unslash( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}
		return $this->route_matches( $route );
	}

	/**
	 * Match a route/URI string against our namespace prefix.
	 *
	 * @param string $route Route or request URI.
	 * @return bool
	 */
	private function route_matches( string $route ): bool {
		if ( '' === $route ) {
			return false;
		}
		return false !== strpos( $route, $this->namespace );
	}
}
