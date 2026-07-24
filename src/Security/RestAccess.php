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
 * This allowlist re-opens **only** the anonymous passkey-login ceremony routes
 * (`…/v1/login/*`). Those are the ones that must run before the visitor is
 * logged in; the authenticated routes (`register/*`, `credentials/*`) are for
 * users who are already signed in, so a "logged-in only" security plugin does
 * not block them and they need no help here.
 *
 * Restricting the scope to `/login` also matters for CSRF: clearing the
 * authentication error for the whole namespace would swallow core's
 * `rest_cookie_invalid_nonce` error on the authenticated routes too, defeating
 * the cookie-nonce check those routes rely on. Only the anonymous login routes
 * (which carry no nonce and mint no side effects until a valid assertion) are
 * re-opened.
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
		if ( is_wp_error( $result ) && $this->request_is_ours( $request ) && $this->is_clearable( $result ) ) {
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
		if ( is_wp_error( $response ) && $this->request_is_ours( $request ) && $this->is_clearable( $response ) ) {
			return null;
		}
		return $response;
	}

	/**
	 * Only clear errors that represent a blanket "REST is locked to logged-in
	 * users" restriction — not an arbitrary WP_Error another plugin (a WAF, an IP
	 * gate, maintenance mode, a forced-auth check) may have returned on this route.
	 * The default set covers the WordPress core authentication codes; a site whose
	 * security plugin uses a different code can add it via the filter.
	 *
	 * The authentication-error hook (allow_authentication) is intentionally left
	 * broad: clearing there only marks the request authenticated and the route's
	 * own permission callback still runs, so it cannot bypass a real restriction.
	 *
	 * @param \WP_Error $error The error being considered.
	 * @return bool
	 */
	private function is_clearable( $error ): bool {
		$codes = array(
			'rest_not_logged_in',
			'rest_cannot_access',
			'rest_login_required',
			'rest_authorization_required',
			'rest_forbidden',
			'rest_forbidden_context',
			'rest_user_cannot_view',
		);
		/**
		 * REST error codes the passkey-login allowlist may clear on its own routes.
		 *
		 * @param string[] $codes Clearable error codes.
		 */
		$codes = (array) apply_filters( 'rapls_passkey/rest_clearable_error_codes', $codes );
		return in_array( (string) $error->get_error_code(), $codes, true );
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
	 * Match a route/URI string against our anonymous login routes.
	 *
	 * Deliberately scoped to `{namespace}/login` — not the whole namespace — so
	 * only the pre-authentication ceremony is re-opened. See the class docblock.
	 *
	 * @param string $route Route or request URI.
	 * @return bool
	 */
	private function route_matches( string $route ): bool {
		if ( '' === $route ) {
			return false;
		}
		// Match `{namespace}/login` only on path-segment boundaries so an
		// unrelated route that merely contains the string (e.g.
		// `/other/rapls-passkey/v1/login-export`) is not mistaken for ours.
		$pattern = '#(?:^|/)' . preg_quote( $this->namespace . '/login', '#' ) . '(?:/|$)#';
		return 1 === preg_match( $pattern, $route );
	}
}
