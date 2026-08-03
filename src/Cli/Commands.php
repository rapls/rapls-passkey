<?php
/**
 * WP-CLI recovery & management commands.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Cli;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\CredentialRepository;
use WP_CLI;

defined( 'ABSPATH' ) || exit;

/**
 * `wp rapls-passkey ...` — inspect and remove stored passkeys from the server.
 * The recovery path for a user who has lost their authenticator (works even if
 * the WebAuthn library is unavailable).
 */
final class Commands {

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Register the command when running under WP-CLI.
	 */
	public function register(): void {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			WP_CLI::add_command( 'rapls-passkey', $this );
		}
	}

	/**
	 * List a user's registered passkeys.
	 *
	 * ## OPTIONS
	 *
	 * --user=<user>
	 * : User id, login, or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp rapls-passkey list --user=admin
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Associative args.
	 * @return void
	 */
	public function list( $args, $assoc_args ): void {
		$user = $this->resolve_user( $assoc_args['user'] ?? '' );

		$rows = array();
		foreach ( $this->repository->find_by_user( (int) $user->ID ) as $credential ) {
			$rows[] = array(
				'id'         => $credential->id,
				'label'      => $credential->label ?? '',
				'created_at' => $credential->created_at,
				'last_used'  => $credential->last_used_at ?? '',
				'sign_count' => $credential->sign_count,
			);
		}

		if ( array() === $rows ) {
			WP_CLI::log( 'No passkeys registered for this user.' );
			return;
		}

		WP_CLI\Utils\format_items( 'table', $rows, array( 'id', 'label', 'created_at', 'last_used', 'sign_count' ) );
	}

	/**
	 * Remove a passkey by its row id.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : The credential row id (see `wp rapls-passkey list`).
	 *
	 * ## EXAMPLES
	 *
	 *     wp rapls-passkey remove 12
	 *
	 * @param array $args       Positional args: [ id ].
	 * @param array $assoc_args Associative args (unused).
	 * @return void
	 */
	public function remove( $args, $assoc_args ): void {
		$id = isset( $args[0] ) ? (int) $args[0] : 0;
		if ( $id <= 0 ) {
			WP_CLI::error( 'Provide a valid credential row id.' );
		}

		// Resolve the owner before deleting, so the audit row is attributed to the
		// user (and is included when their personal data is exported/erased).
		$existing = $this->repository->find_by_id( $id );
		$owner    = $existing ? (int) $existing->user_id : 0;

		if ( $this->repository->delete_by_id( $id ) ) {
			AuditLog::record( AuditLog::REMOVED, $owner, 'wp-cli id=' . $id );
			WP_CLI::success( sprintf( 'Removed passkey #%d.', $id ) );
		} else {
			WP_CLI::error( sprintf( 'No passkey found with id %d.', $id ) );
		}
	}

	/**
	 * Show site-wide passkey adoption totals.
	 *
	 * ## EXAMPLES
	 *
	 *     wp rapls-passkey stats
	 *
	 * @param array $args       Positional args (unused).
	 * @param array $assoc_args Associative args (unused).
	 * @return void
	 */
	public function stats( $args, $assoc_args ): void {
		$stats = $this->repository->stats();
		$rows  = array(
			array(
				'metric' => 'Total passkeys',
				'value'  => (int) $stats['total'],
			),
			array(
				'metric' => 'Users with a passkey',
				'value'  => (int) $stats['users'],
			),
		);
		WP_CLI\Utils\format_items( 'table', $rows, array( 'metric', 'value' ) );
	}

	/**
	 * Resolve a --user value (id / login / email) to a WP_User or bail.
	 *
	 * @param string $value User identifier.
	 * @return \WP_User
	 */
	private function resolve_user( string $value ) {
		$value = trim( (string) $value );
		if ( '' === $value ) {
			WP_CLI::error( 'Specify --user=<id|login|email>.' );
		}

		$user = is_numeric( $value ) ? get_user_by( 'id', (int) $value ) : get_user_by( 'login', $value );
		if ( ! $user && is_email( $value ) ) {
			$user = get_user_by( 'email', $value );
		}
		if ( ! $user ) {
			WP_CLI::error( sprintf( 'User not found: %s', $value ) );
		}

		return $user;
	}
}
