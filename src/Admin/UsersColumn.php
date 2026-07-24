<?php
/**
 * "Passkey" column on the Users list screen.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Credentials\CredentialRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds a column to Users → All Users showing, per user, how many passkeys they
 * have and when one was last used (or "Not registered"). Counts are fetched once per
 * page render, not per row.
 */
final class UsersColumn {

	/** Column id. */
	private const COL = 'rapls_passkey';

	/**
	 * Per-user counts for the current screen, loaded lazily once.
	 *
	 * @var array<int,array{count:int,last_used:?string}>|null
	 */
	private $counts = null;

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the Users-list column.
	 */
	public function register(): void {
		add_filter( 'manage_users_columns', array( $this, 'add_column' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'render_column' ), 10, 3 );
	}

	/**
	 * Declare the column header.
	 *
	 * @param array<string,string> $columns Existing columns.
	 * @return array<string,string>
	 */
	public function add_column( $columns ): array {
		$columns = is_array( $columns ) ? $columns : array();
		$columns[ self::COL ] = __( 'Passkey', 'rapls-passkey' );
		return $columns;
	}

	/**
	 * Render one cell.
	 *
	 * @param string $output      Current cell output (for other columns).
	 * @param string $column_name Column id.
	 * @param int    $user_id     Row user id.
	 * @return string
	 */
	public function render_column( $output, $column_name, $user_id ): string {
		if ( self::COL !== $column_name ) {
			return (string) $output;
		}

		if ( null === $this->counts ) {
			$this->counts = $this->repository->counts_by_user();
		}

		$info = $this->counts[ (int) $user_id ] ?? null;
		if ( null === $info || $info['count'] < 1 ) {
			return '<span aria-hidden="true" style="color:#b32d2e">●</span> ' . esc_html__( 'Not registered', 'rapls-passkey' );
		}

		$count = (int) $info['count'];
		$cell  = '<span aria-hidden="true" style="color:#007017">●</span> ';
		$cell .= esc_html(
			sprintf(
				/* translators: %d: number of passkeys. */
				__( 'Passkeys: %d', 'rapls-passkey' ),
				$count
			)
		);

		if ( ! empty( $info['last_used'] ) ) {
			$cell .= ' <span class="description">'
				. esc_html(
					sprintf(
						/* translators: %s: date a passkey was last used. */
						__( 'Last %s', 'rapls-passkey' ),
						mysql2date( (string) get_option( 'date_format' ), (string) $info['last_used'] )
					)
				)
				. '</span>';
		}

		return $cell;
	}
}
