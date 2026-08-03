<?php
/**
 * Site-wide passkey overview for administrators.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\AuthenticatorNames;
use RaplsPasskey\Credentials\CredentialRepository;

defined( 'ABSPATH' ) || exit;

/**
 * Every passkey on the site in one list, searchable by owner or name.
 *
 * Until now an administrator could only see a user's passkeys by opening that user's
 * profile one at a time, which is no way to answer "who still has a passkey on the
 * laptop we just lost?" or "which of these has never been used?". The list also
 * carries the two actions that matter in that moment — suspend and delete.
 *
 * Deliberately read-mostly: it does not offer renaming, because a name is the label
 * its owner chose (see Rest\Endpoints::update_credential).
 */
final class CredentialsPage {

	/** Menu slug. */
	private const SLUG = 'rapls-passkey-credentials';

	/** admin-post action for suspend / resume / delete. */
	private const ACTION = 'rapls_passkey_credential_action';

	/** Rows per page. */
	private const PER_PAGE = 25;

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the menu and the action handler.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_post_' . self::ACTION, array( $this, 'handle' ) );
	}

	/**
	 * Add the page under Users, next to the people the passkeys belong to.
	 */
	public function add_page(): void {
		add_users_page(
			__( 'Passkeys', 'rapls-passkey' ),
			__( 'Passkeys', 'rapls-passkey' ),
			'list_users',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Apply a suspend / resume / delete from the list. Always redirects.
	 */
	public function handle(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$id = isset( $_REQUEST['credential'] ) ? (int) $_REQUEST['credential'] : 0;
		check_admin_referer( self::ACTION . '_' . $id );

		$credential = $id > 0 ? $this->repository->find_by_id( $id ) : null;
		if ( null === $credential ) {
			$this->redirect( 'missing' );
		}

		// Authorise against the specific owner, so per-user and multisite capability
		// rules apply — not a blanket "can see the list, can edit anyone".
		if ( ! current_user_can( 'edit_user', (int) $credential->user_id ) ) {
			wp_die( esc_html__( 'You do not have permission to change this passkey.', 'rapls-passkey' ), '', array( 'response' => 403 ) );
		}

		$actor = (int) wp_get_current_user()->ID;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$do    = isset( $_REQUEST['do'] ) ? sanitize_key( wp_unslash( $_REQUEST['do'] ) ) : '';

		if ( 'delete' === $do ) {
			$this->repository->delete_by_id( $id );
			AuditLog::record( AuditLog::REMOVED, (int) $credential->user_id, 'id=' . $id . ' by-admin=' . $actor );
			/** Documented in Rest\Endpoints::delete_credential(). */
			do_action( 'rapls_passkey/credential_deleted', (int) $credential->user_id, $id, $actor );
			$this->redirect( 'deleted' );
		}

		if ( 'suspend' === $do || 'resume' === $do ) {
			$active = 'resume' === $do;
			$this->repository->set_active( $id, null, $active );
			AuditLog::record(
				$active ? AuditLog::RESUMED : AuditLog::SUSPENDED,
				(int) $credential->user_id,
				'id=' . $id . ' by-admin=' . $actor
			);
			$this->redirect( $active ? 'resumed' : 'suspended' );
		}

		$this->redirect( 'missing' );
	}

	/**
	 * Back to the list with a result flag. Never returns.
	 *
	 * @param string $result Result slug for the notice.
	 */
	private function redirect( string $result ): void {
		wp_safe_redirect( add_query_arg( 'rapls_pk_result', $result, admin_url( 'users.php?page=' . self::SLUG ) ) );
		exit;
	}

	/**
	 * Render the list.
	 */
	public function render(): void {
		if ( ! current_user_can( 'list_users' ) ) {
			return;
		}

		// Confirmation for the delete links, without an inline handler (CSP-safe).
		wp_enqueue_script( 'rapls-passkey-admin', RAPLS_PASSKEY_URL . 'assets/admin.js', array(), RAPLS_PASSKEY_VERSION, true );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only list state.
		$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		$paged  = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
		$result = isset( $_GET['rapls_pk_result'] ) ? sanitize_key( wp_unslash( $_GET['rapls_pk_result'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$total       = $this->repository->count_all( $search );
		$pages       = max( 1, (int) ceil( $total / self::PER_PAGE ) );
		$paged       = min( $paged, $pages );
		$credentials = $this->repository->find_all( $search, self::PER_PAGE, ( $paged - 1 ) * self::PER_PAGE );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Passkeys', 'rapls-passkey' ); ?></h1>

			<?php if ( '' !== $result ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php echo esc_html( $this->notice( $result ) ); ?></p></div>
			<?php endif; ?>

			<form method="get">
				<input type="hidden" name="page" value="<?php echo esc_attr( self::SLUG ); ?>">
				<p class="search-box">
					<label class="screen-reader-text" for="rapls-pk-search"><?php esc_html_e( 'Search passkeys', 'rapls-passkey' ); ?></label>
					<input type="search" id="rapls-pk-search" name="s" value="<?php echo esc_attr( $search ); ?>">
					<?php submit_button( __( 'Search passkeys', 'rapls-passkey' ), '', '', false ); ?>
				</p>
			</form>

			<p class="description">
				<?php
				printf(
					/* translators: %s: number of passkeys. */
					esc_html__( 'Total passkeys: %s', 'rapls-passkey' ),
					esc_html( number_format_i18n( $total ) )
				);
				?>
			</p>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'User', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Name', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Authenticator', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Registered', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Last used', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Status', 'rapls-passkey' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( empty( $credentials ) ) : ?>
					<tr><td colspan="7"><?php esc_html_e( 'No passkeys found.', 'rapls-passkey' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $credentials as $credential ) : ?>
						<?php
						$owner    = get_user_by( 'id', (int) $credential->user_id );
						$can_edit = current_user_can( 'edit_user', (int) $credential->user_id );
						?>
						<tr>
							<td>
								<?php if ( $owner ) : ?>
									<a href="<?php echo esc_url( get_edit_user_link( (int) $credential->user_id ) ); ?>"><?php echo esc_html( $owner->user_login ); ?></a>
								<?php else : ?>
									<?php esc_html_e( '(deleted user)', 'rapls-passkey' ); ?>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( $credential->label ? $credential->label : __( '(no name)', 'rapls-passkey' ) ); ?></td>
							<td><?php echo esc_html( AuthenticatorNames::display( $credential->record_json, __( 'Unknown', 'rapls-passkey' ) ) ); ?></td>
							<td><?php echo esc_html( $credential->created_at ); ?></td>
							<td><?php echo esc_html( $credential->last_used_at ? $credential->last_used_at : __( 'Never', 'rapls-passkey' ) ); ?></td>
							<td><?php echo esc_html( $credential->active ? __( 'Active', 'rapls-passkey' ) : __( 'Suspended', 'rapls-passkey' ) ); ?></td>
							<td>
								<?php if ( $can_edit ) : ?>
									<a href="<?php echo esc_url( $this->action_url( (int) $credential->id, $credential->active ? 'suspend' : 'resume' ) ); ?>">
										<?php echo esc_html( $credential->active ? __( 'Suspend', 'rapls-passkey' ) : __( 'Resume', 'rapls-passkey' ) ); ?>
									</a>
									|
									<a href="<?php echo esc_url( $this->action_url( (int) $credential->id, 'delete' ) ); ?>" class="submitdelete" data-rapls-confirm="<?php esc_attr_e( 'Delete this passkey? This cannot be undone.', 'rapls-passkey' ); ?>">
										<?php esc_html_e( 'Delete', 'rapls-passkey' ); ?>
									</a>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) : ?>
				<div class="tablenav"><div class="tablenav-pages">
					<?php
					echo wp_kses_post(
						paginate_links(
							array(
								'base'    => add_query_arg( 'paged', '%#%' ),
								'format'  => '',
								'current' => $paged,
								'total'   => $pages,
							)
						)
					);
					?>
				</div></div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Nonce-protected admin-post URL for one row action.
	 *
	 * @param int    $id Credential row id.
	 * @param string $do suspend | resume | delete.
	 * @return string
	 */
	private function action_url( int $id, string $do ): string {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action'     => self::ACTION,
					'credential' => $id,
					'do'         => $do,
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION . '_' . $id
		);
	}

	/**
	 * Message for a result flag.
	 *
	 * @param string $result Result slug.
	 * @return string
	 */
	private function notice( string $result ): string {
		switch ( $result ) {
			case 'deleted':
				return __( 'The passkey was deleted.', 'rapls-passkey' );
			case 'suspended':
				return __( 'The passkey was suspended. It cannot be used to sign in until you resume it.', 'rapls-passkey' );
			case 'resumed':
				return __( 'The passkey was resumed.', 'rapls-passkey' );
			default:
				return __( 'That passkey no longer exists.', 'rapls-passkey' );
		}
	}
}
