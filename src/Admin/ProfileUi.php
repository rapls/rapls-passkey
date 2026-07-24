<?php
/**
 * User profile passkey management UI.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Credentials\AuthenticatorNames;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Support\Help;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds a "Passkey" section to the user profile screen: a list of registered
 * passkeys (with delete), and — on one's own profile — a register button.
 */
final class ProfileUi {

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the profile screens.
	 */
	public function register(): void {
		add_action( 'show_user_profile', array( $this, 'render' ) );
		add_action( 'edit_user_profile', array( $this, 'render' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	/**
	 * Enqueue the profile script on the profile screens only.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue( string $hook ): void {
		if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
			return;
		}

		wp_enqueue_script(
			'rapls-passkey-webauthn',
			RAPLS_PASSKEY_URL . 'assets/webauthn.js',
			array(),
			RAPLS_PASSKEY_VERSION,
			true
		);
		wp_enqueue_script(
			'rapls-passkey-profile',
			RAPLS_PASSKEY_URL . 'assets/profile.js',
			array( 'rapls-passkey-webauthn' ),
			RAPLS_PASSKEY_VERSION,
			true
		);
		// A tiny bit of layout CSS, attached the sanctioned way (no inline <style>).
		wp_register_style( 'rapls-passkey-profile', false, array(), RAPLS_PASSKEY_VERSION );
		wp_enqueue_style( 'rapls-passkey-profile' );
		wp_add_inline_style( 'rapls-passkey-profile', '#rapls-passkey-list th,#rapls-passkey-list td{padding-left:14px}' );

		wp_localize_script(
			'rapls-passkey-profile',
			'raplsPasskeyProfile',
			array(
				'restUrl' => esc_url_raw( rest_url( 'rapls-passkey/v1/' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
				'i18n'    => array(
					'registering' => __( 'Registering passkey...', 'rapls-passkey' ),
					'success'     => __( 'Passkey registered.', 'rapls-passkey' ),
					'failed'      => __( 'Failed to register the passkey.', 'rapls-passkey' ),
					'unsupported' => __( 'This browser does not support passkeys.', 'rapls-passkey' ),
					'cancelled'   => __( 'Registration was cancelled or timed out. Please try again.', 'rapls-passkey' ),
					'duplicate'   => __( 'This authenticator already has a passkey registered.', 'rapls-passkey' ),
					'confirmDel'  => __( 'Delete this passkey?', 'rapls-passkey' ),
					'labelPrompt' => __( 'Name for this passkey (optional):', 'rapls-passkey' ),
					'renamePrompt' => __( 'New name for this passkey:', 'rapls-passkey' ),
					'renameFailed' => __( 'Could not rename the passkey.', 'rapls-passkey' ),
					'noName'      => __( '(no name)', 'rapls-passkey' ),
					'active'      => __( 'Active', 'rapls-passkey' ),
					'suspended'   => __( 'Suspended', 'rapls-passkey' ),
					'suspend'     => __( 'Suspend', 'rapls-passkey' ),
					'resume'      => __( 'Resume', 'rapls-passkey' ),
					'confirmSuspend' => __( 'Suspend this passkey? It will stop working until you resume it, but it is not deleted.', 'rapls-passkey' ),
				),
			)
		);
	}

	/**
	 * Render the profile section.
	 *
	 * @param WP_User $user The profile being edited.
	 */
	public function render( WP_User $user ): void {
		$is_self     = ( get_current_user_id() === (int) $user->ID );
		$can_delete  = $is_self || current_user_can( 'edit_user', (int) $user->ID );
		$credentials = $this->repository->find_by_user( (int) $user->ID );

		/** Documented in Rest\Endpoints::enrolment_target(). */
		$can_enrol = ! $is_self
			&& current_user_can( 'edit_user', (int) $user->ID )
			&& apply_filters( 'rapls_passkey/allow_admin_enrolment', false );
		?>
		<h2 id="rapls-passkey"><?php esc_html_e( 'Passkey', 'rapls-passkey' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php echo esc_html( $is_self ? __( 'Your registered passkeys', 'rapls-passkey' ) : __( 'Registered passkeys', 'rapls-passkey' ) ); ?></th>
				<td>
					<table class="widefat striped" id="rapls-passkey-list" style="max-width:640px">
						<thead>
							<tr>
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
							<tr class="rapls-passkey-empty"><td colspan="6"><?php esc_html_e( 'No passkeys are registered.', 'rapls-passkey' ); ?></td></tr>
						<?php else : ?>
							<?php foreach ( $credentials as $credential ) : ?>
								<tr data-id="<?php echo esc_attr( (string) $credential->id ); ?>" data-active="<?php echo $credential->active ? '1' : '0'; ?>">
									<td class="rapls-passkey-label"><?php echo esc_html( $credential->label ? $credential->label : __( '(no name)', 'rapls-passkey' ) ); ?></td>
									<td><?php echo esc_html( AuthenticatorNames::display( $credential->record_json, __( 'Unknown', 'rapls-passkey' ) ) ); ?></td>
									<td><?php echo esc_html( $credential->created_at ); ?></td>
									<td><?php echo esc_html( $credential->last_used_at ? $credential->last_used_at : '—' ); ?></td>
									<td class="rapls-passkey-state">
										<?php echo esc_html( $credential->active ? __( 'Active', 'rapls-passkey' ) : __( 'Suspended', 'rapls-passkey' ) ); ?>
									</td>
									<td>
										<?php if ( $is_self ) : ?>
											<button type="button" class="button-link rapls-passkey-rename"><?php esc_html_e( 'Rename', 'rapls-passkey' ); ?></button>
										<?php endif; ?>
										<?php if ( $can_delete ) : ?>
											<button type="button" class="button-link rapls-passkey-toggle">
												<?php echo esc_html( $credential->active ? __( 'Suspend', 'rapls-passkey' ) : __( 'Resume', 'rapls-passkey' ) ); ?>
											</button>
											<button type="button" class="button-link delete rapls-passkey-delete"><?php esc_html_e( 'Delete', 'rapls-passkey' ); ?></button>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
						</tbody>
					</table>

					<?php if ( $is_self ) : ?>
						<p style="margin-top:12px">
							<button type="button" class="button button-primary" id="rapls-passkey-register"><?php esc_html_e( 'Register a passkey', 'rapls-passkey' ); ?></button>
							<span id="rapls-passkey-status" style="margin-left:8px"></span>
						</p>
						<?php Help::render(); ?>
					<?php elseif ( $can_enrol ) : ?>
						<p style="margin-top:12px">
							<button type="button" class="button" id="rapls-passkey-register" data-user="<?php echo esc_attr( (string) $user->ID ); ?>"><?php esc_html_e( 'Register a passkey for this user', 'rapls-passkey' ); ?></button>
							<span id="rapls-passkey-status" style="margin-left:8px"></span>
						</p>
						<p class="description">
							<?php esc_html_e( 'The passkey is created on the authenticator in front of you right now (your device, or a security key you are about to hand over) — so use this only when you are setting the user up in person. They are emailed about the new passkey, and it is recorded in the audit log.', 'rapls-passkey' ); ?>
						</p>
					<?php else : ?>
						<p class="description"><?php esc_html_e( 'Passkeys can only be registered from your own profile screen.', 'rapls-passkey' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}
}
