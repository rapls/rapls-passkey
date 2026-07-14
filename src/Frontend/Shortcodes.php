<?php
/**
 * Front-end shortcodes for passkey login and management.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Frontend;

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Support\Help;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exposes the passkey ceremonies outside wp-login.php / the profile screen so
 * they can be embedded on any front-end page (membership areas, custom login
 * pages, WooCommerce account pages, …):
 *
 *   [rapls_passkey_login]     — a passkey sign-in button for logged-out visitors
 *   [rapls_passkey_register]  — passkey management for the logged-in user
 *
 * The same render methods back the Gutenberg blocks (see Frontend\Blocks).
 */
final class Shortcodes {

	/**
	 * Whether the shared front-end assets have been enqueued this request.
	 *
	 * @var bool
	 */
	private bool $assets_enqueued = false;

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Register the shortcodes and their assets.
	 */
	public function register(): void {
		add_action( 'wp_enqueue_scripts', array( $this, 'register_assets' ) );
		add_shortcode( 'rapls_passkey_login', array( $this, 'render_login' ) );
		add_shortcode( 'rapls_passkey_register', array( $this, 'render_register' ) );
	}

	/**
	 * Register (but do not enqueue) the shared scripts and styles.
	 */
	public function register_assets(): void {
		wp_register_script(
			'rapls-passkey-webauthn',
			RAPLS_PASSKEY_URL . 'assets/webauthn.js',
			array(),
			RAPLS_PASSKEY_VERSION,
			true
		);
		wp_register_script(
			'rapls-passkey-frontend',
			RAPLS_PASSKEY_URL . 'assets/frontend.js',
			array( 'rapls-passkey-webauthn' ),
			RAPLS_PASSKEY_VERSION,
			true
		);
		wp_register_style(
			'rapls-passkey-frontend',
			RAPLS_PASSKEY_URL . 'assets/frontend.css',
			array(),
			RAPLS_PASSKEY_VERSION
		);
	}

	/**
	 * Enqueue the shared assets once, with the JS config localised.
	 */
	private function enqueue_assets(): void {
		if ( $this->assets_enqueued ) {
			return;
		}
		$this->assets_enqueued = true;

		wp_enqueue_style( 'rapls-passkey-frontend' );
		wp_enqueue_script( 'rapls-passkey-webauthn' );
		wp_enqueue_script( 'rapls-passkey-frontend' );

		wp_localize_script(
			'rapls-passkey-frontend',
			'raplsPasskeyFrontend',
			array(
				'restUrl' => esc_url_raw( rest_url( 'rapls-passkey/v1/' ) ),
				// Present only for logged-in users; the register routes need it.
				'nonce'   => is_user_logged_in() ? wp_create_nonce( 'wp_rest' ) : '',
				'i18n'    => array(
					'authenticating' => __( 'Authenticating...', 'rapls-passkey' ),
					'loginFailed'    => __( 'Passkey authentication failed.', 'rapls-passkey' ),
					'registering'    => __( 'Registering passkey...', 'rapls-passkey' ),
					'registered'     => __( 'Passkey registered.', 'rapls-passkey' ),
					'registerFailed' => __( 'Failed to register the passkey.', 'rapls-passkey' ),
					'unsupported'    => __( 'This browser does not support passkeys.', 'rapls-passkey' ),
					'cancelled'      => __( 'The operation was cancelled or timed out. Please try again.', 'rapls-passkey' ),
					'duplicate'      => __( 'This authenticator already has a passkey registered.', 'rapls-passkey' ),
					'confirmDel'     => __( 'Delete this passkey?', 'rapls-passkey' ),
					'labelPrompt'    => __( 'Name for this passkey (optional):', 'rapls-passkey' ),
					'noLabel'        => __( '(no name)', 'rapls-passkey' ),
					'renamePrompt'   => __( 'New name for this passkey:', 'rapls-passkey' ),
					'renameFailed'   => __( 'Could not rename the passkey.', 'rapls-passkey' ),
				),
			)
		);
	}

	/**
	 * `[rapls_passkey_login]` — render the sign-in button for logged-out users.
	 *
	 * @param array<string,mixed>|string $atts Shortcode attributes.
	 * @return string
	 */
	public function render_login( $atts ): string {
		$atts = shortcode_atts(
			array(
				'redirect' => '',
				'label'    => __( 'Sign in with a passkey', 'rapls-passkey' ),
			),
			(array) $atts,
			'rapls_passkey_login'
		);

		if ( is_user_logged_in() ) {
			return '<div class="rapls-pk-fe rapls-pk-fe-note">' . esc_html__( 'You are already signed in.', 'rapls-passkey' ) . '</div>';
		}

		$this->enqueue_assets();

		$redirect = '' !== (string) $atts['redirect'] ? esc_url( (string) $atts['redirect'] ) : '';

		ob_start();
		?>
		<div class="rapls-pk-fe rapls-pk-fe-login" data-redirect="<?php echo esc_attr( $redirect ); ?>">
			<label class="rapls-pk-fe-field">
				<span class="rapls-pk-fe-label"><?php esc_html_e( 'Username or email address', 'rapls-passkey' ); ?></span>
				<input type="text" id="rapls-pk-fe-username" autocomplete="username webauthn" autocapitalize="off" autocorrect="off" spellcheck="false">
			</label>
			<button type="button" class="rapls-pk-fe-btn" id="rapls-pk-fe-login-btn"><?php echo esc_html( (string) $atts['label'] ); ?></button>
			<p class="rapls-pk-fe-status" id="rapls-pk-fe-login-status" role="status" aria-live="polite"></p>
			<?php echo Help::html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</div>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * `[rapls_passkey_register]` — render passkey management for the current user.
	 *
	 * @param array<string,mixed>|string $atts Shortcode attributes.
	 * @return string
	 */
	public function render_register( $atts ): string {
		unset( $atts );

		if ( ! is_user_logged_in() ) {
			return '<div class="rapls-pk-fe rapls-pk-fe-note">' . esc_html__( 'Please sign in to manage your passkeys.', 'rapls-passkey' ) . '</div>';
		}

		$this->enqueue_assets();

		$user_id     = get_current_user_id();
		$credentials = $this->repository->find_by_user( $user_id );

		ob_start();
		?>
		<div class="rapls-pk-fe rapls-pk-fe-register">
			<table class="rapls-pk-fe-table" id="rapls-pk-fe-list">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Name', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Authenticator', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Registered', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( 'Last used', 'rapls-passkey' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( empty( $credentials ) ) : ?>
					<tr class="rapls-pk-fe-empty"><td colspan="5"><?php esc_html_e( 'No passkeys are registered.', 'rapls-passkey' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $credentials as $credential ) : ?>
						<tr data-id="<?php echo esc_attr( (string) $credential->id ); ?>">
							<td class="rapls-pk-fe-label"><?php echo esc_html( $credential->label ? $credential->label : __( '(no name)', 'rapls-passkey' ) ); ?></td>
							<td><?php echo esc_html( \RaplsPasskey\Credentials\AuthenticatorNames::display( $credential->record_json, __( 'Unknown', 'rapls-passkey' ) ) ); ?></td>
							<td><?php echo esc_html( $credential->created_at ); ?></td>
							<td><?php echo esc_html( $credential->last_used_at ? $credential->last_used_at : '—' ); ?></td>
							<td>
								<button type="button" class="rapls-pk-fe-rename"><?php esc_html_e( 'Rename', 'rapls-passkey' ); ?></button>
								<button type="button" class="rapls-pk-fe-delete"><?php esc_html_e( 'Delete', 'rapls-passkey' ); ?></button>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
			<p>
				<button type="button" class="rapls-pk-fe-btn" id="rapls-pk-fe-register-btn"><?php esc_html_e( 'Register a passkey', 'rapls-passkey' ); ?></button>
				<span class="rapls-pk-fe-status" id="rapls-pk-fe-register-status" role="status" aria-live="polite"></span>
			</p>
			<?php echo Help::html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}
