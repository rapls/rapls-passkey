<?php
/**
 * Front-end shortcodes for passkey login and management.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Frontend;

use RaplsPasskey\Credentials\CredentialRepository;

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
					'authenticating' => __( '認証しています…', 'rapls-passkey' ),
					'loginFailed'    => __( 'パスキーでの認証に失敗しました。', 'rapls-passkey' ),
					'registering'    => __( 'パスキーを登録しています…', 'rapls-passkey' ),
					'registered'     => __( 'パスキーを登録しました。', 'rapls-passkey' ),
					'registerFailed' => __( 'パスキーの登録に失敗しました。', 'rapls-passkey' ),
					'unsupported'    => __( 'このブラウザはパスキーに対応していません。', 'rapls-passkey' ),
					'cancelled'      => __( '操作がキャンセルされたか、時間切れになりました。もう一度お試しください。', 'rapls-passkey' ),
					'duplicate'      => __( 'この認証器にはすでにパスキーが登録されています。', 'rapls-passkey' ),
					'confirmDel'     => __( 'このパスキーを削除しますか?', 'rapls-passkey' ),
					'labelPrompt'    => __( 'このパスキーの名前(任意):', 'rapls-passkey' ),
					'noLabel'        => __( '(名前なし)', 'rapls-passkey' ),
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
				'label'    => __( 'パスキーでログイン', 'rapls-passkey' ),
			),
			(array) $atts,
			'rapls_passkey_login'
		);

		if ( is_user_logged_in() ) {
			return '<div class="rapls-pk-fe rapls-pk-fe-note">' . esc_html__( 'すでにログインしています。', 'rapls-passkey' ) . '</div>';
		}

		$this->enqueue_assets();

		$redirect = '' !== (string) $atts['redirect'] ? esc_url( (string) $atts['redirect'] ) : '';

		ob_start();
		?>
		<div class="rapls-pk-fe rapls-pk-fe-login" data-redirect="<?php echo esc_attr( $redirect ); ?>">
			<label class="rapls-pk-fe-field">
				<span class="rapls-pk-fe-label"><?php esc_html_e( 'ユーザー名またはメールアドレス', 'rapls-passkey' ); ?></span>
				<input type="text" id="rapls-pk-fe-username" autocomplete="username webauthn" autocapitalize="off" autocorrect="off" spellcheck="false">
			</label>
			<button type="button" class="rapls-pk-fe-btn" id="rapls-pk-fe-login-btn"><?php echo esc_html( (string) $atts['label'] ); ?></button>
			<p class="rapls-pk-fe-status" id="rapls-pk-fe-login-status" role="status" aria-live="polite"></p>
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
			return '<div class="rapls-pk-fe rapls-pk-fe-note">' . esc_html__( 'パスキーを管理するにはログインしてください。', 'rapls-passkey' ) . '</div>';
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
						<th><?php esc_html_e( '名前', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( '認証器', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( '登録日時', 'rapls-passkey' ); ?></th>
						<th><?php esc_html_e( '最終使用', 'rapls-passkey' ); ?></th>
						<th></th>
					</tr>
				</thead>
				<tbody>
				<?php if ( empty( $credentials ) ) : ?>
					<tr class="rapls-pk-fe-empty"><td colspan="5"><?php esc_html_e( '登録済みのパスキーはありません。', 'rapls-passkey' ); ?></td></tr>
				<?php else : ?>
					<?php foreach ( $credentials as $credential ) : ?>
						<tr data-id="<?php echo esc_attr( (string) $credential->id ); ?>">
							<td><?php echo esc_html( $credential->label ? $credential->label : __( '(名前なし)', 'rapls-passkey' ) ); ?></td>
							<td><?php echo esc_html( \RaplsPasskey\Credentials\AuthenticatorNames::display( $credential->record_json, __( '不明', 'rapls-passkey' ) ) ); ?></td>
							<td><?php echo esc_html( $credential->created_at ); ?></td>
							<td><?php echo esc_html( $credential->last_used_at ? $credential->last_used_at : '—' ); ?></td>
							<td><button type="button" class="rapls-pk-fe-delete"><?php esc_html_e( '削除', 'rapls-passkey' ); ?></button></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>
			<p>
				<button type="button" class="rapls-pk-fe-btn" id="rapls-pk-fe-register-btn"><?php esc_html_e( 'パスキーを登録', 'rapls-passkey' ); ?></button>
				<span class="rapls-pk-fe-status" id="rapls-pk-fe-register-status" role="status" aria-live="polite"></span>
			</p>
		</div>
		<?php
		return (string) ob_get_clean();
	}
}
