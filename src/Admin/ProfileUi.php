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
 * Adds a "パスキー" section to the user profile screen: a list of registered
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
		wp_localize_script(
			'rapls-passkey-profile',
			'raplsPasskeyProfile',
			array(
				'restUrl' => esc_url_raw( rest_url( 'rapls-passkey/v1/' ) ),
				'nonce'   => wp_create_nonce( 'wp_rest' ),
				'i18n'    => array(
					'registering' => __( 'パスキーを登録しています…', 'rapls-passkey' ),
					'success'     => __( 'パスキーを登録しました。', 'rapls-passkey' ),
					'failed'      => __( 'パスキーの登録に失敗しました。', 'rapls-passkey' ),
					'unsupported' => __( 'このブラウザはパスキーに対応していません。', 'rapls-passkey' ),
					'cancelled'   => __( '登録がキャンセルされたか、時間切れになりました。もう一度お試しください。', 'rapls-passkey' ),
					'duplicate'   => __( 'この認証器にはすでにパスキーが登録されています。', 'rapls-passkey' ),
					'confirmDel'  => __( 'このパスキーを削除しますか?', 'rapls-passkey' ),
					'labelPrompt' => __( 'このパスキーの名前(任意):', 'rapls-passkey' ),
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
		?>
		<h2 id="rapls-passkey"><?php esc_html_e( 'パスキー', 'rapls-passkey' ); ?></h2>
		<style>
			#rapls-passkey-list th,
			#rapls-passkey-list td { padding-left: 14px; }
		</style>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( '登録済みのパスキー', 'rapls-passkey' ); ?></th>
				<td>
					<table class="widefat striped" id="rapls-passkey-list" style="max-width:640px">
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
							<tr class="rapls-passkey-empty"><td colspan="5"><?php esc_html_e( '登録済みのパスキーはありません。', 'rapls-passkey' ); ?></td></tr>
						<?php else : ?>
							<?php foreach ( $credentials as $credential ) : ?>
								<tr data-id="<?php echo esc_attr( (string) $credential->id ); ?>">
									<td><?php echo esc_html( $credential->label ? $credential->label : __( '(名前なし)', 'rapls-passkey' ) ); ?></td>
									<td><?php echo esc_html( AuthenticatorNames::display( $credential->record_json, __( '不明', 'rapls-passkey' ) ) ); ?></td>
									<td><?php echo esc_html( $credential->created_at ); ?></td>
									<td><?php echo esc_html( $credential->last_used_at ? $credential->last_used_at : '—' ); ?></td>
									<td>
										<?php if ( $can_delete ) : ?>
											<button type="button" class="button-link delete rapls-passkey-delete"><?php esc_html_e( '削除', 'rapls-passkey' ); ?></button>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						<?php endif; ?>
						</tbody>
					</table>

					<?php if ( $is_self ) : ?>
						<p style="margin-top:12px">
							<button type="button" class="button button-primary" id="rapls-passkey-register"><?php esc_html_e( 'パスキーを登録', 'rapls-passkey' ); ?></button>
							<span id="rapls-passkey-status" style="margin-left:8px"></span>
						</p>
						<?php Help::render(); ?>
					<?php else : ?>
						<p class="description"><?php esc_html_e( 'パスキーの登録は本人のプロフィール画面からのみ行えます。', 'rapls-passkey' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}
}
