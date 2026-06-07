<?php
/**
 * Settings & audit screen.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Support\Compat;
use RaplsPasskey\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Options page under Settings → Rapls Passkey: reCAPTCHA configuration, detected
 * security-plugin coexistence notes, and the recent audit log.
 */
final class SettingsPage {

	/** Settings group. */
	private const GROUP = 'rapls_passkey_group';

	/**
	 * Hook the admin menu and settings registration.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
	}

	/**
	 * Add the options page.
	 */
	public function add_page(): void {
		add_options_page(
			__( 'Rapls Passkey', 'rapls-passkey' ),
			__( 'Rapls Passkey', 'rapls-passkey' ),
			'manage_options',
			'rapls-passkey',
			array( $this, 'render' )
		);
	}

	/**
	 * Register the single settings array with a sanitiser.
	 */
	public function register_settings(): void {
		register_setting(
			self::GROUP,
			Settings::OPTION,
			array( 'sanitize_callback' => array( $this, 'sanitize' ) )
		);
	}

	/**
	 * Sanitise submitted settings.
	 *
	 * @param mixed $input Raw input.
	 * @return array<string,mixed>
	 */
	public function sanitize( $input ): array {
		$input     = is_array( $input ) ? $input : array();
		$threshold = isset( $input['recaptcha_threshold'] ) ? (float) $input['recaptcha_threshold'] : 0.5;
		$threshold = max( 0.0, min( 1.0, $threshold ) );

		return array(
			'recaptcha_enabled'    => ! empty( $input['recaptcha_enabled'] ),
			'recaptcha_site_key'   => isset( $input['recaptcha_site_key'] ) ? sanitize_text_field( $input['recaptcha_site_key'] ) : '',
			'recaptcha_secret_key' => isset( $input['recaptcha_secret_key'] ) ? sanitize_text_field( $input['recaptcha_secret_key'] ) : '',
			'recaptcha_threshold'  => $threshold,
			'audit_enabled'        => ! empty( $input['audit_enabled'] ),
		);
	}

	/**
	 * Render the page.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s = Settings::all();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Rapls Passkey 設定', 'rapls-passkey' ); ?></h1>

			<form method="post" action="options.php">
				<?php settings_fields( self::GROUP ); ?>
				<h2><?php esc_html_e( 'reCAPTCHA v3(パスワードログイン保護)', 'rapls-passkey' ); ?></h2>
				<p class="description"><?php esc_html_e( 'パスワードによるログインを Google reCAPTCHA v3 で保護します。パスキーでのログインには適用されません(総当たり攻撃が成立しないため)。サイトキーとシークレットを入力し、有効化してください。', 'rapls-passkey' ); ?></p>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( '有効化', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_enabled]" value="1" <?php checked( ! empty( $s['recaptcha_enabled'] ) ); ?>>
								<?php esc_html_e( 'reCAPTCHA を有効にする', 'rapls-passkey' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-recaptcha-site"><?php esc_html_e( 'サイトキー', 'rapls-passkey' ); ?></label></th>
						<td><input type="text" class="regular-text" id="rapls-recaptcha-site" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_site_key]" value="<?php echo esc_attr( (string) $s['recaptcha_site_key'] ); ?>"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-recaptcha-secret"><?php esc_html_e( 'シークレットキー', 'rapls-passkey' ); ?></label></th>
						<td><input type="password" class="regular-text" id="rapls-recaptcha-secret" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_secret_key]" value="<?php echo esc_attr( (string) $s['recaptcha_secret_key'] ); ?>" autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-recaptcha-threshold"><?php esc_html_e( 'スコアしきい値', 'rapls-passkey' ); ?></label></th>
						<td>
							<input type="number" step="0.1" min="0" max="1" id="rapls-recaptcha-threshold" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_threshold]" value="<?php echo esc_attr( (string) $s['recaptcha_threshold'] ); ?>">
							<p class="description"><?php esc_html_e( '0.0〜1.0。これ未満のスコアは拒否します(既定 0.5)。', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( '監査ログ', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( '記録', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[audit_enabled]" value="1" <?php checked( ! empty( $s['audit_enabled'] ) ); ?>>
								<?php esc_html_e( '登録・ログイン・削除などのイベントを記録する', 'rapls-passkey' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>

			<?php $this->render_compat(); ?>
			<?php $this->render_audit(); ?>
		</div>
		<?php
	}

	/**
	 * Detected security plugins and coexistence note.
	 */
	private function render_compat(): void {
		$detected = Compat::detect();
		echo '<h2>' . esc_html__( 'セキュリティプラグインとの互換', 'rapls-passkey' ) . '</h2>';
		if ( array() === $detected ) {
			echo '<p>' . esc_html__( '既知のログイン系セキュリティプラグインは検出されませんでした。', 'rapls-passkey' ) . '</p>';
			return;
		}
		echo '<p>' . esc_html__( '次のプラグインを検出しました:', 'rapls-passkey' ) . ' <strong>' . esc_html( implode( ', ', $detected ) ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Rapls Passkey は標準のログインフックのみを使用し、ログイン成功時に wp_login を発火するため、これらと共存できます。ログイン画面の CAPTCHA が重複する場合は、どちらか一方を無効にしてください(本プラグインの reCAPTCHA は上記設定で無効化できます)。', 'rapls-passkey' ) . '</p>';
	}

	/**
	 * Recent audit events.
	 */
	private function render_audit(): void {
		echo '<h2>' . esc_html__( '最近のイベント', 'rapls-passkey' ) . '</h2>';
		$events = AuditLog::recent( 50 );
		if ( array() === $events ) {
			echo '<p>' . esc_html__( '記録されたイベントはありません。', 'rapls-passkey' ) . '</p>';
			return;
		}
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( '日時 (UTC)', 'rapls-passkey' ) . '</th>';
		echo '<th>' . esc_html__( 'イベント', 'rapls-passkey' ) . '</th>';
		echo '<th>' . esc_html__( 'ユーザー', 'rapls-passkey' ) . '</th>';
		echo '<th>' . esc_html__( '詳細', 'rapls-passkey' ) . '</th>';
		echo '<th>IP</th>';
		echo '</tr></thead><tbody>';
		foreach ( $events as $row ) {
			$user_label = (int) $row['user_id'] > 0 ? ( get_userdata( (int) $row['user_id'] )->user_login ?? (string) $row['user_id'] ) : '—';
			echo '<tr>';
			echo '<td>' . esc_html( (string) $row['created_at'] ) . '</td>';
			echo '<td>' . esc_html( (string) $row['event'] ) . '</td>';
			echo '<td>' . esc_html( (string) $user_label ) . '</td>';
			echo '<td>' . esc_html( (string) ( $row['detail'] ?? '' ) ) . '</td>';
			echo '<td>' . esc_html( (string) ( $row['ip'] ?? '' ) ) . '</td>';
			echo '</tr>';
		}
		echo '</tbody></table>';
	}
}
