<?php
/**
 * Settings & audit screen.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\CredentialRepository;
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
			'max_passkeys'         => isset( $input['max_passkeys'] ) ? max( 0, (int) $input['max_passkeys'] ) : 0,
			'notifications_enabled' => ! empty( $input['notifications_enabled'] ),
			'upgrade_prompt_enabled' => ! empty( $input['upgrade_prompt_enabled'] ),
			'webauthn_timeout'     => isset( $input['webauthn_timeout'] ) ? max( 0, min( 600, (int) $input['webauthn_timeout'] ) ) : 60,
			'webauthn_user_verification' => in_array( $input['webauthn_user_verification'] ?? '', array( 'required', 'preferred', 'discouraged' ), true ) ? $input['webauthn_user_verification'] : 'preferred',
			'webauthn_attachment'  => in_array( $input['webauthn_attachment'] ?? '', array( 'platform', 'cross-platform' ), true ) ? $input['webauthn_attachment'] : '',
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

				<?php $this->render_adoption(); ?>

			<form method="post" action="options.php">
				<?php settings_fields( self::GROUP ); ?>
				<h2><?php esc_html_e( 'パスキー', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="rapls-max-passkeys"><?php esc_html_e( '1ユーザーあたりの登録上限', 'rapls-passkey' ); ?></label></th>
						<td>
							<input type="number" step="1" min="0" id="rapls-max-passkeys" name="<?php echo esc_attr( Settings::OPTION ); ?>[max_passkeys]" value="<?php echo esc_attr( (string) $s['max_passkeys'] ); ?>">
							<p class="description"><?php esc_html_e( 'ユーザーが登録できるパスキーの最大数。0 は無制限です。複数端末での利用を考慮し、2 以上を推奨します。', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( '詳細設定(WebAuthn)', 'rapls-passkey' ); ?></h2>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="rapls-wa-timeout"><?php esc_html_e( 'タイムアウト(秒)', 'rapls-passkey' ); ?></label></th>
							<td>
								<input type="number" step="1" min="0" max="600" id="rapls-wa-timeout" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_timeout]" value="<?php echo esc_attr( (string) $s['webauthn_timeout'] ); ?>">
								<p class="description"><?php esc_html_e( 'パスキーの登録・認証ダイアログのタイムアウト。0 はブラウザ既定(通常 60 秒程度)を使用します。', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="rapls-wa-uv"><?php esc_html_e( 'ユーザー検証', 'rapls-passkey' ); ?></label></th>
							<td>
								<select id="rapls-wa-uv" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_user_verification]">
									<option value="preferred" <?php selected( $s['webauthn_user_verification'], 'preferred' ); ?>><?php esc_html_e( '推奨(preferred)', 'rapls-passkey' ); ?></option>
									<option value="required" <?php selected( $s['webauthn_user_verification'], 'required' ); ?>><?php esc_html_e( '必須(required)', 'rapls-passkey' ); ?></option>
									<option value="discouraged" <?php selected( $s['webauthn_user_verification'], 'discouraged' ); ?>><?php esc_html_e( '不要(discouraged)', 'rapls-passkey' ); ?></option>
								</select>
								<p class="description"><?php esc_html_e( '生体認証や PIN による本人確認をどの程度求めるか。「必須」は対応していない認証器を弾く可能性があります。通常は「推奨」のままを推奨します。', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="rapls-wa-attachment"><?php esc_html_e( '認証器の種類', 'rapls-passkey' ); ?></label></th>
							<td>
								<select id="rapls-wa-attachment" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_attachment]">
									<option value="" <?php selected( $s['webauthn_attachment'], '' ); ?>><?php esc_html_e( '指定なし(すべて許可)', 'rapls-passkey' ); ?></option>
									<option value="platform" <?php selected( $s['webauthn_attachment'], 'platform' ); ?>><?php esc_html_e( '内蔵のみ(Touch ID / Windows Hello など)', 'rapls-passkey' ); ?></option>
									<option value="cross-platform" <?php selected( $s['webauthn_attachment'], 'cross-platform' ); ?>><?php esc_html_e( '外付けのみ(セキュリティキー / 別端末)', 'rapls-passkey' ); ?></option>
								</select>
								<p class="description"><?php esc_html_e( '新規登録時に許可する認証器の種類(登録時のみ適用)。通常は「指定なし」を推奨します。', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
					</table>

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

				<h2><?php esc_html_e( 'セキュリティ通知メール', 'rapls-passkey' ); ?></h2>
					<p class="description"><?php esc_html_e( 'パスキーの登録・削除、および新しい端末からのパスキーサインインを、対象ユーザー本人のメールアドレスに通知します。乗っ取りの早期発見に役立ちます。', 'rapls-passkey' ); ?></p>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( '送信', 'rapls-passkey' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[notifications_enabled]" value="1" <?php checked( ! empty( $s['notifications_enabled'] ) ); ?>>
									<?php esc_html_e( 'セキュリティ通知メールを送信する', 'rapls-passkey' ); ?>
								</label>
							</td>
						</tr>
					</table>

					<h2><?php esc_html_e( 'パスキー登録のうながし', 'rapls-passkey' ); ?></h2>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'ログイン後の表示', 'rapls-passkey' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[upgrade_prompt_enabled]" value="1" <?php checked( ! empty( $s['upgrade_prompt_enabled'] ) ); ?>>
									<?php esc_html_e( 'パスワードでログインした直後に、パスキーの作成をその場でおすすめする(パスキー未登録のユーザーのみ)', 'rapls-passkey' ); ?>
								</label>
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
	 * Passkey adoption summary (how many users have enrolled).
	 */
	private function render_adoption(): void {
		$stats       = ( new CredentialRepository() )->stats();
		$counts      = count_users();
		$total_users = isset( $counts['total_users'] ) ? (int) $counts['total_users'] : 0;
		$pct         = $total_users > 0 ? (int) round( $stats['users'] / $total_users * 100 ) : 0;

		echo '<h2>' . esc_html__( '導入状況', 'rapls-passkey' ) . '</h2>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: users with a passkey, 2: total users, 3: percentage. */
				__( 'パスキーを登録済みのユーザー: %1$d / %2$d 人(%3$d%%)', 'rapls-passkey' ),
				$stats['users'],
				$total_users,
				$pct
			)
		) . '</p>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: %d: total number of registered passkeys. */
				__( '登録済みパスキーの総数: %d 個', 'rapls-passkey' ),
				$stats['total']
			)
		) . '</p>';
		echo '<p class="description">' . esc_html__( '各ユーザーの登録状況は「ユーザー」一覧の「パスキー」列で確認できます。', 'rapls-passkey' ) . '</p>';
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

		$export_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . AuditExport::ACTION ),
			AuditExport::ACTION
		);
		echo '<p><a class="button" href="' . esc_url( $export_url ) . '">' . esc_html__( 'CSV エクスポート', 'rapls-passkey' ) . '</a></p>';
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
