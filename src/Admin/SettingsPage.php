<?php
/**
 * Settings & audit screen.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Security\SecondFactor;
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

	/** admin-post action for "reset to defaults". */
	private const RESET_ACTION = 'rapls_passkey_reset_settings';

	/**
	 * Hook the admin menu and settings registration.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_post_' . self::RESET_ACTION, array( $this, 'handle_reset' ) );
	}

	/**
	 * Reset all settings to their defaults, then return to the settings screen.
	 */
	public function handle_reset(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'rapls-passkey' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::RESET_ACTION );

		update_option( Settings::OPTION, Settings::defaults() );

		wp_safe_redirect( add_query_arg( 'rapls_pk_reset', 'ok', admin_url( 'options-general.php?page=rapls-passkey' ) ) );
		exit;
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
			'recaptcha_secret_key' => $this->store_secret( isset( $input['recaptcha_secret_key'] ) ? (string) $input['recaptcha_secret_key'] : '' ),
			'recaptcha_threshold'  => $threshold,
			'audit_enabled'        => ! empty( $input['audit_enabled'] ),
			'max_passkeys'         => isset( $input['max_passkeys'] ) ? max( 0, (int) $input['max_passkeys'] ) : 0,
			'login_rate_max'       => isset( $input['login_rate_max'] ) ? max( 0, (int) $input['login_rate_max'] ) : 30,
			'login_rate_window'    => isset( $input['login_rate_window'] ) ? max( 1, (int) $input['login_rate_window'] ) : 300,
			'admin_remember_allowed' => ! empty( $input['admin_remember_allowed'] ),
			'alt_login_second_factor' => ! empty( $input['alt_login_second_factor'] ),
			'notifications_enabled' => ! empty( $input['notifications_enabled'] ),
			'upgrade_prompt_enabled' => ! empty( $input['upgrade_prompt_enabled'] ),
			'webauthn_timeout'     => isset( $input['webauthn_timeout'] ) ? max( 0, min( 600, (int) $input['webauthn_timeout'] ) ) : 60,
			'webauthn_user_verification' => in_array( $input['webauthn_user_verification'] ?? '', array( 'required', 'preferred', 'discouraged' ), true ) ? $input['webauthn_user_verification'] : 'preferred',
			'webauthn_attachment'  => in_array( $input['webauthn_attachment'] ?? '', array( 'platform', 'cross-platform' ), true ) ? $input['webauthn_attachment'] : '',
			'webauthn_hints'       => isset( $input['webauthn_hints'] ) && is_array( $input['webauthn_hints'] )
				? array_values( array_intersect( array( 'security-key', 'client-device', 'hybrid' ), array_map( 'strval', $input['webauthn_hints'] ) ) )
				: array(),
		);
	}

	/**
	 * Store a secret, idempotently. An already-encrypted value (e.g. re-sanitised
	 * during a settings import) is kept as-is rather than double-encrypted.
	 *
	 * @param string $value Plaintext secret, or existing ciphertext.
	 * @return string Tagged ciphertext, or '' for empty input.
	 */
	private function store_secret( string $value ): string {
		if ( \RaplsPasskey\Security\Secret::is_encrypted( $value ) ) {
			return $value;
		}
		return \RaplsPasskey\Security\Secret::encrypt( sanitize_text_field( $value ) );
	}

	/**
	 * Render the page.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_enqueue_script( 'rapls-passkey-admin', RAPLS_PASSKEY_URL . 'assets/admin.js', array(), RAPLS_PASSKEY_VERSION, true );
		$s = Settings::all();
		?>
		<div class="wrap">
			<h1>
				<?php esc_html_e( 'Rapls Passkey Settings', 'rapls-passkey' ); ?>
				<a href="<?php echo esc_url( SetupWizard::url() ); ?>" class="page-title-action"><?php esc_html_e( 'Setup check', 'rapls-passkey' ); ?></a>
			</h1>

			<?php if ( isset( $_GET['rapls_pk_reset'] ) && 'ok' === sanitize_key( wp_unslash( $_GET['rapls_pk_reset'] ) ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings were reset to their defaults.', 'rapls-passkey' ); ?></p></div>
			<?php endif; ?>

				<?php $this->render_adoption(); ?>

			<form method="post" action="options.php">
				<?php settings_fields( self::GROUP ); ?>
				<h2><?php esc_html_e( 'Passkey', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="rapls-max-passkeys"><?php esc_html_e( 'Per-user registration limit', 'rapls-passkey' ); ?></label></th>
						<td>
							<input type="number" step="1" min="0" id="rapls-max-passkeys" name="<?php echo esc_attr( Settings::OPTION ); ?>[max_passkeys]" value="<?php echo esc_attr( (string) $s['max_passkeys'] ); ?>">
							<p class="description"><?php esc_html_e( 'Maximum number of passkeys a user can register. 0 means unlimited. We recommend 2 or more so passkeys can be used across multiple devices.', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Login rate limit', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="rapls-login-rate-max"><?php esc_html_e( 'Attempt limit', 'rapls-passkey' ); ?></label></th>
						<td>
							<input type="number" step="1" min="0" id="rapls-login-rate-max" name="<?php echo esc_attr( Settings::OPTION ); ?>[login_rate_max]" value="<?php echo esc_attr( (string) $s['login_rate_max'] ); ?>">
							<p class="description"><?php esc_html_e( 'How many failed passkey-login attempts from the same IP address are allowed within the window below before "Too many attempts" is shown. Successful logins are not counted. 0 disables the limit.', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-login-rate-window"><?php esc_html_e( 'Lockout time (seconds)', 'rapls-passkey' ); ?></label></th>
						<td>
							<input type="number" step="1" min="1" id="rapls-login-rate-window" name="<?php echo esc_attr( Settings::OPTION ); ?>[login_rate_window]" value="<?php echo esc_attr( (string) $s['login_rate_window'] ); ?>">
							<p class="description"><?php esc_html_e( 'The length of the counting window, and how long the lockout lasts once the attempt limit is reached (default 300 seconds = 5 minutes).', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Session security', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Administrator "remember me"', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[admin_remember_allowed]" value="1" <?php checked( ! empty( $s['admin_remember_allowed'] ) ); ?>>
								<?php esc_html_e( 'Allow administrators to stay signed in ("remember me") after a passkey login', 'rapls-passkey' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Off by default for safety: administrators never get a persistent session, so a shared or stolen device cannot keep an admin logged in. Turn this on to honour the "remember me" checkbox for administrators too. Non-administrators are unaffected.', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Two-factor on alternative logins', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[alt_login_second_factor]" value="1" <?php checked( ! empty( $s['alt_login_second_factor'] ) ); ?>>
								<?php esc_html_e( 'Ask for the site\'s two-factor code on the logins that are weaker than a passkey', 'rapls-passkey' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'Two-factor plugins (Wordfence Login Security, Two-Factor, ...) only enforce inside the wp-login.php password chain, which the email magic link and the recovery-code login do not go through — so without this they are a way around your 2FA. A passkey sign-in (including the QR cross-device flow) is itself the second factor and is never challenged. Only users who have actually set a second factor up see the challenge.', 'rapls-passkey' ); ?>
							</p>
							<?php $detected = SecondFactor::providers(); ?>
							<?php if ( array() === $detected ) : ?>
								<p class="description"><em><?php esc_html_e( 'No supported two-factor plugin detected, so this setting currently has no effect.', 'rapls-passkey' ); ?></em></p>
							<?php else : ?>
								<p class="description">
									<strong><?php esc_html_e( 'Detected:', 'rapls-passkey' ); ?></strong>
									<?php
									$labels = array();
									foreach ( $detected as $provider ) {
										$labels[] = $provider->label();
									}
									echo esc_html( implode( ', ', $labels ) );
									?>
								</p>
							<?php endif; ?>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Advanced (WebAuthn)', 'rapls-passkey' ); ?></h2>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><label for="rapls-wa-timeout"><?php esc_html_e( 'Timeout (seconds)', 'rapls-passkey' ); ?></label></th>
							<td>
								<input type="number" step="1" min="0" max="600" id="rapls-wa-timeout" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_timeout]" value="<?php echo esc_attr( (string) $s['webauthn_timeout'] ); ?>">
								<p class="description"><?php esc_html_e( 'Timeout for the passkey registration and authentication dialogs. 0 uses the browser default (typically around 60 seconds).', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="rapls-wa-uv"><?php esc_html_e( 'User verification', 'rapls-passkey' ); ?></label></th>
							<td>
								<select id="rapls-wa-uv" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_user_verification]">
									<option value="preferred" <?php selected( $s['webauthn_user_verification'], 'preferred' ); ?>><?php esc_html_e( 'Preferred', 'rapls-passkey' ); ?></option>
									<option value="required" <?php selected( $s['webauthn_user_verification'], 'required' ); ?>><?php esc_html_e( 'Required', 'rapls-passkey' ); ?></option>
									<option value="discouraged" <?php selected( $s['webauthn_user_verification'], 'discouraged' ); ?>><?php esc_html_e( 'Discouraged', 'rapls-passkey' ); ?></option>
								</select>
								<p class="description"><?php esc_html_e( 'How strongly to require identity verification via biometrics or PIN. Required may reject authenticators that do not support it; leaving this at Preferred is usually recommended.', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><label for="rapls-wa-attachment"><?php esc_html_e( 'Authenticator type', 'rapls-passkey' ); ?></label></th>
							<td>
								<select id="rapls-wa-attachment" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_attachment]">
									<option value="" <?php selected( $s['webauthn_attachment'], '' ); ?>><?php esc_html_e( 'No preference (allow all)', 'rapls-passkey' ); ?></option>
									<option value="platform" <?php selected( $s['webauthn_attachment'], 'platform' ); ?>><?php esc_html_e( 'Platform only (Touch ID / Windows Hello, etc.)', 'rapls-passkey' ); ?></option>
									<option value="cross-platform" <?php selected( $s['webauthn_attachment'], 'cross-platform' ); ?>><?php esc_html_e( 'Cross-platform only (security key / another device)', 'rapls-passkey' ); ?></option>
								</select>
								<p class="description"><?php esc_html_e( 'Which authenticator type to allow at registration (applies at registration only). No preference is usually recommended.', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
						<tr>
							<th scope="row"><?php esc_html_e( 'UI hints', 'rapls-passkey' ); ?></th>
							<td>
								<?php
								$hints     = (array) ( $s['webauthn_hints'] ?? array() );
								$hint_opts = array(
									'client-device' => __( 'Passkey on this device (client-device)', 'rapls-passkey' ),
									'hybrid'        => __( 'Another device / QR (hybrid)', 'rapls-passkey' ),
									'security-key'  => __( 'Security key (security-key)', 'rapls-passkey' ),
								);
								foreach ( $hint_opts as $value => $label ) :
									?>
									<label style="display:block;margin:2px 0">
										<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[webauthn_hints][]" value="<?php echo esc_attr( $value ); ?>" <?php checked( in_array( $value, $hints, true ) ); ?>>
										<?php echo esc_html( $label ); ?>
									</label>
								<?php endforeach; ?>
								<p class="description"><?php esc_html_e( 'Give supported browsers hints about which sign-in methods to suggest first (order is respected). No hints are sent if none are selected.', 'rapls-passkey' ); ?></p>
							</td>
						</tr>
					</table>

					<h2><?php esc_html_e( 'reCAPTCHA v3 (password login protection)', 'rapls-passkey' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Protect password logins with Google reCAPTCHA v3. It does not apply to passkey logins (brute force does not work against them). Enter your site key and secret, then enable it.', 'rapls-passkey' ); ?></p>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Enable', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_enabled]" value="1" <?php checked( ! empty( $s['recaptcha_enabled'] ) ); ?>>
								<?php esc_html_e( 'Enable reCAPTCHA', 'rapls-passkey' ); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-recaptcha-site"><?php esc_html_e( 'Site key', 'rapls-passkey' ); ?></label></th>
						<td><input type="text" class="regular-text" id="rapls-recaptcha-site" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_site_key]" value="<?php echo esc_attr( (string) $s['recaptcha_site_key'] ); ?>"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-recaptcha-secret"><?php esc_html_e( 'Secret key', 'rapls-passkey' ); ?></label></th>
						<td><input type="password" class="regular-text" id="rapls-recaptcha-secret" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_secret_key]" value="<?php echo esc_attr( \RaplsPasskey\Security\Secret::decrypt( (string) $s['recaptcha_secret_key'] ) ); ?>" autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="rapls-recaptcha-threshold"><?php esc_html_e( 'Score threshold', 'rapls-passkey' ); ?></label></th>
						<td>
							<input type="number" step="0.1" min="0" max="1" id="rapls-recaptcha-threshold" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_threshold]" value="<?php echo esc_attr( (string) $s['recaptcha_threshold'] ); ?>">
							<p class="description"><?php esc_html_e( '0.0 to 1.0. Scores below this are rejected (default 0.5).', 'rapls-passkey' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Security notification emails', 'rapls-passkey' ); ?></h2>
					<p class="description"><?php esc_html_e( 'Email the affected user about passkey registration and removal, and about passkey sign-ins from a new device. Helps detect account takeover early.', 'rapls-passkey' ); ?></p>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'Send', 'rapls-passkey' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[notifications_enabled]" value="1" <?php checked( ! empty( $s['notifications_enabled'] ) ); ?>>
									<?php esc_html_e( 'Send security notification emails', 'rapls-passkey' ); ?>
								</label>
							</td>
						</tr>
					</table>

					<h2><?php esc_html_e( 'Passkey enrolment prompt', 'rapls-passkey' ); ?></h2>
					<table class="form-table" role="presentation">
						<tr>
							<th scope="row"><?php esc_html_e( 'After login', 'rapls-passkey' ); ?></th>
							<td>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[upgrade_prompt_enabled]" value="1" <?php checked( ! empty( $s['upgrade_prompt_enabled'] ) ); ?>>
									<?php esc_html_e( 'Right after a password login, suggest creating a passkey on the spot (only for users without a passkey)', 'rapls-passkey' ); ?>
								</label>
							</td>
						</tr>
					</table>

					<h2><?php esc_html_e( 'Audit log', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Logging', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[audit_enabled]" value="1" <?php checked( ! empty( $s['audit_enabled'] ) ); ?>>
								<?php esc_html_e( 'Record events such as registration, login, and removal', 'rapls-passkey' ); ?>
							</label>
						</td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>

			<?php
			// Reset-to-defaults — its own form (posts to admin-post.php), kept
			// outside the settings form so its action field cannot override the
			// Settings API save.
			?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-rapls-confirm="<?php echo esc_attr__( 'Reset all Rapls Passkey settings to their defaults? This cannot be undone.', 'rapls-passkey' ); ?>">
				<input type="hidden" name="action" value="<?php echo esc_attr( self::RESET_ACTION ); ?>">
				<?php wp_nonce_field( self::RESET_ACTION ); ?>
				<?php submit_button( __( 'Reset to defaults', 'rapls-passkey' ), 'delete', 'submit', false ); ?>
				<span class="description" style="margin-left:8px"><?php esc_html_e( 'Restore every setting on this page to its default value.', 'rapls-passkey' ); ?></span>
			</form>

			<?php $this->render_compat(); ?>
			<?php $this->render_audit(); ?>
			<?php $this->render_upsell(); ?>
		</div>
		<?php
	}

	/**
	 * Upgrade-to-Pro panel. Shown only when Pro is not active (Pro flips the
	 * rapls_passkey/is_pro filter), and only on this settings screen — not a
	 * site-wide nag. All copy is translatable and the URL is filterable.
	 */
	private function render_upsell(): void {
		/** Filter: whether Pro is active (Pro returns true). */
		if ( (bool) apply_filters( 'rapls_passkey/is_pro', false ) ) {
			return;
		}

		/** Filter: whether to show the upgrade panel at all. */
		if ( ! (bool) apply_filters( 'rapls_passkey/show_upsell', true ) ) {
			return;
		}

		/** Filter: the "learn more" URL for Rapls Passkey Pro. */
		$url = (string) apply_filters( 'rapls_passkey/pro_url', 'https://raplsworks.com/rapls-passkey-pro/' );

		$features = array(
			__( 'Cross-device sign-in: approve a login on your computer from your phone via a QR code.', 'rapls-passkey' ),
			__( 'Passwordless recovery: one-time recovery codes and email magic-link sign-in.', 'rapls-passkey' ),
			__( 'Require passkeys for chosen roles, with a grace period, and optionally turn off password login.', 'rapls-passkey' ),
			__( 'Adaptive step-up: ask for a passkey again after a risky password sign-in.', 'rapls-passkey' ),
			__( 'Authenticator policy (FIDO Metadata Service / AAGUID allow & deny) and trusted-device management.', 'rapls-passkey' ),
			__( 'Security webhooks, adoption reports, multisite network settings and WP-CLI commands.', 'rapls-passkey' ),
		);

		echo '<h2>' . esc_html__( 'Rapls Passkey Pro', 'rapls-passkey' ) . '</h2>';
		echo '<div class="card" style="max-width:820px">';
		echo '<p>' . esc_html__( 'Everything here is free forever. If you want more, Rapls Passkey Pro adds:', 'rapls-passkey' ) . '</p>';
		echo '<ul style="list-style:disc;margin-left:20px">';
		foreach ( $features as $feature ) {
			echo '<li>' . esc_html( $feature ) . '</li>';
		}
		echo '</ul>';
		echo '<p><a class="button button-primary" href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">'
			. esc_html__( 'Learn more about Pro', 'rapls-passkey' )
			. '</a></p>';
		echo '</div>';
	}

	/**
	 * Passkey adoption summary (how many users have enrolled).
	 */
	private function render_adoption(): void {
		$stats       = ( new CredentialRepository() )->stats();
		$counts      = count_users();
		$total_users = isset( $counts['total_users'] ) ? (int) $counts['total_users'] : 0;
		$pct         = $total_users > 0 ? (int) round( $stats['users'] / $total_users * 100 ) : 0;

		echo '<h2>' . esc_html__( 'Adoption', 'rapls-passkey' ) . '</h2>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: 1: users with a passkey, 2: total users, 3: percentage. */
				__( 'Users with a passkey: %1$d / %2$d (%3$d%%)', 'rapls-passkey' ),
				$stats['users'],
				$total_users,
				$pct
			)
		) . '</p>';
		echo '<p>' . esc_html(
			sprintf(
				/* translators: %d: total number of registered passkeys. */
				__( 'Total registered passkeys: %d', 'rapls-passkey' ),
				$stats['total']
			)
		) . '</p>';
		echo '<p class="description">' . esc_html__( 'Per-user status is shown in the Passkey column of the Users list.', 'rapls-passkey' ) . '</p>';
	}

	/**
	 * Detected security plugins and coexistence note.
	 */
	private function render_compat(): void {
		$detected = Compat::detect();
		echo '<h2>' . esc_html__( 'Compatibility with security plugins', 'rapls-passkey' ) . '</h2>';
		if ( array() === $detected ) {
			echo '<p>' . esc_html__( 'No known login-security plugins were detected.', 'rapls-passkey' ) . '</p>';
			return;
		}
		echo '<p>' . esc_html__( 'The following plugins were detected:', 'rapls-passkey' ) . ' <strong>' . esc_html( implode( ', ', $detected ) ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Rapls Passkey uses only the standard login hooks and fires wp_login on a successful sign-in, so it coexists with these. If the login screen shows a duplicate CAPTCHA, disable one of them (you can disable this plugin reCAPTCHA in the settings above).', 'rapls-passkey' ) . '</p>';
	}

	/**
	 * Recent audit events.
	 */
	private function render_audit(): void {
		echo '<h2>' . esc_html__( 'Recent events', 'rapls-passkey' ) . '</h2>';
		$events = AuditLog::recent( 50 );
		if ( array() === $events ) {
			echo '<p>' . esc_html__( 'No events have been recorded.', 'rapls-passkey' ) . '</p>';
			return;
		}

		$export_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=' . AuditExport::ACTION ),
			AuditExport::ACTION
		);
		echo '<p><a class="button" href="' . esc_url( $export_url ) . '">' . esc_html__( 'Export CSV', 'rapls-passkey' ) . '</a></p>';
		echo '<table class="widefat striped"><thead><tr>';
		echo '<th>' . esc_html__( 'Date/time (UTC)', 'rapls-passkey' ) . '</th>';
		echo '<th>' . esc_html__( 'Event', 'rapls-passkey' ) . '</th>';
		echo '<th>' . esc_html__( 'Users', 'rapls-passkey' ) . '</th>';
		echo '<th>' . esc_html__( 'Details', 'rapls-passkey' ) . '</th>';
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
