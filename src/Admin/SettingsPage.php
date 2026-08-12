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

defined( 'ABSPATH' ) || exit;

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
		add_filter( 'plugin_action_links_' . RAPLS_PASSKEY_BASENAME, array( $this, 'action_links' ) );
	}

	/**
	 * Row links on the Plugins screen.
	 *
	 * Settings first, because that is what someone clicking here almost always
	 * wants. The Pro link is the only advertising outside this plugin's own
	 * screens, and it is one word on the plugin's own row — the place a reader
	 * is already looking at this plugin, and the placement every other add-on
	 * uses. It disappears once Pro is active.
	 *
	 * @param string[] $links Existing links.
	 * @return string[]
	 */
	public function action_links( $links ): array {
		$links = is_array( $links ) ? $links : array();

		$settings = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=rapls-passkey' ) ),
			esc_html__( 'Settings', 'rapls-passkey' )
		);
		array_unshift( $links, $settings );

		/** Filter: whether Pro is active (Pro returns true). */
		if ( (bool) apply_filters( 'rapls_passkey/is_pro', false ) ) {
			return $links;
		}
		/** Filter: whether to show the upgrade panel at all. */
		if ( ! (bool) apply_filters( 'rapls_passkey/show_upsell', true ) ) {
			return $links;
		}

		/** Filter: the "learn more" URL for Rapls Passkey Pro. */
		$url = (string) apply_filters( 'rapls_passkey/pro_url', 'https://raplsworks.com/rapls-passkey-pro/' );

		$links[] = sprintf(
			'<a href="%s" target="_blank" rel="noopener noreferrer" style="color:#2271b1;font-weight:600">%s</a>',
			esc_url( $url ),
			esc_html__( 'Go Pro', 'rapls-passkey' )
		);

		return $links;
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
			'recaptcha_fail_open'  => ! empty( $input['recaptcha_fail_open'] ),
			'recaptcha_site_key'   => isset( $input['recaptcha_site_key'] ) ? sanitize_text_field( $input['recaptcha_site_key'] ) : '',
			'recaptcha_secret_key' => $this->store_secret( isset( $input['recaptcha_secret_key'] ) ? (string) $input['recaptcha_secret_key'] : '' ),
			'recaptcha_threshold'  => $threshold,
			'audit_enabled'        => ! empty( $input['audit_enabled'] ),
			'rest_relax_login'     => ! empty( $input['rest_relax_login'] ),
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

			<?php // phpcs:disable WordPress.Security.NonceVerification.Recommended ?>
			<?php if ( isset( $_GET['rapls_pk_reset'] ) && 'ok' === sanitize_key( wp_unslash( $_GET['rapls_pk_reset'] ) ) ) : ?>
			<?php // phpcs:enable WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Settings were reset to their defaults.', 'rapls-passkey' ); ?></p></div>
			<?php endif; ?>

			<?php
			// Two columns, WordPress's own. The settings are long — the audit table
			// alone can fill a screen — and anything after them is never reached.
			// A sidebar keeps the one panel that is not a setting in view without
			// pushing it into anybody's way.
			?>
			<div id="poststuff">
			<div id="post-body" class="metabox-holder columns-2">
			<div id="post-body-content">

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
					<tr>
						<th scope="row"><?php esc_html_e( 'If Google is unreachable', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[recaptcha_fail_open]" value="1" <?php checked( ! empty( $s['recaptcha_fail_open'] ) ); ?>>
								<?php esc_html_e( 'Allow the password login when reCAPTCHA cannot be verified (fail open)', 'rapls-passkey' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'On by default (availability): a Google outage will not lock everyone out. Turn it off to fail closed (reject password logins that cannot be scored) — a passkey login never uses reCAPTCHA, so it stays available either way.', 'rapls-passkey' ); ?></p>
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

					<h2><?php esc_html_e( 'REST API', 'rapls-passkey' ); ?></h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Passkey login when REST is restricted', 'rapls-passkey' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( Settings::OPTION ); ?>[rest_relax_login]" value="1" <?php checked( ! empty( $s['rest_relax_login'] ) ); ?>>
								<?php esc_html_e( 'Allow the anonymous passkey-login endpoints when a security plugin restricts the REST API to logged-in users', 'rapls-passkey' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Off by default. Only turn this on if a security plugin locks the REST API to logged-in users and passkey sign-in has stopped working. When on, the plugin re-opens only its own anonymous login routes and only for a "must be logged in" (HTTP 401) restriction; a firewall, IP-block or maintenance page (HTTP 403) is never overridden.', 'rapls-passkey' ); ?></p>
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

			</div><?php // #post-body-content ?>

			<div id="postbox-container-1" class="postbox-container">
				<?php $this->render_upsell(); ?>
			</div>

			</div><?php // #post-body ?>
			<br class="clear">
			</div><?php // #poststuff ?>
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

		// Paired lead-in and detail. A reader scanning only the bold half should
		// still come away knowing what Pro is for; the plain half is there for
		// the one who stops.
		$features = array(
			array(
				__( 'Sign in from another device', 'rapls-passkey' ),
				__( 'Approve a login on your computer from your phone — a QR code plus a four-digit confirmation code, so a relayed code cannot be used elsewhere.', 'rapls-passkey' ),
			),
			array(
				__( 'A way back in that is not a password', 'rapls-passkey' ),
				__( 'One-time recovery codes and email magic-link sign-in, for the day a phone is lost or replaced.', 'rapls-passkey' ),
			),
			array(
				__( 'Roll out by role, at your pace', 'rapls-passkey' ),
				__( 'Require passkeys for the roles you choose, with a grace period, and turn password login off once everyone is across.', 'rapls-passkey' ),
			),
			array(
				__( 'Ask again when it looks wrong', 'rapls-passkey' ),
				__( 'Adaptive step-up requests a passkey after a password sign-in from somewhere unfamiliar.', 'rapls-passkey' ),
			),
			array(
				__( 'Decide which authenticators you trust', 'rapls-passkey' ),
				__( 'FIDO Metadata Service checks, AAGUID allow and deny lists, and trusted-device management.', 'rapls-passkey' ),
			),
			array(
				__( 'Run it across a fleet', 'rapls-passkey' ),
				__( 'Security webhooks, adoption reports, multisite network settings and WP-CLI commands.', 'rapls-passkey' ),
			),
		);

		// Scoped to this panel and printed only when the panel is: a site running
		// Pro never sees the panel, and never pays for the stylesheet either.
		?>
		<style>
		/* Follows the page down: the settings are long enough that a panel fixed
		   at the top would be off screen for most of the scroll. 46px clears the
		   admin bar. */
		.rapls-pk-pro{position:sticky;top:46px;margin:0;border:1px solid #dcdcde;border-left:4px solid #2271b1;border-radius:4px;background:#fff;padding:18px 20px}
		.rapls-pk-pro__kicker{margin:0;font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#646970}
		.rapls-pk-pro__title{margin:6px 0 0;font-size:16px;line-height:1.45}
		.rapls-pk-pro__lead{margin:8px 0 0;color:#50575e;font-size:13px;line-height:1.6}
		.rapls-pk-pro__grid{display:grid;grid-template-columns:1fr;gap:0;margin:14px 0 0}
		.rapls-pk-pro__item{padding:8px 0;border-top:1px solid #f0f0f1}
		.rapls-pk-pro__item b{display:block;color:#1d2327;font-size:13px}
		.rapls-pk-pro__item span{color:#646970;font-size:12px;line-height:1.55}
		.rapls-pk-pro__foot{margin:16px 0 0}
		.rapls-pk-pro__note{margin:8px 0 0;color:#646970;font-size:12px}
		.rapls-pk-pro__foot .button{width:100%;text-align:center}
		/* One column below the breakpoint where WordPress drops the sidebar under
		   the content — a sticky panel there would follow the reader pointlessly. */
		@media (max-width:850px){.rapls-pk-pro{position:static}}
		</style>
		<div class="rapls-pk-pro">
			<p class="rapls-pk-pro__kicker"><?php esc_html_e( 'Rapls Passkey Pro — optional add-on', 'rapls-passkey' ); ?></p>
			<h3 class="rapls-pk-pro__title"><?php esc_html_e( 'Get everyone onto passkeys — without locking anyone out', 'rapls-passkey' ); ?></h3>
			<p class="rapls-pk-pro__lead">
				<?php esc_html_e( 'Everything on this page is free, and stays free. Pro is for what comes after the first passkey: moving a whole site across, and keeping a way in when a device goes missing.', 'rapls-passkey' ); ?>
			</p>
			<div class="rapls-pk-pro__grid">
				<?php foreach ( $features as $feature ) : ?>
					<div class="rapls-pk-pro__item">
						<b><?php echo esc_html( $feature[0] ); ?></b>
						<span><?php echo esc_html( $feature[1] ); ?></span>
					</div>
				<?php endforeach; ?>
			</div>
			<p class="rapls-pk-pro__foot">
				<a class="button button-primary" href="<?php echo esc_url( $url ); ?>" target="_blank" rel="noopener noreferrer">
					<?php esc_html_e( 'See what Pro adds', 'rapls-passkey' ); ?>
				</a>
				<span class="rapls-pk-pro__note"><?php esc_html_e( 'One-time purchase, no subscription. 14-day refund.', 'rapls-passkey' ); ?></span>
			</p>
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

		$this->render_adoption_hint( $stats['users'], $total_users );
	}

	/**
	 * A line about closing the gap, next to the number that shows it.
	 *
	 * Only when there is a gap to close, and only once some people are across —
	 * a site where nobody has enrolled has a different problem, and a site where
	 * everybody has is not being sold anything. Nothing here is disabled or
	 * withheld: the free plugin's adoption figure is the whole figure, and this
	 * is a sentence about what else exists.
	 *
	 * @param int $with  Users holding a passkey.
	 * @param int $total Users on the site.
	 * @return void
	 */
	private function render_adoption_hint( int $with, int $total ): void {
		/** Filter: whether Pro is active (Pro returns true). */
		if ( (bool) apply_filters( 'rapls_passkey/is_pro', false ) ) {
			return;
		}
		/** Filter: whether to show the upgrade panel at all. */
		if ( ! (bool) apply_filters( 'rapls_passkey/show_upsell', true ) ) {
			return;
		}
		if ( $with < 1 || $total <= $with ) {
			return;
		}

		/** Filter: the "learn more" URL for Rapls Passkey Pro. */
		$url = (string) apply_filters( 'rapls_passkey/pro_url', 'https://raplsworks.com/rapls-passkey-pro/' );

		printf(
			'<p class="description">%s <a href="%s" target="_blank" rel="noopener noreferrer">%s</a></p>',
			esc_html(
				sprintf(
					/* translators: %d: number of users without a passkey. */
					_n(
						'%d user has not enrolled yet.',
						'%d users have not enrolled yet.',
						$total - $with,
						'rapls-passkey'
					),
					$total - $with
				)
			),
			esc_url( $url ),
			esc_html__( 'Pro can require a passkey by role, with a grace period.', 'rapls-passkey' )
		);
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
