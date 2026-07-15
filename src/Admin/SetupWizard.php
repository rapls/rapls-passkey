<?php
/**
 * First-run setup wizard.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Support\Compat;
use RaplsPasskey\WebAuthn\RelyingParty;
use RaplsPasskey\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Activating a passkey plugin and being dropped on a settings screen leaves the two
 * questions that actually decide whether passkeys will work unanswered: is this site
 * served over HTTPS (WebAuthn refuses to run otherwise), and what is the relying-party
 * id the credentials will be bound to? Get the second one wrong later and every
 * registered passkey stops matching.
 *
 * So the wizard checks the environment, shows the RP ID the site will use, and then
 * walks the administrator through registering their own passkey — because an
 * administrator who has not tried it has no idea whether it works for anyone else.
 *
 * It shows once. Dismissing it, or finishing it, is remembered.
 */
final class SetupWizard {

	/** Option: the wizard has been completed or dismissed. */
	private const DONE_OPTION = 'rapls_passkey_setup_done';

	/** Menu slug (hidden page). */
	private const SLUG = 'rapls-passkey-setup';

	/** admin-post action for dismissing. */
	private const DISMISS = 'rapls_passkey_setup_dismiss';

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the page, the notice and the dismissal.
	 */
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_page' ) );
		// Registered under Settings so the page resolves normally, then taken back out
		// of the menu: it is a one-off, reached from the notice, not a permanent item.
		add_action( 'admin_menu', array( $this, 'hide_page' ), 999 );
		add_action( 'admin_notices', array( $this, 'render_notice' ) );
		add_action( 'admin_post_' . self::DISMISS, array( $this, 'handle_dismiss' ) );
	}

	/**
	 * Has the administrator been through this already?
	 */
	public static function done(): bool {
		return (bool) get_option( self::DONE_OPTION, false );
	}

	/**
	 * Register the page without a menu entry — it is reached from the notice and
	 * from a link on the settings screen, not from a permanent menu item.
	 */
	public function add_page(): void {
		add_submenu_page(
			'options-general.php',
			__( 'Rapls Passkey setup', 'rapls-passkey' ),
			__( 'Rapls Passkey setup', 'rapls-passkey' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * Take the entry back out of the Settings menu (the page stays reachable).
	 */
	public function hide_page(): void {
		remove_submenu_page( 'options-general.php', self::SLUG );
	}

	/**
	 * URL of the wizard.
	 */
	public static function url(): string {
		return admin_url( 'options-general.php?page=' . self::SLUG );
	}

	/**
	 * Nudge a fresh install towards the wizard, once.
	 */
	public function render_notice(): void {
		if ( ! current_user_can( 'manage_options' ) || self::done() ) {
			return;
		}
		// A site that already has passkeys registered has plainly been through setup
		// — it was just running before the wizard existed. Don't nag it on upgrade;
		// remember that instead.
		if ( $this->already_working() ) {
			update_option( self::DONE_OPTION, true, false );
			return;
		}
		// Not on the wizard itself.
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && false !== strpos( (string) $screen->id, self::SLUG ) ) {
			return;
		}
		?>
		<div class="notice notice-info">
			<p>
				<strong><?php esc_html_e( 'Rapls Passkey is active.', 'rapls-passkey' ); ?></strong>
				<?php esc_html_e( 'Run the three-minute setup check to confirm passkeys will work on this site, and register your own.', 'rapls-passkey' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( self::url() ); ?>" class="button button-primary"><?php esc_html_e( 'Start setup', 'rapls-passkey' ); ?></a>
				<a href="<?php echo esc_url( $this->dismiss_url() ); ?>" class="button"><?php esc_html_e( 'Dismiss', 'rapls-passkey' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Mark the wizard finished. Always redirects.
	 */
	public function handle_dismiss(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'rapls-passkey' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( self::DISMISS );

		update_option( self::DONE_OPTION, true, false );

		wp_safe_redirect( admin_url( 'options-general.php?page=rapls-passkey' ) );
		exit;
	}

	/**
	 * Render the wizard.
	 */
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$user_id  = get_current_user_id();
		$has_key  = array() !== $this->repository->find_active_by_user( $user_id );
		$secure   = is_ssl() || $this->is_local_host();
		$library  = Plugin::instance()->webauthn_library_available();
		$rp_id    = RelyingParty::from_site()->id();
		$detected = Compat::detect();
		$ready    = $secure && $library;
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Rapls Passkey setup', 'rapls-passkey' ); ?></h1>

			<h2><?php esc_html_e( 'Step 1: can this site use passkeys?', 'rapls-passkey' ); ?></h2>
			<table class="widefat striped" style="max-width:820px">
				<tbody>
					<tr>
						<td style="width:200px"><strong><?php esc_html_e( 'Secure connection', 'rapls-passkey' ); ?></strong></td>
						<td>
							<?php if ( $secure ) : ?>
								<?php esc_html_e( 'OK. WebAuthn requires HTTPS (localhost is exempt).', 'rapls-passkey' ); ?>
							<?php else : ?>
								<strong style="color:#b32d2e"><?php esc_html_e( 'Not available.', 'rapls-passkey' ); ?></strong>
								<?php esc_html_e( 'Browsers refuse WebAuthn without HTTPS, so no passkey can be registered or used until this site is served over HTTPS.', 'rapls-passkey' ); ?>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'WebAuthn library', 'rapls-passkey' ); ?></strong></td>
						<td>
							<?php if ( $library ) : ?>
								<?php esc_html_e( 'Loaded.', 'rapls-passkey' ); ?>
							<?php else : ?>
								<strong style="color:#b32d2e"><?php esc_html_e( 'Missing.', 'rapls-passkey' ); ?></strong>
								<?php esc_html_e( 'Run composer install in the plugin directory.', 'rapls-passkey' ); ?>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Relying-party ID', 'rapls-passkey' ); ?></strong></td>
						<td>
							<code><?php echo esc_html( $rp_id ); ?></code>
							<p class="description" style="margin-top:4px">
								<?php esc_html_e( 'Passkeys are bound to this domain. If you later move the site to another domain, or change this with the rapls_passkey_rp_id filter, every passkey already registered stops matching and users have to register again. Decide it now, before anyone enrols.', 'rapls-passkey' ); ?>
							</p>
						</td>
					</tr>
					<?php if ( ! empty( $detected ) ) : ?>
						<tr>
							<td><strong><?php esc_html_e( 'Security plugins', 'rapls-passkey' ); ?></strong></td>
							<td>
								<?php echo esc_html( implode( ', ', $detected ) ); ?>
								<p class="description" style="margin-top:4px">
									<?php esc_html_e( 'Detected and coexisted with: this plugin adds no CSP header, uses only standard login hooks, and keeps its REST routes reachable where a plugin locks the REST API down to logged-in users.', 'rapls-passkey' ); ?>
								</p>
							</td>
						</tr>
					<?php endif; ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Step 2: register your own passkey', 'rapls-passkey' ); ?></h2>
			<?php if ( ! $ready ) : ?>
				<p><?php esc_html_e( 'Fix the items above first — passkeys cannot be registered until they pass.', 'rapls-passkey' ); ?></p>
			<?php elseif ( $has_key ) : ?>
				<p>
					<?php esc_html_e( 'You already have a passkey. Sign out and back in with it once, so you know the login flow works before you ask anyone else to use it.', 'rapls-passkey' ); ?>
				</p>
			<?php else : ?>
				<p>
					<?php esc_html_e( 'Register one now. An administrator who has not tried it cannot tell whether it works for everyone else.', 'rapls-passkey' ); ?>
				</p>
				<p>
					<a href="<?php echo esc_url( admin_url( 'profile.php#rapls-passkey' ) ); ?>" class="button button-primary">
						<?php esc_html_e( 'Go to your profile and register', 'rapls-passkey' ); ?>
					</a>
				</p>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Step 3: decide the rollout', 'rapls-passkey' ); ?></h2>
			<p style="max-width:820px">
				<?php esc_html_e( 'Passkeys sit alongside passwords by default: nothing is taken away, and users adopt them at their own pace. When you are ready to go further, the settings screen carries the login rate limit, the post-login prompt that offers users a passkey, and reCAPTCHA for the password form. Making passkeys mandatory for a role, disabling password login, cross-device QR sign-in and recovery codes come with Rapls Passkey Pro.', 'rapls-passkey' ); ?>
			</p>

			<p style="margin-top:24px">
				<a href="<?php echo esc_url( admin_url( 'options-general.php?page=rapls-passkey' ) ); ?>" class="button button-primary"><?php esc_html_e( 'Go to settings', 'rapls-passkey' ); ?></a>
				<a href="<?php echo esc_url( $this->dismiss_url() ); ?>" class="button"><?php esc_html_e( 'Finish setup', 'rapls-passkey' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Does this site already have at least one registered passkey?
	 */
	private function already_working(): bool {
		try {
			$stats = $this->repository->stats();
			return (int) ( $stats['total'] ?? 0 ) > 0;
		} catch ( \Throwable $e ) {
			// A missing table (fresh install mid-upgrade) just means "not yet".
			return false;
		}
	}

	/**
	 * Nonce-protected dismissal URL.
	 */
	private function dismiss_url(): string {
		return wp_nonce_url( admin_url( 'admin-post.php?action=' . self::DISMISS ), self::DISMISS );
	}

	/**
	 * Is this a local development host, where browsers allow WebAuthn without HTTPS?
	 */
	private function is_local_host(): bool {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return in_array( (string) $host, array( 'localhost', '127.0.0.1', '::1' ), true );
	}
}
