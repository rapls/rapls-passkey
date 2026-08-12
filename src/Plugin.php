<?php
/**
 * Main plugin container.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

use RaplsPasskey\Admin\AuditExport;
use RaplsPasskey\Admin\CredentialsPage;
use RaplsPasskey\Admin\ReviewPrompt;
use RaplsPasskey\Admin\DashboardWidget;
use RaplsPasskey\Admin\ProfileUi;
use RaplsPasskey\Admin\SettingsPage;
use RaplsPasskey\Admin\SetupWizard;
use RaplsPasskey\Admin\SiteHealth;
use RaplsPasskey\Admin\UsersColumn;
use RaplsPasskey\Cli\Commands;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Frontend\Blocks;
use RaplsPasskey\Frontend\Shortcodes;
use RaplsPasskey\Integrations\LoginForms;
use RaplsPasskey\Integrations\TwoFactor;
use RaplsPasskey\Integrations\WooCommerce;
use RaplsPasskey\Integrations\WooCommerceAccount;
use RaplsPasskey\Login\LoginForm;
use RaplsPasskey\Login\Recaptcha;
use RaplsPasskey\Login\SecondFactorScreen;
use RaplsPasskey\Login\UpgradePrompt;
use RaplsPasskey\Privacy\PersonalData;
use RaplsPasskey\Recovery\Bypass;
use RaplsPasskey\Rest\Endpoints;
use RaplsPasskey\Security\Notifications;
use RaplsPasskey\Security\RestAccess;
use RaplsPasskey\WebAuthn\AssertionManager;
use RaplsPasskey\WebAuthn\Ceremonies;
use RaplsPasskey\WebAuthn\ChallengeStore;
use RaplsPasskey\WebAuthn\Codec;
use RaplsPasskey\WebAuthn\RegistrationManager;
use RaplsPasskey\WebAuthn\RelyingParty;

defined( 'ABSPATH' ) || exit;

/**
 * Singleton that wires the plugin's subsystems on `plugins_loaded`.
 *
 * Phase 0 boots a minimal skeleton: translations, the schema upgrade check, and
 * a dependency notice when web-auth/webauthn-lib is missing. The WebAuthn,
 * REST, login and admin subsystems are wired here in later phases.
 */
final class Plugin {

	/**
	 * Sole instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Whether boot() has already run.
	 *
	 * @var bool
	 */
	private $booted = false;

	/**
	 * Get the shared instance.
	 *
	 * @return Plugin
	 */
	public static function instance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private to enforce the singleton.
	 */
	private function __construct() {}

	/**
	 * Wire hooks and subsystems. Idempotent.
	 */
	public function boot(): void {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		// No load_plugin_textdomain(): translations for a WordPress.org-hosted
		// plugin come from translate.wordpress.org and load just in time.

		// Keep the schema current after plugin updates (no manual reactivation).
		add_action( 'admin_init', array( Schema::class, 'maybe_upgrade' ) );
		// A site can be updated without anyone opening wp-admin — a background
		// update, or WP-CLI — and the very next thing to happen may be a passkey
		// login, which needs the current columns. Every request to OUR OWN REST
		// namespace therefore checks too, before the route runs. The check is a
		// single option read and only for our routes, so ordinary REST traffic is
		// untouched.
		add_filter( 'rest_pre_dispatch', array( $this, 'upgrade_before_ceremony' ), 5, 3 );

		// These work independently of the WebAuthn library (recovery tooling,
		// admin settings, and password-form reCAPTCHA), so wire them before the
		// dependency guard below.
		( new Bypass() )->register();
		( new Commands( new CredentialRepository() ) )->register();
		( new SettingsPage() )->register();
		( new Recaptcha() )->register();
		// Privacy (GDPR) export/erase must work even without the WebAuthn library.
		( new PersonalData( new CredentialRepository() ) )->register();
		( new AuditExport() )->register();
		( new SiteHealth() )->register();

		// First-run wizard. Wired before the library guard on purpose: a site whose
		// dependency is missing is exactly the one that needs to be told.
		if ( is_admin() ) {
			( new SetupWizard( new CredentialRepository() ) )->register();
		}

		// The WebAuthn core lives in web-auth/webauthn-lib; degrade loudly without it.
		if ( ! $this->webauthn_library_available() ) {
			add_action( 'admin_notices', array( $this, 'render_missing_library_notice' ) );
			return;
		}

		$this->wire_passkey_subsystems();
	}

	/**
	 * Build the relying party and the ceremony endpoints, once every plugin has
	 * registered its filters. Public because it runs as an `init` callback.
	 */
	public function wire_ceremonies(): void {
		$rp         = RelyingParty::from_site();
		$codec      = new Codec();
		$challenges = new ChallengeStore();
		$ceremonies = new Ceremonies( $rp );

		$registration = new RegistrationManager( $rp, $codec, $challenges, $ceremonies );
		$assertion    = new AssertionManager( $rp, $codec, $challenges, $ceremonies );

		( new Endpoints( $registration, $assertion, new CredentialRepository(), $codec ) )->register();
	}

	/**
	 * Construct and register the registration/authentication subsystems.
	 *
	 * Runs only when the WebAuthn library is present (guarded by boot()).
	 */
	private function wire_passkey_subsystems(): void {
		$repository = new CredentialRepository();

		// The relying party is resolved on `init`, not here. Its ID and the allowed
		// origins come from filters (`rapls_passkey_rp_id`, the related-origins
		// list) that other plugins — Pro's shared RP ID and Related Origin Requests
		// among them — register during `plugins_loaded`, some of them after this
		// one. Building it here would freeze the site host before those filters
		// existed, so a network-wide shared RP ID silently never applied. By `init`
		// every plugin has had its say, and the REST routes registered below are
		// hooked long before `rest_api_init` fires.
		add_action( 'init', array( $this, 'wire_ceremonies' ), 0 );

		( new RestAccess( 'rapls-passkey/v1' ) )->register();
		( new LoginForm() )->register();

		// Offer to create a passkey right after an interactive (password) login.
		( new UpgradePrompt( $repository ) )->register();

		// Front-end embedding: shortcodes and the matching Gutenberg blocks.
		$shortcodes = new Shortcodes( $repository );
		$shortcodes->register();
		( new Blocks( $shortcodes ) )->register();

		// WooCommerce "My account" / checkout login (inert without WooCommerce).
		( new WooCommerce( $shortcodes ) )->register();

		// WooCommerce "My account" passkey management tab (inert without WooCommerce).
		( new WooCommerceAccount( $shortcodes ) )->register();

		// Other membership / e-commerce login forms (inert without those plugins).
		( new LoginForms( $shortcodes ) )->register();

		// 2FA coexistence: a passkey login satisfies MFA (inert without a 2FA plugin).
		( new TwoFactor() )->register();

		// The other side of that coin: the logins that are *not* a passkey (magic
		// link, recovery code) still have to answer the site's 2FA challenge.
		( new SecondFactorScreen() )->register();

		// Security notification emails (registration / removal / new-device sign-in).
		( new Notifications() )->register();

		if ( is_admin() ) {
			( new ProfileUi( $repository ) )->register();
			( new UsersColumn( $repository ) )->register();
			( new CredentialsPage( $repository ) )->register();
			( new DashboardWidget( $repository ) )->register();
			( new ReviewPrompt( $repository ) )->register();
		}
	}

	/**
	 * Bring the schema up to date before one of our own REST routes runs.
	 *
	 * Passes the dispatch result through untouched — this only ensures the table
	 * a ceremony is about to write to has the columns that ceremony needs, on a
	 * site updated without an admin page load.
	 *
	 * @param mixed            $result  Pre-dispatch result (untouched).
	 * @param mixed            $server  REST server (unused).
	 * @param \WP_REST_Request $request The request.
	 * @return mixed The result, unchanged.
	 */
	public function upgrade_before_ceremony( $result, $server = null, $request = null ) {
		if ( ! $request instanceof \WP_REST_Request ) {
			return $result;
		}
		// Both plugins' namespaces: the Pro QR and sign-up ceremonies write to this
		// table too (slot numbers, the touch nonce), so covering only our own routes
		// would leave those failing on a site nobody has opened wp-admin on.
		$route = ltrim( (string) $request->get_route(), '/' );
		if ( 0 !== strpos( $route, 'rapls-passkey/' ) && 0 !== strpos( $route, 'rapls-passkey-pro/' ) ) {
			return $result;
		}
		// Throttled, because this runs before any permission callback: an anonymous
		// caller must not be able to re-run a failing migration on every request.
		Schema::maybe_upgrade_throttled();
		return $result;
	}

	/**
	 * Is the WebAuthn library loaded (via Composer)?
	 *
	 * @return bool
	 */
	public function webauthn_library_available(): bool {
		return class_exists( \Webauthn\PublicKeyCredentialSource::class );
	}

	/**
	 * Admin notice shown when web-auth/webauthn-lib is unavailable.
	 */
	public function render_missing_library_notice(): void {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p>';
		echo esc_html__( 'Rapls Passkey: The WebAuthn library is not loaded. Run `composer install` to install dependencies. Passkey authentication is disabled.', 'rapls-passkey' );
		echo '</p></div>';
	}
}
