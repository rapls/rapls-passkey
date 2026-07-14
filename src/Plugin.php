<?php
/**
 * Main plugin container.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

use RaplsPasskey\Admin\AuditExport;
use RaplsPasskey\Admin\DashboardWidget;
use RaplsPasskey\Admin\ProfileUi;
use RaplsPasskey\Admin\SettingsPage;
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

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

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

		add_action( 'init', array( $this, 'load_textdomain' ) );

		// Keep the schema current after plugin updates (no manual reactivation).
		add_action( 'admin_init', array( Schema::class, 'maybe_upgrade' ) );

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

		// The WebAuthn core lives in web-auth/webauthn-lib; degrade loudly without it.
		if ( ! $this->webauthn_library_available() ) {
			add_action( 'admin_notices', array( $this, 'render_missing_library_notice' ) );
			return;
		}

		$this->wire_passkey_subsystems();
	}

	/**
	 * Construct and register the registration/authentication subsystems.
	 *
	 * Runs only when the WebAuthn library is present (guarded by boot()).
	 */
	private function wire_passkey_subsystems(): void {
		$rp         = RelyingParty::from_site();
		$codec      = new Codec();
		$challenges = new ChallengeStore();
		$ceremonies = new Ceremonies( $rp );
		$repository = new CredentialRepository();

		$registration = new RegistrationManager( $rp, $codec, $challenges, $ceremonies );
		$assertion    = new AssertionManager( $rp, $codec, $challenges, $ceremonies );

		( new Endpoints( $registration, $assertion, $repository, $codec ) )->register();
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
			( new DashboardWidget( $repository ) )->register();
		}
	}

	/**
	 * Load translations.
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain( 'rapls-passkey', false, dirname( RAPLS_PASSKEY_BASENAME ) . '/languages' );
	}

	/**
	 * Is the WebAuthn library loaded (via Composer)?
	 *
	 * @return bool
	 */
	public function webauthn_library_available(): bool {
		return class_exists( '\Webauthn\PublicKeyCredentialSource' );
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
