<?php
/**
 * Main plugin container.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

use RaplsPasskey\Admin\ProfileUi;
use RaplsPasskey\Admin\SettingsPage;
use RaplsPasskey\Cli\Commands;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Frontend\Blocks;
use RaplsPasskey\Frontend\Shortcodes;
use RaplsPasskey\Integrations\TwoFactor;
use RaplsPasskey\Integrations\WooCommerce;
use RaplsPasskey\Login\LoginForm;
use RaplsPasskey\Login\Recaptcha;
use RaplsPasskey\Recovery\Bypass;
use RaplsPasskey\Rest\Endpoints;
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

		// Front-end embedding: shortcodes and the matching Gutenberg blocks.
		$shortcodes = new Shortcodes( $repository );
		$shortcodes->register();
		( new Blocks( $shortcodes ) )->register();

		// WooCommerce "My account" / checkout login (inert without WooCommerce).
		( new WooCommerce( $shortcodes ) )->register();

		// 2FA coexistence: a passkey login satisfies MFA (inert without a 2FA plugin).
		( new TwoFactor() )->register();

		if ( is_admin() ) {
			( new ProfileUi( $repository ) )->register();
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
		echo esc_html__( 'Rapls Passkey: WebAuthn ライブラリが読み込まれていません。`composer install` を実行して依存関係を導入してください。パスキー認証は無効化されています。', 'rapls-passkey' );
		echo '</p></div>';
	}
}
