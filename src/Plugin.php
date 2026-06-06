<?php
/**
 * Main plugin container.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey;

use RaplsPasskey\Credentials\Schema;

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

		// The WebAuthn core lives in web-auth/webauthn-lib; degrade loudly without it.
		if ( ! $this->webauthn_library_available() ) {
			add_action( 'admin_notices', array( $this, 'render_missing_library_notice' ) );
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
