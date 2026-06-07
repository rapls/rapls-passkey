<?php
/**
 * Emergency bypass switch.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Recovery;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A last-resort escape hatch: defining `RAPLS_PASSKEY_BYPASS` (truthy) in
 * wp-config.php disables any passkey enforcement so an administrator who has
 * lost their authenticator can still sign in with a password. A persistent
 * admin notice reminds them to remove it once recovered.
 *
 * Enforcement itself arrives in a later phase; everything that gates login on a
 * passkey must consult Bypass::active() first.
 */
final class Bypass {

	/**
	 * Whether the emergency bypass is engaged.
	 *
	 * @return bool
	 */
	public static function active(): bool {
		return defined( 'RAPLS_PASSKEY_BYPASS' ) && RAPLS_PASSKEY_BYPASS;
	}

	/**
	 * Register the reminder notice when the bypass is active.
	 */
	public function register(): void {
		if ( self::active() ) {
			add_action( 'admin_notices', array( $this, 'notice' ) );
		}
	}

	/**
	 * Warn administrators that the bypass is on.
	 */
	public function notice(): void {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		echo esc_html__( 'Rapls Passkey: 緊急バイパス (RAPLS_PASSKEY_BYPASS) が有効です。パスキーの強制は無効化されています。復旧後は wp-config.php から定数を削除してください。', 'rapls-passkey' );
		echo '</p></div>';
	}
}
