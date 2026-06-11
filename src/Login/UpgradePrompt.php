<?php
/**
 * Post-login "create a passkey" upgrade prompt.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Login;

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Support\Settings;
use WP_User;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Right after an interactive (password) login, if the user has no passkey yet,
 * intercept the login redirect and show a one-screen prompt offering to create
 * one — the single biggest driver of passkey adoption. The user is already
 * authenticated on this screen, so the normal logged-in registration ceremony
 * runs; "後で" simply continues to the original destination.
 *
 * It hooks `login_redirect`, which fires for the wp-login.php form flow but not
 * for the plugin's own passkey / magic-link / recovery logins (those redirect
 * directly), so only password logins are upgraded. The prompt is shown at most
 * once per interval per user.
 */
final class UpgradePrompt {

	/** Custom wp-login.php action. */
	private const ACTION = 'rapls_pk_upgrade';

	/** User meta: last time the prompt was shown/dismissed (unix time). */
	private const META_DISMISSED = 'rapls_pk_upgrade_seen';

	/** Days before the prompt may show again. */
	private const INTERVAL_DAYS = 30;

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the login redirect and the interstitial screen.
	 */
	public function register(): void {
		add_filter( 'login_redirect', array( $this, 'maybe_intercept' ), 10, 3 );
		add_action( 'login_form_' . self::ACTION, array( $this, 'render_screen' ) );
	}

	/**
	 * Redirect an eligible password login to the upgrade screen.
	 *
	 * @param string $redirect_to Where the login would send the user.
	 * @param string $requested   Originally requested redirect (unused).
	 * @param mixed  $user        The user, or a WP_Error.
	 * @return string
	 */
	public function maybe_intercept( $redirect_to, $requested, $user ): string {
		unset( $requested );
		$redirect_to = (string) $redirect_to;

		if ( ! $user instanceof WP_User ) {
			return $redirect_to;
		}
		if ( isset( $_REQUEST['interim-login'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return $redirect_to;
		}
		if ( ! Settings::upgrade_prompt_enabled() ) {
			return $redirect_to;
		}
		if ( $this->has_passkey( (int) $user->ID ) ) {
			return $redirect_to;
		}
		if ( $this->recently_seen( (int) $user->ID ) ) {
			return $redirect_to;
		}

		$dest = '' !== $redirect_to ? $redirect_to : admin_url();

		return add_query_arg(
			array(
				'action'      => self::ACTION,
				'redirect_to' => rawurlencode( $dest ),
			),
			wp_login_url()
		);
	}

	/**
	 * Render the upgrade screen (the user is already logged in here). Always exits.
	 */
	public function render_screen(): void {
		$user = wp_get_current_user();
		if ( 0 === (int) $user->ID ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$dest = isset( $_GET['redirect_to'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			? wp_validate_redirect( wp_unslash( $_GET['redirect_to'] ), admin_url() ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			: admin_url();
		if ( '' === $dest ) {
			$dest = admin_url();
		}

		// Show at most once per interval, regardless of the choice made.
		update_user_meta( $user->ID, self::META_DISMISSED, time() );

		$config = array(
			'restUrl'  => esc_url_raw( rest_url( 'rapls-passkey/v1/' ) ),
			'nonce'    => wp_create_nonce( 'wp_rest' ),
			'redirect' => $dest,
			/**
			 * Whether to attempt a silent automatic passkey upgrade (Conditional
			 * Create) before showing the explicit button.
			 *
			 * @param bool $enabled Whether automatic upgrade is attempted.
			 */
			'conditionalCreate' => (bool) apply_filters( 'rapls_passkey_conditional_create', true ),
			'i18n'     => array(
				'registering' => __( 'パスキーを登録しています…', 'rapls-passkey' ),
				'success'     => __( 'パスキーを登録しました。', 'rapls-passkey' ),
				'failed'      => __( 'パスキーの登録に失敗しました。', 'rapls-passkey' ),
				'unsupported' => __( 'このブラウザはパスキーに対応していません。', 'rapls-passkey' ),
				'cancelled'   => __( 'キャンセルされました。', 'rapls-passkey' ),
				'duplicate'   => __( 'この認証器にはすでにパスキーが登録されています。', 'rapls-passkey' ),
			),
		);

		login_header( __( 'パスキーの設定', 'rapls-passkey' ), '' );
		?>
		<div class="rapls-pk-upgrade">
			<h2 style="margin-top:0"><?php esc_html_e( '次回から、もっと速く安全にログイン', 'rapls-passkey' ); ?></h2>
			<p><?php esc_html_e( 'この端末にパスキーを設定すると、次回からパスワードなしで、指紋・顔認証・PIN ですばやくログインできます。フィッシングにも強くなります。', 'rapls-passkey' ); ?></p>
			<p>
				<button type="button" id="rapls-pk-upgrade-create" class="button button-primary button-large" style="width:100%">
					<?php esc_html_e( 'パスキーを作成', 'rapls-passkey' ); ?>
				</button>
			</p>
			<p id="rapls-pk-upgrade-status" role="status" aria-live="polite" style="min-height:1.5em"></p>
			<p style="text-align:center">
				<a id="rapls-pk-upgrade-skip" href="<?php echo esc_url( $dest ); ?>"><?php esc_html_e( '後で', 'rapls-passkey' ); ?></a>
			</p>
		</div>
		<script type="application/json" id="rapls-pk-upgrade-config"><?php echo wp_json_encode( $config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE ); ?></script>
		<script src="<?php echo esc_url( RAPLS_PASSKEY_URL . 'assets/webauthn.js?ver=' . RAPLS_PASSKEY_VERSION ); ?>"></script>
		<script src="<?php echo esc_url( RAPLS_PASSKEY_URL . 'assets/upgrade.js?ver=' . RAPLS_PASSKEY_VERSION ); ?>"></script>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Does the user already have at least one passkey?
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	private function has_passkey( int $user_id ): bool {
		return array() !== $this->repository->find_by_user( $user_id );
	}

	/**
	 * Was the prompt shown within the interval?
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	private function recently_seen( int $user_id ): bool {
		$seen = (int) get_user_meta( $user_id, self::META_DISMISSED, true );
		return $seen > 0 && ( time() - $seen ) < ( self::INTERVAL_DAYS * DAY_IN_SECONDS );
	}
}
