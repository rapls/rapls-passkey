<?php
/**
 * Site Health self-checks for common passkey setup problems.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Support\Compat;
use RaplsPasskey\WebAuthn\RelyingParty;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds checks under Tools → Site Health for the things that most often break a
 * passkey setup — no HTTPS, the WebAuthn library missing, the custom tables not
 * created, an unexpected RP ID — so a site owner can spot and fix them before
 * users get locked out, instead of opening a support ticket.
 */
final class SiteHealth {

	/**
	 * Hook the Site Health tests.
	 */
	public function register(): void {
		add_filter( 'site_status_tests', array( $this, 'add_tests' ) );
	}

	/**
	 * Register our direct (synchronous) tests.
	 *
	 * @param array<string,mixed> $tests Existing tests.
	 * @return array<string,mixed>
	 */
	public function add_tests( $tests ): array {
		$tests = is_array( $tests ) ? $tests : array();

		$tests['direct']['rapls_passkey_https']   = array(
			'label' => __( 'Rapls Passkey: HTTPS', 'rapls-passkey' ),
			'test'  => array( $this, 'test_https' ),
		);
		$tests['direct']['rapls_passkey_library'] = array(
			'label' => __( 'Rapls Passkey: WebAuthn ライブラリ', 'rapls-passkey' ),
			'test'  => array( $this, 'test_library' ),
		);
		$tests['direct']['rapls_passkey_tables']  = array(
			'label' => __( 'Rapls Passkey: データベース', 'rapls-passkey' ),
			'test'  => array( $this, 'test_tables' ),
		);
		$tests['direct']['rapls_passkey_rp']      = array(
			'label' => __( 'Rapls Passkey: RP ID', 'rapls-passkey' ),
			'test'  => array( $this, 'test_rp' ),
		);

		return $tests;
	}

	// --- Tests ---------------------------------------------------------------

	/**
	 * HTTPS / secure context.
	 *
	 * @return array<string,mixed>
	 */
	public function test_https(): array {
		$secure = is_ssl() || $this->is_local_host();
		$desc   = $secure
			? __( 'サイトは安全なコンテキスト(HTTPS)で配信されています。', 'rapls-passkey' )
			: __( 'パスキーには HTTPS(安全なコンテキスト)が必要です。SSL 証明書を導入し、サイトを HTTPS で配信してください(localhost を除く)。', 'rapls-passkey' );

		return $this->result( 'rapls_passkey_https', __( 'Rapls Passkey: HTTPS', 'rapls-passkey' ), self::https_status( $secure ), $desc );
	}

	/**
	 * WebAuthn library availability.
	 *
	 * @return array<string,mixed>
	 */
	public function test_library(): array {
		$present = class_exists( '\\Webauthn\\PublicKeyCredentialSource' );
		$desc    = $present
			? __( 'WebAuthn ライブラリが読み込まれています。', 'rapls-passkey' )
			: __( 'WebAuthn ライブラリが見つかりません。`composer install` を実行して依存関係を導入してください。パスキー認証は無効になっています。', 'rapls-passkey' );

		return $this->result( 'rapls_passkey_library', __( 'Rapls Passkey: WebAuthn ライブラリ', 'rapls-passkey' ), self::library_status( $present ), $desc );
	}

	/**
	 * Custom tables present.
	 *
	 * @return array<string,mixed>
	 */
	public function test_tables(): array {
		$present = $this->tables_exist();
		$desc    = $present
			? __( '認証情報・監査ログのテーブルが存在します。', 'rapls-passkey' )
			: __( 'プラグインのデータベーステーブルが見つかりません。プラグインを一度無効化してから再度有効化すると作成されます。', 'rapls-passkey' );

		return $this->result( 'rapls_passkey_tables', __( 'Rapls Passkey: データベース', 'rapls-passkey' ), self::tables_status( $present ), $desc );
	}

	/**
	 * Relying Party ID information (always informational).
	 *
	 * @return array<string,mixed>
	 */
	public function test_rp(): array {
		$rp_id     = RelyingParty::from_site()->id();
		$host      = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$detected  = Compat::detect();
		$compat    = array() === $detected
			? __( '既知のログイン系セキュリティプラグインは検出されていません。', 'rapls-passkey' )
			: sprintf(
				/* translators: %s: comma-separated plugin names. */
				__( 'セキュリティプラグインを検出しました: %s。REST API 制限環境でも動作するよう自動対応しています。', 'rapls-passkey' ),
				implode( ', ', $detected )
			);

		$desc = sprintf(
			/* translators: 1: RP ID, 2: site host. */
			__( '現在の RP ID は「%1$s」、サイトのホストは「%2$s」です。RP ID はパスキーの有効範囲を決めます(rapls_passkey_rp_id フィルターで変更可)。', 'rapls-passkey' ),
			$rp_id,
			$host
		) . ' ' . $compat;

		return $this->result( 'rapls_passkey_rp', __( 'Rapls Passkey: RP ID', 'rapls-passkey' ), 'good', $desc );
	}

	// --- Pure status decisions (unit-testable) -------------------------------

	/**
	 * @param bool $secure Secure context.
	 * @return string
	 */
	public static function https_status( bool $secure ): string {
		return $secure ? 'good' : 'critical';
	}

	/**
	 * @param bool $present Library present.
	 * @return string
	 */
	public static function library_status( bool $present ): string {
		return $present ? 'good' : 'critical';
	}

	/**
	 * @param bool $present Tables present.
	 * @return string
	 */
	public static function tables_status( bool $present ): string {
		return $present ? 'good' : 'recommended';
	}

	// --- Helpers -------------------------------------------------------------

	/**
	 * Build a Site Health result array.
	 *
	 * @param string $key         Test key.
	 * @param string $label       Test label.
	 * @param string $status      good|recommended|critical.
	 * @param string $description Plain-text description.
	 * @return array<string,mixed>
	 */
	private function result( string $key, string $label, string $status, string $description ): array {
		$colors = array(
			'good'        => 'green',
			'recommended' => 'orange',
			'critical'    => 'red',
		);

		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'セキュリティ', 'rapls-passkey' ),
				'color' => $colors[ $status ] ?? 'gray',
			),
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'test'        => $key,
		);
	}

	/**
	 * Whether the site host is a local development host (HTTPS not required).
	 *
	 * @return bool
	 */
	private function is_local_host(): bool {
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		if ( in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true ) ) {
			return true;
		}
		return (bool) preg_match( '/\.(local|test|localhost)$/', $host );
	}

	/**
	 * Whether both custom tables exist.
	 *
	 * @return bool
	 */
	private function tables_exist(): bool {
		global $wpdb;
		foreach ( array( Schema::credentials_table(), Schema::audit_table() ) as $table ) {
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB
			if ( $found !== $table ) {
				return false;
			}
		}
		return true;
	}
}
