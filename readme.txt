=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 8.2
Stable tag: 0.3.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress のログインをパスキー(WebAuthn / FIDO2)で行う、パスワードレス認証プラグイン。

== Description ==

Rapls Passkey は、WordPress のログインをパスキー(WebAuthn / FIDO2)で行えるようにするプラグインです。

* パスワードレスでフィッシング耐性のあるログイン
* 同一デバイスのパスキー(Touch ID / Windows Hello)に対応
* スマートフォンのパスキー(iOS パスワード / 1Password など)によるクロスデバイス認証に対応
* 任意のページに埋め込めるショートコードと Gutenberg ブロック(ログイン / パスキー管理)
* 日本市場向けの丁寧な日本語 UI

= ショートコード =

任意の固定ページ・投稿・ウィジェットに埋め込めます。Gutenberg では「パスキーでログイン」「パスキーの管理」ブロックとしても利用できます。

* `[rapls_passkey_login]` — ログアウト中の訪問者向けのパスキーログインボタン。`redirect`(成功後の遷移先 URL)と `label`(ボタン文言)属性に対応。
* `[rapls_passkey_register]` — ログイン中のユーザーが自分のパスキーを登録・削除できる管理 UI。

= 要件 =

* PHP 8.2 以上
* WordPress 6.0 以上
* HTTPS(localhost を除く)

== Installation ==

1. プラグインを `wp-content/plugins/rapls-passkey` に配置します。
2. プラグイン管理画面から「Rapls Passkey」を有効化します。
3. プロフィール画面からパスキーを登録します。

== Frequently Asked Questions ==

= パスキーを紛失してログインできない場合は? =

現在はパスワードログインも併用できるため、通常はパスワードでサインインし、プロフィール画面から不要なパスキーを削除・再登録してください。

サーバーから直接操作する場合は WP-CLI を使えます。

    wp rapls-passkey list --user=admin
    wp rapls-passkey remove <id>

緊急時は wp-config.php に次を追加するとパスキーの強制を一時的に無効化できます(復旧後は必ず削除してください)。

    define( 'RAPLS_PASSKEY_BYPASS', true );

== Changelog ==

= 0.3.0 =
* セキュリティ通知メール: パスキーの登録・削除、および新しい端末からのパスキーサインインを本人にメール通知(設定で無効化可、フィルターで個別制御可)。
* プライバシー(GDPR)対応: WordPress 標準の「個人データのエクスポート/消去」にパスキー・監査ログを連携。ユーザー削除時にも関連データを自動消去。
* 「ユーザー」一覧に「パスキー」列を追加(登録数・最終使用・未登録を表示)。設定画面に導入状況(登録率・総数)サマリを追加。
* ログインフォーム連携を拡張: Ultimate Member / MemberPress / Easy Digital Downloads / Theme My Login のログインフォームにパスキーボタンを表示(各プラグインが有効なときのみ。フィルターで個別制御可)。
* WebAuthn 詳細設定を追加: タイムアウト・ユーザー検証(required/preferred/discouraged)・認証器の種類(内蔵/外付け)を設定画面およびフィルターで調整可能。
* 登録ポリシー用の拡張フックを追加(rapls_passkey/registration_policy・rapls_passkey/attestation_conveyance)。Pro の認証器ポリシーや独自のアテステーション検証に利用できます。
* ログイン後のパスキー登録うながし: パスワードでログインした直後に、その場でパスキーの作成をおすすめ(未登録ユーザーのみ・一定期間に1回・設定で無効化可)。
* WooCommerce「マイアカウント」に「パスキー」タブを追加。会員が自分のパスキーを登録・削除できます(WooCommerce 有効時のみ)。
* 監査ログの CSV エクスポート(設定画面からダウンロード。Excel 対応の UTF-8 BOM 付き)。

= 0.2.0 =
* ショートコードと Gutenberg ブロックによるフロントエンド埋め込み(ログイン / パスキー管理)。
* 1ユーザーあたりのパスキー登録上限を設定可能。管理者は他ユーザーのパスキーを削除可能。
* 二要素認証プラグイン(Automattic Two-Factor / WP 2FA)と共存。パスキーログインを多要素認証として扱います。
* REST API をログイン済みユーザーに制限するセキュリティプラグイン環境でも、パスキー用エンドポイントのみ許可して動作を維持。
* Content-Security-Policy を壊しません。独自の CSP ヘッダーを注入せず、インラインのイベントハンドラーも使用しません。
* マルチサイト向けに rapls_passkey_rp_id / rapls_passkey_rp_name フィルターを追加(共通 RP ID)。

= 0.1.0 =
* 初期スキャフォールド。プラグインの起動・認証情報テーブル・依存関係チェック。
* パスキーの登録・ログイン(同一端末・クロスデバイス・オートフィル対応)。
* WP-CLI による管理/復旧コマンドと緊急バイパス定数。
* 設定画面。パスワードログイン向け reCAPTCHA v3、監査ログ。
* Wordfence / SiteGuard WP Plugin / CloudSecure WP Security 等の検出と共存。
