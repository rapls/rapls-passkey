=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 8.2
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress のログインをパスキー(WebAuthn / FIDO2)で行う、パスワードレス認証プラグイン。

== Description ==

Rapls Passkey は、WordPress のログインをパスキー(WebAuthn / FIDO2)で行えるようにするプラグインです。

* パスワードレスでフィッシング耐性のあるログイン
* 同一デバイスのパスキー(Touch ID / Windows Hello)に対応
* スマートフォンのパスキー(iOS パスワード / 1Password など)によるクロスデバイス認証に対応
* 日本市場向けの丁寧な日本語 UI

= 要件 =

* PHP 8.2 以上
* WordPress 6.0 以上
* HTTPS(localhost を除く)

== Installation ==

1. プラグインを `wp-content/plugins/rapls-passkey` に配置します。
2. プラグイン管理画面から「Rapls Passkey」を有効化します。
3. プロフィール画面からパスキーを登録します。

== Changelog ==

= 0.1.0 =
* 初期スキャフォールド。プラグインの起動・認証情報テーブル・依存関係チェック。
