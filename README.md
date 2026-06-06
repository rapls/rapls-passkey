# rapls-passkey

WordPress のログインをパスキー(WebAuthn / FIDO2)で行う WordPress プラグイン。rapls ファミリーの一員。

## 概要

- パスワードレスでフィッシング耐性のあるログインを提供します。
- 同一デバイスのパスキー(Touch ID / Windows Hello)と、スマホのパスキー(iOS パスワード / 1Password など)によるクロスデバイス認証に対応します。
- 日本市場向けの丁寧な日本語 UI を目指します。

## ステータス

設計・初期開発段階(コードは順次追加予定)。

## 要件

- PHP 8.2 以上
- WordPress 6.0 以上
- HTTPS(localhost を除く)
- WebAuthn ライブラリ: `web-auth/webauthn-lib`

## 開発

```bash
composer install            # 依存関係のインストール
composer dump-autoload -o   # オートローダ最適化
php tests/smoke-<name>.php   # スモークテスト実行
bin/build.sh                # 配布 ZIP 生成 -> ../rapls-passkey.zip
```

## ライセンス

GPL-2.0-or-later
