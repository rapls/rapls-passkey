=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 8.2
Stable tag: 0.9.3
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless authentication for WordPress using passkeys (WebAuthn / FIDO2).

== Description ==

Rapls Passkey lets users sign in to WordPress with passkeys (WebAuthn / FIDO2).

* Passwordless, phishing-resistant sign-in
* Same-device passkeys (Touch ID / Windows Hello)
* Cross-device sign-in with phone passkeys (iCloud Keychain, 1Password, and more)
* Shortcodes and Gutenberg blocks (login / passkey management) you can embed on any page
* Fully translatable UI (English source with a bundled Japanese translation)

= Shortcodes =

Embed them in any page, post, or widget. In the block editor they are also available as the "Sign in with a passkey" and "Manage passkeys" blocks.

* `[rapls_passkey_login]` — a passkey sign-in button for logged-out visitors. Supports the `redirect` (URL to go to after success) and `label` (button text) attributes.
* `[rapls_passkey_register]` — a management UI where logged-in users can register and remove their own passkeys.

= Requirements =

* PHP 8.2 or later
* WordPress 6.0 or later
* HTTPS (except on localhost)

== Installation ==

1. Place the plugin in `wp-content/plugins/rapls-passkey`.
2. Activate "Rapls Passkey" from the Plugins screen.
3. Register a passkey from your profile screen.

== Frequently Asked Questions ==

= What if I lose my passkey and cannot sign in? =

Password login still works alongside passkeys, so sign in with your password as usual and then remove or re-register passkeys from your profile screen.

You can also manage passkeys from the server with WP-CLI:

    wp rapls-passkey list --user=admin
    wp rapls-passkey remove <id>

In an emergency, add the following to wp-config.php to temporarily disable passkey enforcement (remove it once you have recovered):

    define( 'RAPLS_PASSKEY_BYPASS', true );

== Changelog ==

= 0.9.3 =
* The stored reCAPTCHA secret key is now encrypted at rest (versioned, tagged ciphertext via libsodium, with an OpenSSL AES-256-GCM fallback) instead of plaintext. Existing keys keep working and are re-encrypted on the next save. Settings export decrypts secrets so a configuration stays portable between sites.

= 0.9.2 =
* Hardening: the audit-log CSV export now neutralises spreadsheet formula injection (cells beginning with =, +, -, @ are prefixed with an apostrophe), since a user-chosen login could otherwise be executed as a formula when the CSV is opened in Excel/Sheets.

= 0.9.1 =
* Hardening (from a security review): added a rapls_passkey/allow_login veto filter, consulted before a passkey/alternative-method login sets the auth cookie, so integrations that block users via the core authenticate filter can apply the same block to passkey logins. Expanded uninstall cleanup to also remove the plugin's per-user meta. No functional change for normal use.

= 0.9.0 =
* Internationalization: all source strings are now in English, with Japanese provided as a bundled translation (languages/rapls-passkey-ja.po/.mo). The text domain remains rapls-passkey, so any locale can be translated. No functional change; the Japanese UI is unchanged for ja sites.

= 0.8.0 =
* Added a passkey education snippet: a concise "What is a passkey?" explainer (a JavaScript-free disclosure) on the profile screen, the login screen, and the login/management shortcodes. Use the rapls_passkey_learn_more_url filter to point the "Learn more" link at your own help page.

= 0.7.0 =
* Added LifterLMS and BuddyPress login-form integrations (a passkey button on each plugin's login form, only when that plugin is active). Forms that use the standard login_form action (such as bbPress and LearnDash) are already covered by the login-screen passkey button (and can be added via the rapls_passkey_login_form_hooks filter).

= 0.6.0 =
* Added an "Adoption" dashboard widget. See at a glance the number of registered passkeys, how many users have a passkey and their share of all users, and the last 30 days of activity (logins / new registrations), plus links to the users list and settings (administrators only).

= 0.5.0 =
* Added `wp rapls-passkey stats` (site-wide adoption: total passkeys and users with a passkey). Together with the existing `list` / `remove` commands, this helps automate operations and audits.

= 0.4.0 =
* Authenticator (provider) names: added an "Authenticator" column to the passkey list (profile screen and the [rapls_passkey_register] shortcode), showing the provider derived from the AAGUID — iCloud Keychain, Google Password Manager, Windows Hello, 1Password, YubiKey, and more. The provider name is also included in the registration notification email. The mapping is extensible/overridable via the rapls_passkey/authenticator_names filter (shows "Unknown" where the provider is hidden).

= 0.3.0 =
* Security notification emails: notify the user about passkey registration and removal, and about passkey sign-ins from a new device (can be disabled in settings; individually controllable via filters).
* Privacy (GDPR): integrates passkeys and the audit log with WordPress's built-in personal-data export/erase, and purges related data when a user is deleted.
* Added a "Passkey" column to the Users list (count / last used / not registered), and an adoption summary (rate / total) on the settings screen.
* Extended login-form integrations: a passkey button on the login forms of Ultimate Member / MemberPress / Easy Digital Downloads / Theme My Login (only when each plugin is active; individually controllable via filters).
* Added advanced WebAuthn settings: timeout, user verification (required/preferred/discouraged), and authenticator type (platform/cross-platform), adjustable in settings and via filters.
* Added extension hooks for the registration policy (rapls_passkey/registration_policy, rapls_passkey/attestation_conveyance) for the Pro authenticator policy or custom attestation verification.
* Post-login passkey prompt: right after a password login, suggest creating a passkey on the spot (only for users without one, once per interval, can be disabled in settings).
* Added a "Passkey" tab to the WooCommerce "My account" page so members can register and remove their own passkeys (only when WooCommerce is active).
* CSV export of the audit log (download from the settings screen; UTF-8 with BOM for Excel).
* Added the registration core that powers Pro passkey sign-up (creation options for not-yet-created users).
* Automatic passkey creation (Conditional Create): on supported browsers (Safari 18+ / Chrome 136+, etc.) a passkey is created automatically right after a password login with no dialog; falls back to the prompt screen when unsupported.
* Site Health integration: self-checks for HTTPS, the WebAuthn library, the database tables, and RP ID / security-plugin coexistence under Tools → Site Health (Status tab checks plus an Info tab panel/export).
* Added WebAuthn UI hints. Tell supported browsers whether to suggest this device, another device (QR), or a security key first. Also supports usernameless passkey login (sign in with just the button).
* Plugin Check compliance: the post-login prompt script is loaded via wp_enqueue_script, direct DB query annotations were tidied (table names come from the prefix and are safe), and a direct-access guard was added to dev-only files (tests/ and bin/).

= 0.2.0 =
* Front-end embedding via shortcodes and Gutenberg blocks (login / passkey management).
* Configurable per-user passkey registration limit. Administrators can remove other users' passkeys.
* Coexists with two-factor plugins (Automattic Two-Factor / WP 2FA), treating a passkey login as multi-factor.
* Keeps working even where a security plugin restricts the REST API to logged-in users, by allowing only the passkey endpoints.
* Does not break Content-Security-Policy: injects no custom CSP header and uses no inline event handlers.
* Added the rapls_passkey_rp_id / rapls_passkey_rp_name filters for multisite (shared RP ID).

= 0.1.0 =
* Initial scaffold: plugin bootstrap, credential table, and dependency checks.
* Passkey registration and login (same-device, cross-device, and autofill).
* WP-CLI management/recovery commands and an emergency bypass constant.
* Settings screen, reCAPTCHA v3 for password logins, and an audit log.
* Detects and coexists with Wordfence / SiteGuard WP Plugin / CloudSecure WP Security, etc.
