=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 7.0.2
Requires PHP: 8.2
Stable tag: 0.13.22
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless authentication for WordPress using passkeys (WebAuthn / FIDO2).

== Description ==

Rapls Passkey lets users sign in to WordPress with passkeys (WebAuthn / FIDO2).

* Passwordless, phishing-resistant sign-in
* Same-device passkeys (Touch ID / Windows Hello)
* Cross-device sign-in using the browser's native passkey flow when the browser offers it (scan with your phone). A custom QR approval flow is available in Pro.
* Shortcodes and Gutenberg blocks (login / passkey management) you can embed on any page
* Rename, suspend and resume individual passkeys — a device that is temporarily out of reach can be cut off without destroying the credential
* A site-wide passkey list for administrators (Users -> Passkeys), searchable by owner or name
* Works with two-factor plugins (Wordfence Login Security, Two-Factor, ...): a passkey counts as the second factor, while weaker alternative logins must still pass the site's 2FA
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

== Privacy ==

This plugin stores authentication data on your own site and, by default, sends nothing to any external service.

What is stored on your site:

* Passkey credential records (public key, credential ID, sign counter, a label and timestamps) in a custom database table.
* A per-user WebAuthn user handle (random, not derived from personal data) in user meta.
* An optional audit log of passkey events (registration, sign-in, removal) with the acting user, IP address and timestamp.

External services (used only when you enable them):

* Google reCAPTCHA v3 — only if you turn on reCAPTCHA for password logins. When active, the visitor's browser contacts Google and the plugin sends the resulting token (and the request IP) to Google's siteverify endpoint to score the request. See Google's privacy policy. Leaving reCAPTCHA off means no data goes to Google.

Retention and removal:

* Passkey records remain until the user or an administrator deletes them; deleting a user removes their passkey records.
* The plugin integrates with WordPress's built-in personal-data export and erase tools, so a user's passkey and audit data are included in export/erase requests.
* Uninstalling the plugin (delete from the Plugins screen) drops its custom table and options.

This plugin does not use cookies for tracking. It sets only short-lived, functional cookies during a login ceremony (for example the pending second-factor login), which expire within minutes.

== Changelog ==

= 0.13.22 =
* Fifth re-review fixes (concurrency correctness, isolation- and engine-independence):
* The passkey per-user limit and the atomic quota reservation are now serialised with a MySQL advisory named lock (GET_LOCK) instead of a transaction + row lock. Named locks work regardless of the table's storage engine (they hold even on MyISAM, where SELECT ... FOR UPDATE does not), do not touch the shared connection's transaction state (so they cannot implicitly commit another plugin's open transaction), signal success with an explicit result rather than an affected-row count (so a quota can no longer be miscounted when the connection uses MYSQLI_CLIENT_FOUND_ROWS), and release automatically if the connection drops. A lock that cannot be taken fails closed.
* Every SQL step in the registration path is now checked, and the per-user count fails closed on a database error (a failed count no longer reads as "under the limit").
* The passkey-login REST routes and the Pro recovery-code login now use the shared fail-closed rate counter as well, so a database error blocks instead of silently allowing, on every login path.

= 0.13.21 =
* Fourth re-review fixes (concurrency correctness):
* The passkey per-user limit is now enforced under a real database row lock (a short transaction on a per-user row), so it holds exactly regardless of the server's transaction isolation level — not just the default. The lock releases automatically on commit/rollback, so a crashed request cannot leave it stuck.
* The atomic quota primitive reads its own result before the opportunistic cleanup runs (a stray cleanup query could otherwise flip a reservation's success/failure), and a slot is now handed back only to the exact time-window it was taken in, so a late failure from an expired window cannot subtract from a newer one.
* Re-opening the anonymous passkey-login REST routes when a security plugin locks the REST API to logged-in users is now an explicit, off-by-default admin setting (Settings -> Rapls Passkey -> REST API). It never overrides a firewall / IP-block / maintenance response, and does nothing unless you turn it on.

= 0.13.20 =
* Third re-review fixes (concurrency and REST hardening):
* The passkey per-user limit is now enforced in a single atomic INSERT ... SELECT statement, so two simultaneous registrations can never both exceed the maximum — the cap no longer depends on a post-insert rollback. The per-user registration lock is released only by its owner (compare-and-delete), so a stale lock cannot be freed out from under the request that stole it.
* The shared rate/attempt counter now FAILS CLOSED on a database error (a read or write failure blocks the guarded action instead of silently allowing it), and gained an atomic "reserve one slot under a cap" primitive for callers that need a strict quota.
* The REST re-open for the anonymous passkey-login routes now clears ONLY a genuine 401 "authentication required" restriction; a 403 from a WAF, IP gate, maintenance mode or capability check is preserved even on the plugin's own routes.

= 0.13.19 =
* Second re-review fixes (concurrency, 2FA and distribution build):
* Distribution build: WooCommerce's global WC() (and the wc_*/WC_* family) is excluded from prefixing, so the build no longer rewrites a function_exists('WC') check or emits a global WC() alias that forwards to a non-existent prefixed function (which could mis-detect WooCommerce or fatal another plugin). The final-artifact check now also fails on any mis-prefixed WooCommerce symbol or any generated host-function alias.
* A passkey login that did NOT perform user verification is treated as a weaker login: with the site's 2FA active it is now sent to the 2FA challenge BEFORE the auth cookie is issued (previously the 2FA "verified" mark was merely withheld afterwards).
* The post-first-factor 2FA attempt counter now uses an atomic fixed-window count (shared with the login rate limiter), passkey registration takes a short per-user lock so the per-user limit holds strictly under concurrency, and the REST auth-error allowlist clears only the plugin's own authentication errors.

= 0.13.18 =
* Re-review resubmission. No code change from 0.13.17: the end-to-end matrix (clean-WordPress activation, passkey register/login, user-verification-gated 2FA, single-use / per-user limit / rate limit, coexistence with another plugin that bundles web-auth, and the two-factor integration) was run on a real install and passed. The procedure is recorded in docs/E2E-TESTING.md.

For the change history of 0.13.17 and earlier releases, see changelog.txt.
