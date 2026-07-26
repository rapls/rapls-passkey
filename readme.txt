=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 7.0.2
Requires PHP: 8.2
Stable tag: 0.13.25
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

= 0.13.25 =
* Eighth re-review fixes (the passkey limit's safety check, and one availability fix):
* Before applying a passkey limit the plugin now proves the constraint on the server that takes the writes — it writes two rows claiming one slot and requires the second to be refused — instead of only asking whether an index with the right name exists. A read can be answered by a replica whose schema differs from the writer's, so an index that only the replica still has can no longer make the limit look enforced.
* The index check also verifies its shape: it must be UNIQUE and over exactly (user_id, slot_no) in that order. A same-named index that is not unique, or covers other columns, enforces nothing and is no longer mistaken for the real constraint.
* When a limit cannot be confirmed, registration refuses (503) rather than proceeding unprotected.
* Availability fix: if the row a request has just written is not yet visible (a replica lagging behind), the request now stops instead of trying the next attempt slot. Previously one request could write a row for every slot and use up that IP's whole login / recovery / sign-up budget for the window.

= 0.13.24 =
* Seventh re-review fixes. Every attempt limit is now enforced the same way the passkey limit is — by a database constraint rather than by comparing a number the plugin has read:
* Login, two-factor, recovery-code, magic-link, QR-code and sign-up limits each claim a numbered attempt row whose uniqueness the database guarantees. Because nothing is decided from a value that was read, the limits hold even where a read/write-splitting database drop-in can serve a stale count from a replica — a configuration in which a counter-based limit can be bypassed entirely.
* Time windows are now clock-aligned and half-open, so every request places itself in the same window. Previously the exact second a window ended was read inconsistently, which let a burst of requests arriving on that boundary through.
* The per-user passkey limit now verifies its unique index on the database at the moment of registration instead of trusting a flag stored during the upgrade. If the index is ever lost (a restore, a manual change), registration refuses with an error rather than silently letting the limit be exceeded.
* A failed upgrade no longer records itself as complete: if the slot numbering or the index cannot be created, the schema version is left behind so the next admin request retries it.
* Verified against a real MySQL server, running the plugin's own code: upgrading from the previous schema, limit 1 storing exactly 1 passkey and limit 3 exactly 3 under 20 simultaneous processes, registration refusing when the index is dropped, refusing on a database error, and a replayed registration storing one passkey rather than two. The test ships in the repository (tests/db/integration.php) and runs in CI against MySQL 8.0/8.4 and MariaDB 10.11/11.4.

= 0.13.23 =
* Sixth re-review fixes. The per-user passkey limit and the sign-up quota are now enforced by DATABASE CONSTRAINTS instead of an application lock:
* Each passkey occupies a numbered slot under a new UNIQUE (user_id, slot_no) index, and only slots within the configured limit are ever offered — so two simultaneous registrations can never both take the last one. Unlike the previous named lock, this holds even when WordPress transparently reconnects and replays a statement, when a db.php drop-in (HyperDB and similar) routes queries to a different server, and on any storage engine. A replayed registration after a reconnect now stores exactly one passkey instead of two.
* The sign-up quota reserves a numbered row and confirms ownership by reading it back, so it no longer depends on a database session, an advisory lock, or affected-row counts. A reservation is handed back by its own token, so a hand-back can never disturb another request's slot or mis-count the quota.
* Login attempt limits are now consumed BEFORE the passkey assertion (or recovery code) is checked, not after it fails. Previously a batch of simultaneous attempts could all read the same under-limit count and all proceed; now exactly one can take the last attempt, which also caps the verification work a flood of requests can start.
* Verified against a real MySQL server with 100 simultaneous processes: limit 1 stores 1 passkey, limit 3 stores 3, and with one attempt left exactly one of 20 concurrent logins is admitted. The test ships in the plugin's repository (tests/db/concurrency.php) and runs in CI against MySQL 8.0/8.4 and MariaDB 10.11/11.4.
* With the passkey limit set to 0 (unlimited, the default) registration no longer performs any limit bookkeeping at all.

For the change history of 0.13.22 and earlier releases, see changelog.txt.
