=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 7.0.2
Requires PHP: 8.2
Stable tag: 0.13.17
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

= 0.13.17 =
* Re-review fixes: make the namespace-prefixed distribution build actually boot, plus concurrency and configuration hardening.
* The prefixed bundled libraries now load correctly — the build generates the class map BEFORE scoping (and no longer regenerates it afterwards, which had dropped the prefixed classes), so the plugin no longer mistakes WebAuthn for "missing". WordPress-core and third-party-plugin symbols are no longer prefixed by mistake. A final-artifact check (bin/verify-dist.php) guards against a regression, and the bundled third-party licence notices are kept in the ZIP.
* A direct passkey login satisfies the site's 2FA only when the authenticator performed user verification (biometric/PIN); possession alone no longer counts as the second factor.
* The WebAuthn user handle is minted under an atomic database lock, the per-user passkey-limit rollback is deterministic under concurrent registrations, and the per-IP login rate counter is an atomic fixed-window count — closing read-modify-write races.
* reCAPTCHA fail-open vs fail-closed on a Google outage is now an explicit setting (Settings -> Rapls Passkey), not just a filter.

= 0.13.16 =
* Build hardening for distribution (no runtime behaviour change): the bundled libraries (web-auth/webauthn-lib, Symfony, Brick, spomky-labs, ParagonIE) are now rewritten into the plugin-private RaplsPasskey\Vendor\ namespace at build time with PHP-Scoper, so another plugin bundling a different version of the same library can no longer collide with this one. The WebAuthn availability checks were switched to a `::class` reference so the prefixing is deterministic. Committed source stays unscoped; only the distributed ZIP is prefixed.

= 0.13.15 =
* Documentation: clarified that sharing an RP ID / Related Origins aligns the WebAuthn protocol across domains but does not by itself make a passkey usable on another site — that also needs shared users and a shared credential store (Multisite or shared tables). Independent installs use a passkey per domain. No behaviour change.

= 0.13.14 =
* Related Origin Requests (cross-domain passkeys) now work end-to-end: a site can use a shared relying-party ID that is not its own registrable domain when its origin is one of the authorized related origins, and the ceremony verifier accepts assertions from those origins. Filter: rapls_passkey/related_origins (Pro's "related origins" setting wires it). Requires real cross-domain WebAuthn testing to validate for your domains.

= 0.13.13 =
* The WooCommerce "My account" passkey endpoint's rewrite rule is now cleared and regenerated across a deactivate/reactivate cycle, so the tab no longer 404s if the rewrite rules were flushed while the plugin was inactive.

= 0.13.12 =
* The login and passkey-management shortcodes/blocks now scope their controls to each instance instead of shared DOM ids, so more than one of them (or a shortcode alongside the WooCommerce account integration) can appear on the same page and all of them work.
* The registration policy filter (rapls_passkey/registration_policy) now also receives a context array (owner_id, actor_id, context) so a policy can be scoped to the real owner rather than the current user, which differs during admin enrolment.

= 0.13.11 =
* The "Export Personal Data" tool now pages through the audit log instead of stopping at the first 1000 rows, so a data-subject export is complete no matter how many events a user has.

= 0.13.10 =
* The per-user passkey limit is now enforced atomically: after storing a new credential the count is re-checked and the insert is rolled back if two simultaneous registrations both slipped past the pre-insert check, so the configured maximum can never be exceeded.

= 0.13.9 =
* More hardening from a follow-up review:
* Passkey registration now binds the new credential to the user the ceremony was actually built for (a constant-time check of the verified userHandle against the re-resolved owner), so a caller allowed to enrol on behalf of others cannot request options for one user and then save the credential to another.
* A user's WebAuthn user handle is now created atomically on first use, so two simultaneous first registrations can no longer mint two different handles for the same account.
* reCAPTCHA can now be set to fail closed when Google cannot be reached (it still fails open by default so an outage does not lock everyone out). Filter: rapls_passkey/recaptcha_fail_open.

For the change history of 0.13.8 and earlier releases, see changelog.txt.
