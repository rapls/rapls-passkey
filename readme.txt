=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 7.0.2
Requires PHP: 8.2
Stable tag: 0.13.16
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

= 0.13.8 =
* The relying-party ID is now validated against the full Mozilla Public Suffix List (bundled in data/public_suffix_list.dat), so a public suffix the previous short denylist missed — github.io, appspot.com, co.id, com.ar and the like — is correctly rejected as an RP ID. Wildcard and exception rules are honoured. If the list file is unavailable the matcher falls back to the previous heuristic, so validation never hard-fails. Filter: rapls_passkey_rp_id_public_suffixes (adds further suffixes).

= 0.13.7 =
* Hardening from a follow-up review (concurrency and multi-factor assurance):
* The signature counter is now advanced with an optimistic compare-and-set, and the login is refused if it does not commit — so a replayed assertion cannot slip past the counter check in a race, and a database write failure no longer signs anyone in on stale state. Counter-less authenticators (which legitimately report 0) are unaffected.
* Login options accept a raise-only "uv=required" request so a caller (such as Pro's step-up) can require user verification for a multi-factor login; it can only strengthen, never weaken, the site's setting. Filter: rapls_passkey/allow_uv_elevation.

= 0.13.6 =
* From a follow-up static-analysis review:
* The WebAuthn verifier now accepts both the Site Address (home) and WordPress Address (site) origins, matching the REST same-origin gate, so a split-URL install whose login screen runs on a different origin verifies correctly.
* Registration options now isolate a corrupt stored credential per row (like login options already did), so one unreadable record can no longer stop a user from enrolling a replacement passkey.
* The REST login allowlist now only clears the known "REST is limited to logged-in users" authentication errors on its routes, so an unrelated block (WAF, IP gate, maintenance) another plugin returns is preserved. Filter: rapls_passkey/rest_clearable_error_codes.
* Moved the older change history into changelog.txt to keep readme.txt within the WordPress.org size guideline.

= 0.13.5 =
* From a follow-up static-analysis review:
* Same-origin checks on the login/registration routes now compare the full origin (scheme, host and port), so http vs https or a different port is no longer treated as the same site.
* The relying-party ID can no longer be set to a public suffix (e.g. "com" or "co.jp"); such a value is rejected and the site host is used instead. Filter: rapls_passkey_rp_id_public_suffixes.
* The REST allowlist that keeps passkey login reachable under "logged-in only" security plugins now matches its routes on path-segment boundaries, so an unrelated route that merely contains the string is not affected.
* Alternative (magic-link / recovery-code) logins now fail closed when an active 2FA plugin cannot report a user's second-factor status: rather than letting the weaker login through, it is refused and the user is asked to use their passkey or password. A passkey login is unaffected.
* An internal exception reason is never returned to an anonymous REST client, even with WP_DEBUG on; it is written to the server log only.
* Tested up to WordPress 7.0.2.

For the change history of earlier releases, see changelog.txt.
