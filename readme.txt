=== Rapls Passkey ===
Contributors: rapls
Tags: passkey, webauthn, fido2, login, passwordless
Requires at least: 6.0
Tested up to: 7.0.2
Requires PHP: 8.2
Stable tag: 0.13.32
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
* A per-user WebAuthn user handle in user meta, plus one row in the options table recording that the account has one. The handle carries nothing about the person: for accounts created from this version it is derived from the account id and a site secret, and accounts that already had a random handle keep it.
* An optional audit log of passkey events (registration, sign-in, removal) with the acting user, IP address and timestamp.

External services (used only when you enable them):

* Google reCAPTCHA v3 — only if you turn on reCAPTCHA for password logins. When active, the visitor's browser contacts Google and the plugin sends the resulting token (and the request IP) to Google's siteverify endpoint to score the request. See Google's privacy policy. Leaving reCAPTCHA off means no data goes to Google.

Retention and removal:

* Passkey records remain until the user or an administrator deletes them; deleting a user removes their passkey records.
* The plugin integrates with WordPress's built-in personal-data export and erase tools, so a user's passkey and audit data are included in export/erase requests.
* Uninstalling the plugin (delete from the Plugins screen) drops its custom table and options.

This plugin does not use cookies for tracking. It sets only short-lived, functional cookies during a login ceremony (for example the pending second-factor login), which expire within minutes.

== Changelog ==

= 0.13.32 =
* More of the same audit, all about one account keeping exactly one WebAuthn identity:
* An account whose identity was recorded by an older version now has that fact registered the first time it is used, so a later request that cannot read it can no longer start a second one. While the table update is still outstanding no new identity is created at all — an account that looks new may simply be one the update has not reached.
* An identity whose copy in the account's profile data is lost is recovered from the record itself instead of leaving the account permanently unable to register a passkey.
* Registration establishes the identity once per request and carries it through, rather than asking twice and risking two different answers on a database whose reads lag behind its writes.

= 0.13.31 =
* A passkey confirmation now completes. Pro's step-up held risky password sign-ins for a passkey check — and then held the passkey sign-in that answered it, so with the strictest setting nobody could get in at all. A sign-in now says what kind it is, and the confirmation is never held.
* An account can no longer be given a second WebAuthn identity. When the handle an account already has cannot be read — a database whose reads lag behind its writes — registration is refused rather than started under a newly derived one, and the migration records every existing handle so that "does this account have one?" is answered by the database instead of by a read.
* The table update after a plugin upgrade now also runs for the Pro QR and sign-up ceremonies, not only the free plugin's own, and at most once every few minutes on a site where it cannot complete.

= 0.13.30 =
* Fixed: a site updated without anyone opening the admin screens — a background update, or WP-CLI — could be left with the previous table layout, and a passkey sign-in would then be refused until an administrator visited the dashboard. The table is now brought up to date by the sign-in itself.

= 0.13.29 =
* Further findings from the security audit, all about not trusting a value the plugin has just read back:
* Signing in with a username no longer tells anyone whether that account exists or holds a passkey. Sign-in now uses the browser's own passkey picker, and the answer to a username is identical whatever you type. A site that must support older security keys (which store nothing themselves and so have to be named by the server) can switch the old behaviour back on; the response is then padded to a fixed shape, and the trade-off is documented.
* A passkey suspended or deleted while someone is signing in with it no longer completes that sign-in, even on installations that send reads to a replica database.
* Each user's WebAuthn identifier is now derived rather than generated and stored. Concurrent first registrations, retries and lagging replicas all arrive at the same value, so an account's passkeys can no longer end up split across two identifiers.
* Recovery codes: a site whose database is lagging could report that generation failed after the previous codes had already been replaced — and then tell the user their old codes still worked. The result now comes from the write itself, and the message no longer makes that claim.

= 0.13.28 =
* Findings from a full-codebase security audit:
* SECURITY (multisite): a user marked as spam on a network — or whose primary site is — could still sign in with a passkey, a QR approval, a magic link or a recovery code. Those methods set the login cookie directly and so never reached WordPress's own spam check, which a password login passes through. All of them now apply it, before any site filter.
* A passkey login no longer proceeds if the credential was suspended or removed while the sign-in was in progress; the check now happens at the moment the login is committed rather than only when it started.
* Asking for sign-in options with a username no longer reveals whether that account exists or holds a passkey: a name with nothing behind it now receives plausible decoy entries derived from the name and a site secret, so the answer looks the same either way.
* A shared relying-party ID and Related Origins configured for a network are now actually applied to registration and sign-in. They were read before the settings that provide them had loaded, so a network-wide shared ID silently had no effect.
* Recovery codes are no longer displayed unless the site could store them. Previously a storage failure produced codes that looked usable but none of which would have been accepted — the opposite of a way back in.
* Adaptive step-up no longer fails open: if the record that holds a session for passkey confirmation cannot be written, that session is ended instead of continuing unchallenged. A database error while checking for held sessions now holds rather than releases.
* Passwordless sign-up confirms the account adopted the identifier its passkey was created against, and undoes the sign-up if not, rather than leaving an account whose credential cannot resolve.
* Enforcement's grace period no longer restarts on every request when its start time cannot be saved (which would have postponed the deadline indefinitely).
* Uninstall and the personal-data eraser now remove the current attempt-limit rows, the per-user handle lock and per-session step-up records, which earlier versions left behind.

= 0.13.27 =
* Tenth re-review fix: the check that proves the passkey limit's constraint on the database now also requires that it could remove its own temporary rows. If those deletions keep failing — a database that accepts writes but cannot complete them — the limit is reported as unenforceable and registration refuses, instead of reporting success while leaving rows behind.

= 0.13.26 =
* Ninth re-review fixes (both about not trusting a read, and about proving it):
* Claiming an attempt or a quota slot no longer reads anything at all. The insert either wrote the row — which, with a unique row name, means this request holds the slot — or it did not. Previously the plugin confirmed ownership with a follow-up read, and a read can be answered by a replica that is behind the writer, which could make a single request write a row for every slot and use up that key's whole allowance for the window. Each failed insert is now followed by a removal of that request's own row, so a request that ends up refused provably leaves nothing behind.
* The test that checks the passkey limit's constraint on the write server now calls that check directly, with and without the constraint in place, and asserts it reports true only when the database really refuses a duplicate — previously the scenario could pass without the check having run.

For the change history of 0.13.25 and earlier releases, see changelog.txt.
