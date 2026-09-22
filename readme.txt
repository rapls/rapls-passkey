=== Rapls Passkey – Passwordless Login with WebAuthn ===
Contributors: rapls
Tags: passkey, passwordless, webauthn, login, two-factor
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.2
Stable tag: 0.13.79
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless login with passkeys (WebAuthn). Nothing to configure, no external service, and password sign-in keeps working.

== Description ==

Rapls Passkey adds passkey sign-in to WordPress. Touch ID, Windows Hello, Face
ID or a security key takes the place of the password, and your server never
holds a shared secret. It stores only a public key, which is useless to anyone
who steals it.

A video walkthrough (in Japanese):

https://www.youtube.com/watch?v=6qeKYlZrh1M

It is built to run where most WordPress sites actually run:

* **Fewer moving parts.** Nothing to configure before the first passkey, and no `gmp` to ask your host for: the large-number maths WebAuthn needs uses `gmp` or `bcmath` when one is installed and plain PHP when neither is. Signatures are checked with OpenSSL, one of the modules WordPress's Site Health already looks for.
* **Nothing leaves your site.** The passkey ceremony happens between the browser and your own server. No account, no API key, no third-party service in the login path.
* **Passwords keep working.** Password login is never switched off in the free plugin. Nobody gets locked out while a site moves across.
* **Japanese UI included.** Fully translated, alongside the English source.

= What the free plugin does =

* Passwordless, phishing-resistant sign-in (WebAuthn / FIDO2)
* Same-device passkeys (Touch ID / Windows Hello / Face ID)
* Cross-device sign-in using the browser's native passkey flow when the browser offers it (scan with your phone). A custom QR approval flow is available in Pro.
* Shortcodes and Gutenberg blocks (login / passkey management) you can embed on any page
* Rename, suspend and resume individual passkeys — a device that is temporarily out of reach can be cut off without destroying the credential
* A site-wide passkey list for administrators (Users -> Passkeys), searchable by owner or name
* Works with two-factor plugins (Wordfence Login Security, Two-Factor, ...): a passkey counts as the second factor, while weaker alternative logins must still pass the site's 2FA
* An audit log of registrations, sign-ins and removals, exportable as CSV
* WP-CLI commands, a first-run configuration check, and an emergency bypass constant
* Fully translatable UI (English source; translations come from translate.wordpress.org)

= Shortcodes =

Embed them in any page, post, or widget. In the block editor they are also available as the "Sign in with a passkey" and "Manage passkeys" blocks.

* `[rapls_passkey_login]` — a passkey sign-in button for logged-out visitors. Supports the `redirect` (URL to go to after success) and `label` (button text) attributes.
* `[rapls_passkey_register]` — a management UI where logged-in users can register and remove their own passkeys.

= Requirements =

* WordPress 6.0 or later
* PHP 8.2 or later
* HTTPS, except on localhost — browsers refuse WebAuthn without it

No PHP extension beyond WordPress's own requirements.

= Rapls Passkey Pro =

Everything above is free, and stays free. Pro is a separate add-on for the part
that comes after the first passkey: moving a whole site across, and keeping a
way in when a device goes missing.

* **Sign in from another device** — approve a login on your computer from your phone, with a QR code and a four-digit confirmation code so a relayed code cannot be used elsewhere
* **A way back in that is not a password** — one-time recovery codes and email magic-link sign-in
* **Roll out by role** — require passkeys for the roles you choose, with a grace period, then turn password login off once everyone is across
* **Adaptive step-up** — ask for a passkey again after a password sign-in from somewhere unfamiliar
* **Authenticator policy** — FIDO Metadata Service checks, an AAGUID denylist, trusted-device management
* **Operations** — security webhooks, adoption reports, multisite network settings, WP-CLI

One-time purchase, no subscription: updates with no time limit, a year of support, and a 14-day refund.
[Details and pricing](https://raplsworks.com/rapls-passkey-pro/)

== Installation ==

1. Place the plugin in `wp-content/plugins/rapls-passkey`.
2. Activate "Rapls Passkey" from the Plugins screen.
3. Register a passkey from your profile screen.

Nothing else is required: no account, no API key, no configuration before the
first passkey. The settings screen shows a first-run check (HTTPS, the
relying-party ID, the WebAuthn library) so you can see the site is ready.

== Frequently Asked Questions ==

= Does this need any PHP extensions? =

It needs OpenSSL, which checks the passkey signatures and is one of the modules
WordPress's Site Health already looks for. It does not need `gmp`: the
large-number maths WebAuthn needs uses `gmp` or `bcmath` when one is installed,
and plain PHP when neither is.

= Does it work on shared hosting? =

Yes. There is no extension to install, no persistent process, and nothing
written outside the plugin's own table and options. 

= Which browsers and devices work? =

Any current browser with a built-in authenticator — Touch ID, Windows Hello,
Face ID — or a FIDO2 security key. If the machine in front of you has no
passkey for the site, the browser's own cross-device flow lets you scan with
your phone instead.

= Is the free version limited? =

No. Passkey sign-in, registration, management, the shortcodes and blocks, the
administrator's passkey list and the two-factor integrations are all in the free
plugin, without a cap, a trial period or a licence key. Rapls Passkey Pro is a
separate add-on that adds different features — cross-device QR login, recovery
codes, enforcement by role — and installing it is not required for anything
described above to work.

= Does it work with my security plugin? =

It is built to sit alongside them rather than replace them. A plugin that
changes the login URL keeps doing so, and the passkey button appears on
whatever login screen your site actually serves; the developer's own site runs
it this way with CloudSecure WP Security. If your security plugin restricts the
REST API to logged-in users, turn on "Passkey login when REST is restricted"
under Settings → Rapls Passkey → REST API, so the sign-in can start before
anyone is logged in. With Wordfence Login Security or Two-Factor, a passkey
satisfies the second factor, and a weaker alternative login still has to pass
the site's own 2FA.

= Is the plugin available in Japanese? =

Yes. The Japanese translation is complete, and WordPress.org serves it as a
language pack — no bundled catalogue, so it updates independently of the
plugin.

= What if I lose my passkey and cannot sign in? =

Password login still works alongside passkeys, so sign in with your password as usual and then remove or re-register passkeys from your profile screen.

You can also manage passkeys from the server with WP-CLI:

    wp rapls-passkey list --user=admin
    wp rapls-passkey remove <id>

In an emergency, add the following to wp-config.php. It switches off every passkey requirement and second-factor check this plugin applies; remove it once you have recovered:

    define( 'RAPLS_PASSKEY_BYPASS', true );

= Will passkeys made on a staging site work on the live site? =

Not by default. A passkey is bound to the domain it was registered on, and that
binding is kept inside the authenticator, not in the database — so moving the
database to production does not carry it across. A passkey registered on
staging.example.com is not offered on example.com.

Either register again on the live site and treat staging passkeys as disposable,
or have both sites use the parent domain before anyone registers:

    add_filter( 'rapls_passkey_rp_id', function () {
        return 'example.com';
    } );

With the second, passkeys registered on staging keep working once the database
moves to production, including any you did not mean to keep. Passkeys made on
localhost only ever work on localhost. The setup screen shows the relying-party
ID in use, so this can be settled before the first passkey is registered.

== External services ==

This plugin sends nothing to any external service by default. One optional
integration, off unless you turn it on, contacts a third party:

**Google reCAPTCHA v3** — used only when you enable reCAPTCHA for password
logins. When it is on, the visitor's browser loads
`https://www.google.com/recaptcha/api.js`, and the plugin sends the resulting
token together with the request IP address to
`https://www.google.com/recaptcha/api/siteverify` so that Google can score the
request. Nothing is sent while the option is off. This service is provided by
Google and its use is governed by Google's terms and privacy policy:

* Terms of Service: https://policies.google.com/terms
* Privacy Policy: https://policies.google.com/privacy

No other host is contacted. The plugin bundles the public suffix list it needs
(`data/public_suffix_list.dat`) rather than fetching it, and passkey ceremonies
happen between the browser and your own site.

== Privacy ==

Authentication data is stored on your own site.

What is stored:

* Passkey credential records (public key, credential ID, sign counter, a label and timestamps) in a custom database table.
* A per-user WebAuthn user handle in user meta, plus one row in the options table recording that the account has one. The handle carries nothing about the person: for accounts created from this version it is derived from the account id and a site secret, and accounts that already had a random handle keep it.
* An optional audit log of passkey events (registration, sign-in, removal) with the acting user, IP address and timestamp.

Retention and removal:

* Passkey records remain until the user or an administrator deletes them; deleting a user removes their passkey records.
* The plugin integrates with WordPress's built-in personal-data export and erase tools, so a user's passkey and audit data are included in export/erase requests.
* Uninstalling the plugin (delete from the Plugins screen) drops its custom table and options.

This plugin does not use cookies for tracking. It sets only short-lived, functional cookies during a login ceremony (for example the pending second-factor login), which expire within minutes.

== Screenshots ==

1. Sign in with a passkey from the normal WordPress login screen.
2. The browser offers the passkeys saved for this site.
3. Your registered passkeys: rename, suspend or delete each one.
4. Registering a passkey from your profile screen.
5. Touch ID confirms before the passkey is saved.
6. Choose where the passkey is stored.
7. The first-run check: HTTPS, the relying-party ID, and the WebAuthn library.
8. Every registration, sign-in and removal, exportable as CSV.

== Changelog ==

= 0.13.79 =
* Corrected: Site Health and the setup check said passkey sign-in copes by itself when a security plugin restricts the REST API. It does not: that needs the "Passkey login when REST is restricted" option in the REST API section of the settings, which is off by default. Both now say so.
* Corrected: the readme said the Pro add-on has AAGUID allow and deny lists. It has a denylist.
* The Pro add-on's line in the readme says updates have no time limit and support is included for a year.

= 0.13.78 =
* The short description now says what the plugin is in the words people search for, that there is nothing to set up, and that password sign-in keeps working.
* Corrected: the readme said `gmp` is often missing on shared hosts and that nothing beyond WordPress's own requirements is needed. The first was never measured, and the second overlooked OpenSSL. `gmp` is optional — the maths uses it or `bcmath` when one is present and plain PHP otherwise — and OpenSSL is what checks the signatures. The description and the FAQ now say exactly that.
* The security-plugin FAQ now says what has been checked, a login URL changed by CloudSecure WP Security, and what a REST API restricted to logged-in users needs: one option in the settings. The claim about image CAPTCHAs, which had not been checked, is gone.
* No functional change.

= 0.13.77 =
* The short description now leads with what decides whether a site can try this safely: your password still works, so a lost device does not lock you out, and the Japanese interface is fully translated.
* New FAQ entry: why passkeys registered on a staging site do not work on the live one, and the two ways to handle it. The lost-passkey entry now says what the emergency constant actually switches off.
* A video walkthrough is linked from the description.
* The changelog had lost 0.13.46–0.13.62. When 0.13.71 trimmed this readme it deleted those entries and pointed to changelog.txt for them, but they were never added there. They are restored from history, and this readme now carries only the latest releases.
* No functional change.

= 0.13.76 =
* Packaging fix: in the released package, and only there, every certificate signature check failed. Building this plugin rewrites the bundled libraries into a private namespace so that another plugin carrying the same library cannot collide with ours, and that step rewrites any text shaped like a namespaced class name. One piece of text has that shape without being a class name: `ymdHis\Z`, the format a certificate's validity dates are written in. Certificates were then rewritten with those dates expanded into something else, the bytes stopped matching what the certificate authority had signed, and every certificate was reported as not verifying. Sign-in and registration verify no certificates, so passkeys themselves were unaffected; the Pro add-on's FIDO metadata refresh does, and it reported "Certificate chain does not validate to a trusted FIDO root" while naming trust anchors that had been correct all along.
* The check that would have caught this was being skipped. Running the suite against the built package excused it as needing the bundled libraries under their original names — it does not; it reaches them only through the plugin's own code. It runs against the package now, and the packaging step's rewrites are exercised directly as well, so a string it should not touch failing to survive is a test failure rather than a release.

= 0.13.75 =
* Translation only: the Japanese catalogue now follows the WordPress Japanese style guide where it had drifted from it. A half-width number takes no space around it in Japanese, so "0 は無制限です" becomes "0は無制限です"; and the glossary settles ブラウザー, サーバー and ユーザー over the shorter forms the 長音 rule would otherwise produce. 293 strings, no code change.
* tests/smoke-ja-style.php now checks both, and one more thing: translate.wordpress.org warns when a translation opens in a different letter case from the original. Japanese word order produces that on its own — "Enable reCAPTCHA" becomes "reCAPTCHA を有効にする" — so it is worth catching here rather than at upload time.

For the change history of 0.13.74 and earlier releases, see changelog.txt.

== Upgrade Notice ==

= 0.13.70 =
On PHP older than 8.2 the previous release took the whole site down, front end included. The plugin now steps aside with an admin notice instead.

= 0.13.66 =
Administrator enrolment is on by default instead of being unlocked by the Pro add-on. Translations now come from translate.wordpress.org rather than a bundled catalogue.

= 0.13.63 =
Every file in the previous package failed the WordPress Plugin Check direct-access test: the guard was rewritten by the build into a form the tool does not recognise. Fixed, along with the code-standard findings that were hidden behind misplaced exemptions.

= 0.13.53 =
Fixes CSV injection in the audit-log export: a formula preceded by whitespace was not neutralised. Update if you export audit logs.

= 0.13.28 =
Security (multisite): a user marked as spam on the network could still sign in with a passkey, a QR approval, a magic link or a recovery code. Update immediately on multisite.
