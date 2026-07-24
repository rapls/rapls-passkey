# Bundled data

## `public_suffix_list.dat`

A snapshot of the Mozilla **Public Suffix List** (https://publicsuffix.org/),
used by `RaplsPasskey\WebAuthn\PublicSuffixList` to reject a public suffix (e.g.
`com`, `co.jp`, `github.io`, `appspot.com`) being configured as the WebAuthn
Relying Party ID.

- **Source:** https://publicsuffix.org/list/public_suffix_list.dat
- **License:** Mozilla Public License 2.0 (the list is dual-licensed; the MPL-2.0
  applies to the data file).
- **Format:** one rule per line; `//` comments and blank lines ignored; `*.`
  wildcard and `!` exception rules supported.

If this file is absent or unreadable the matcher falls back to a small built-in
heuristic (single-label hosts plus a short denylist), so RP ID validation never
hard-fails — the default RP ID (the site's own host) is safe either way.

### Updating the snapshot

    curl -sS -o public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat

Refresh periodically so newly-delegated suffixes are recognised.
