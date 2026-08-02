<?php
/**
 * A digest of vendor/ — every file, not two of them.
 *
 * WHAT WAS WRONG (V84-01). vendor/ is generated and untracked, and everything
 * that claimed to bind it bound something else: the build recorded the SHA-256
 * of composer.lock and of vendor/composer/installed.json, and the bundle wrote
 * those two numbers into VENDOR-PROVENANCE.json. Neither changes when
 * vendor/autoload.php changes. A file edited inside an installed package, or an
 * autoloader with a line added to it, therefore reached both the scoped
 * distribution ZIP and the source tree in the verification bundle — where it
 * runs on a reviewer's machine — and repeated rebuilds from the same working
 * tree agreed with each other perfectly, so "three identical digests" said
 * nothing about it. Recording a fresh digest at build time is no better: it
 * writes down whatever is there.
 *
 * So the digest covers the TREE: every path, its type, whether it is
 * executable, and its contents (or, for a symlink, its target). It is computed
 * before a release, committed as vendor-manifest.json, and CHECKED — never
 * silently rewritten — by bin/build-dist.sh and bin/make-bundle.sh.
 *
 *   php bin/vendor-digest.php --write     regenerate the manifest (deliberate)
 *   php bin/vendor-digest.php --check     compare; exit 1 and name what differs
 *   php bin/vendor-digest.php --print     print the digest only
 *
 * The per-file list is kept in the manifest rather than only the total, because
 * "vendor/ differs" is not an answer anybody can act on.
 *
 * @package RaplsPasskey
 */

$root     = dirname( __DIR__ );
$mode     = '';
foreach ( array_slice( $argv, 1 ) as $a ) {
	if ( in_array( $a, array( '--write', '--check', '--print' ), true ) ) {
		$mode = substr( $a, 2 );
	}
	// --root exists so tests/smoke-vendor-digest.php can drive this against a
	// tree it builds itself: the rules are worth testing without a network and
	// without depending on which packages happen to be installed today.
	if ( 0 === strpos( $a, '--root=' ) ) {
		$root = rtrim( substr( $a, 7 ), '/' );
	}
}
$vendor   = $root . '/vendor';
$manifest = $root . '/vendor-manifest.json';
if ( '' === $mode ) {
	fwrite( STDERR, "usage: vendor-digest.php --write|--check|--print\n" );
	exit( 2 );
}

if ( ! is_dir( $vendor ) ) {
	fwrite( STDERR, "vendor-digest: there is no vendor/ here — run composer install\n" );
	exit( 2 );
}

/**
 * Every entry under vendor/, canonically.
 *
 * @param string $vendor Absolute path.
 * @return array<string,string> Relative path => "type:mode:hash".
 */
function rapls_vendor_entries( $vendor ) {
	$out  = array();
	$base = rtrim( $vendor, '/' );
	$it   = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS ),
		RecursiveIteratorIterator::SELF_FIRST
	);
	foreach ( $it as $path => $info ) {
		$rel = substr( (string) $path, strlen( $base ) + 1 );
		if ( '' === $rel || 0 === strpos( $rel, '.git/' ) || '.git' === $rel ) {
			continue;
		}
		if ( is_link( $path ) ) {
			// The TARGET is the content of a symlink; following it would hash
			// something that is not in the tree.
			$out[ $rel ] = 'link:0:' . hash( 'sha256', (string) readlink( $path ) );
			continue;
		}
		if ( is_dir( $path ) ) {
			// Directories carry no content, and an EMPTY one is not reproducible:
			// a --no-dev install in a clean clone leaves no vendor/bin while a tree
			// that once had dev tools keeps the empty directory behind. Recording
			// them made the manifest checkout-specific for no gain — a directory
			// with nothing in it cannot run.
			continue;
		}
		// Only the executable bit matters: the rest of the mode varies with the
		// umask of whoever ran Composer and says nothing about the bytes.
		$exec = ( fileperms( $path ) & 0111 ) ? '1' : '0';

		// TWO FILES DESCRIBE THE CHECKOUT THEY WERE WRITTEN IN. Composer records
		// the ROOT package's git reference and a version derived from its branch
		// in vendor/composer/installed.php and installed.json. Those change on
		// every commit — a manifest recorded against them is stale the moment it
		// is committed, and an unkeepable check is one that gets deleted — and a
		// tree exported WITHOUT .git, which is exactly what this bundle ships,
		// gets NULL and '1.0.0+no-version-set' instead, so the source we hand out
		// could never satisfy its own manifest (V86-01).
		//
		// Three values are blanked, inside the root block only. The dependencies'
		// versions and references are untouched, and every other byte of both
		// files — including all the code in installed.php — is hashed as it
		// stands. install_path is written as __DIR__ . '…' and so is already the
		// same text everywhere.
		if ( 'composer/installed.php' === $rel || 'composer/installed.json' === $rel ) {
			$body = (string) file_get_contents( $path );
			// The root block, delimited by BALANCED parentheses rather than by a
			// pattern: it contains `'aliases' => array(),`, so "up to the first
			// `),`" ends in the middle of it, and "up to a `),` on its own line"
			// depends on how the file happens to be laid out. Neither is a fact
			// about where the block ends.
			// TWICE, NOT ONCE. installed.php describes the root package in its
			// 'root' block AND again under 'versions' => array( '<name>' => … ),
			// with the same three values. Blanking only the first left the second
			// to differ and the whole thing to fail — which is what the first
			// attempt at this did.
			$blank = static function ( $body, $marker ) {
				$at = strpos( $body, $marker );
				while ( false !== $at ) {
					$open  = strpos( $body, '(', $at );
					$depth = 0;
					$end   = $open;
					for ( $i = $open, $n = strlen( $body ); $i < $n; $i++ ) {
						if ( '(' === $body[ $i ] ) {
							$depth++;
						} elseif ( ')' === $body[ $i ] ) {
							$depth--;
							if ( 0 === $depth ) {
								$end = $i;
								break;
							}
						}
					}
					$block = substr( $body, $at, $end - $at + 1 );
					$fixed = preg_replace( "/('(?:pretty_version|version|reference)'\s*=>\s*)(?:NULL|null|'[^']*')/", '$1<volatile>', $block );
					$body  = substr( $body, 0, $at ) . $fixed . substr( $body, $end + 1 );
					$at    = strpos( $body, $marker, $at + strlen( $fixed ) );
				}
				return $body;
			};
			$body = $blank( $body, "'root' => array(" );
			// The root package's own entry in the versions map, found by the name
			// the root block gives — not by guessing which package we are.
			if ( preg_match( "/'root' => array\(\s*'name' => '([^']+)'/", $body, $nm ) ) {
				$body = $blank( $body, "'" . $nm[1] . "' => array(" );
			}
			$body = preg_replace_callback(
				'/"root"\s*:\s*\{.*?\}/s',
				static function ( $m ) {
					return preg_replace( '/("(?:pretty_version|version|reference)"\s*:\s*)(?:null|"[^"]*")/', '$1"<volatile>"', $m[0] );
				},
				(string) $body
			);
			$out[ $rel ] = 'file:' . $exec . ':' . hash( 'sha256', (string) $body );
			continue;
		}

		// AND THE AUTOLOADER'S OWN NAME. Composer names its bootstrap classes
		// ComposerAutoloaderInit<hash> / ComposerStaticInit<hash>, and the hash is
		// minted per installation — so two installs of the SAME lock file differ
		// in these three files and nowhere else. Blanking the name is what lets a
		// clean clone reproduce the recorded tree and be checked against it;
		// every other byte of the autoloader, including the class maps, is
		// hashed as it stands.
		if ( in_array( $rel, array( 'autoload.php', 'composer/autoload_real.php', 'composer/autoload_static.php' ), true ) ) {
			$body       = preg_replace( '/Composer(?:Autoloader|Static)Init[0-9a-f]{16,}/', 'ComposerInit<hash>', (string) file_get_contents( $path ) );
			$out[ $rel ] = 'file:' . $exec . ':' . hash( 'sha256', (string) $body );
			continue;
		}
		$out[ $rel ] = 'file:' . $exec . ':' . hash_file( 'sha256', $path );
	}
	ksort( $out, SORT_STRING );
	return $out;
}

$entries = rapls_vendor_entries( $vendor );
$canon   = '';
foreach ( $entries as $rel => $meta ) {
	$canon .= $rel . "\0" . $meta . "\n";
}
$digest = hash( 'sha256', $canon );

if ( 'print' === $mode ) {
	echo $digest, "\n";
	exit( 0 );
}

if ( 'write' === $mode ) {
	file_put_contents(
		$manifest,
		json_encode(
			array(
				'algorithm' => 'rapls-vendor-tree-1',
				'digest'    => $digest,
				'files'     => count( $entries ),
				'entries'   => $entries,
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		) . "\n"
	);
	echo "wrote {$manifest}\n  ", count( $entries ), " entries, digest {$digest}\n";
	exit( 0 );
}

// --check
$have = json_decode( (string) @file_get_contents( $manifest ), true );
if ( ! is_array( $have ) || ! isset( $have['digest'], $have['entries'] ) ) {
	fwrite( STDERR, "vendor-digest: vendor-manifest.json is missing or unreadable\n" );
	fwrite( STDERR, "  (generate it deliberately: php bin/vendor-digest.php --write, then commit it)\n" );
	exit( 1 );
}
if ( $have['digest'] === $digest ) {
	echo "vendor ok: ", count( $entries ), " entries match vendor-manifest.json ({$digest})\n";
	exit( 0 );
}

$was     = (array) $have['entries'];
$added   = array_diff_key( $entries, $was );
$removed = array_diff_key( $was, $entries );
$changed = array();
foreach ( $entries as $rel => $meta ) {
	if ( isset( $was[ $rel ] ) && $was[ $rel ] !== $meta ) {
		$changed[] = $rel;
	}
}
fwrite( STDERR, "vendor-digest: vendor/ is not the tree this release recorded\n" );
fwrite( STDERR, '  recorded ' . $have['digest'] . "\n  found    {$digest}\n" );
foreach ( array( 'changed' => $changed, 'added' => array_keys( $added ), 'removed' => array_keys( $removed ) ) as $what => $list ) {
	foreach ( array_slice( $list, 0, 12 ) as $rel ) {
		fwrite( STDERR, "  {$what}: {$rel}\n" );
	}
	if ( count( $list ) > 12 ) {
		fwrite( STDERR, '  ' . $what . ': … and ' . ( count( $list ) - 12 ) . " more\n" );
	}
}
fwrite( STDERR, "  (if this is a deliberate dependency change: composer install, then\n" );
fwrite( STDERR, "   php bin/vendor-digest.php --write, and commit vendor-manifest.json)\n" );
exit( 1 );
