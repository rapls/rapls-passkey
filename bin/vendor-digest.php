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
$vendor   = $root . '/vendor';
$manifest = $root . '/vendor-manifest.json';
$mode     = '';
foreach ( array_slice( $argv, 1 ) as $a ) {
	if ( in_array( $a, array( '--write', '--check', '--print' ), true ) ) {
		$mode = substr( $a, 2 );
	}
}
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
			// Directories are recorded so an empty one cannot appear or vanish
			// unnoticed; they have no contents of their own.
			$out[ $rel ] = 'dir:0:-';
			continue;
		}
		// Only the executable bit matters: the rest of the mode varies with the
		// umask of whoever ran Composer and says nothing about the bytes.
		$exec        = ( fileperms( $path ) & 0111 ) ? '1' : '0';
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
