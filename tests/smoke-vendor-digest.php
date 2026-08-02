<?php
/**
 * The vendor gate, on trees this test builds itself.
 *
 * V84-01 added a recorded digest of vendor/; V85-01 was that bin/build-dist.sh
 * consulted it only when vendor/ already existed, on the reasoning that Composer
 * had just created it from composer.lock. composer.lock pins which packages and
 * which references — not the bytes on disk, not the executable bits, not a file
 * a package ships that the lock never names, and not what a different Composer
 * version generates. Provenance was standing in for content, which is the
 * substitution V84-01 existed to remove.
 *
 * The build gate is unconditional now, and this covers the rule it applies. No
 * network and no Composer: a synthetic vendor/ is enough to show what the digest
 * does and does not notice, and it runs on every machine that runs the suite.
 * The clean-checkout cases — install from the lock and compare — need the real
 * thing and are measured in the release harness instead.
 *
 * Run: php tests/smoke-vendor-digest.php
 *
 * @package RaplsPasskey
 */

$pass  = 0;
$failc = 0;
function check( $label, $cond, $detail = '' ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . ( ! $cond && '' !== $detail ? ' — ' . $detail : '' ) . "\n";
	$cond ? $pass++ : $failc++;
}
function finish() {
	global $pass, $failc;
	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( 0 === $failc ? 0 : 1 );
}

$tool = dirname( __DIR__ ) . '/bin/vendor-digest.php';
if ( ! is_file( $tool ) ) {
	echo "  SKIP  bin/vendor-digest.php is not here (distribution)\n\n  0 passed, 0 failed, 1 skipped\n";
	exit( 0 );
}

$root = sys_get_temp_dir() . '/rapls-vd-' . bin2hex( random_bytes( 4 ) );
mkdir( $root . '/vendor/acme/lib/src', 0777, true );
mkdir( $root . '/vendor/composer', 0777, true );

function put( $path, $body, $mode = 0644 ) {
	file_put_contents( $path, $body );
	chmod( $path, $mode );
}

put( $root . '/vendor/autoload.php', "<?php\nrequire __DIR__.'/composer/autoload_real.php';\nreturn ComposerAutoloaderInit0123456789abcdef0123456789abcdef::getLoader();\n" );
put( $root . '/vendor/composer/autoload_real.php', "<?php\nclass ComposerAutoloaderInit0123456789abcdef0123456789abcdef {}\n" );
put( $root . '/vendor/composer/autoload_static.php', "<?php\nclass ComposerStaticInit0123456789abcdef0123456789abcdef {}\n" );
put( $root . '/vendor/composer/installed.php', "<?php return array('root' => array('reference' => '" . str_repeat( 'a', 40 ) . "'));\n" );
put( $root . '/vendor/composer/installed.json', json_encode( array( 'packages' => array( array( 'name' => 'acme/lib', 'reference' => str_repeat( 'b', 40 ) ) ) ) ) );
put( $root . '/vendor/acme/lib/src/Thing.php', "<?php\nclass Thing { public function run() { return 1; } }\n" );
put( $root . '/vendor/acme/lib/LICENSE', "MIT\n" );

$run = function ( $args ) use ( $tool, $root ) {
	$out = array();
	$rc  = 0;
	exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $tool ) . ' --root=' . escapeshellarg( $root ) . ' ' . $args . ' 2>&1', $out, $rc );
	return array( 'rc' => $rc, 'out' => implode( "\n", $out ) );
};

// Recorded once, deliberately — as a release does.
$w = $run( '--write' );
check( 'the tree can be recorded', 0 === $w['rc'] && is_file( $root . '/vendor-manifest.json' ), $w['out'] );
$c = $run( '--check' );
check( 'and the unchanged tree matches it', 0 === $c['rc'], $c['out'] );

// --- What it must notice -----------------------------------------------------
$cases = array(
	'a package file edited' => function () use ( $root ) {
		file_put_contents( $root . '/vendor/acme/lib/src/Thing.php', "<?php\nclass Thing { public function run() { return 2; } }\n" );
	},
	'a file added that no package ships' => function () use ( $root ) {
		file_put_contents( $root . '/vendor/acme/lib/src/Extra.php', "<?php // stowaway\n" );
	},
	'a file removed' => function () use ( $root ) {
		unlink( $root . '/vendor/acme/lib/LICENSE' );
	},
	'a file made executable' => function () use ( $root ) {
		chmod( $root . '/vendor/acme/lib/src/Thing.php', 0755 );
	},
	'a symlink pointed somewhere else' => function () use ( $root ) {
		@symlink( '/etc/passwd', $root . '/vendor/acme/lib/link' );
	},
	'the autoloader given an extra statement' => function () use ( $root ) {
		file_put_contents( $root . '/vendor/autoload.php', "<?php\neval('1');\n", FILE_APPEND );
	},
	'installed.php given code beyond its reference' => function () use ( $root ) {
		file_put_contents( $root . '/vendor/composer/installed.php', "// added\n", FILE_APPEND );
	},
);
$snapshot = array();
foreach ( array( 'vendor/acme/lib/src/Thing.php', 'vendor/autoload.php', 'vendor/composer/installed.php', 'vendor/acme/lib/LICENSE' ) as $rel ) {
	$snapshot[ $rel ] = array( file_get_contents( $root . '/' . $rel ), fileperms( $root . '/' . $rel ) & 0777 );
}
$missed = array();
foreach ( $cases as $label => $mutate ) {
	$mutate();
	$r = $run( '--check' );
	if ( 0 === $r['rc'] ) {
		$missed[] = $label;
	}
	// Put everything back.
	foreach ( $snapshot as $rel => $was ) {
		put( $root . '/' . $rel, $was[0], $was[1] );
	}
	@unlink( $root . '/vendor/acme/lib/src/Extra.php' );
	@unlink( $root . '/vendor/acme/lib/link' );
}
check( 'every change to the tree is refused' . ( $missed ? ' — missed: ' . implode( '; ', $missed ) : '' ), array() === $missed );
$c = $run( '--check' );
check( 'and the restored tree matches again', 0 === $c['rc'], $c['out'] );

// --- What it must NOT notice -------------------------------------------------
//
// Two things move for reasons that are not content, and a manifest that trips on
// them is a manifest nobody can keep — which is how a check ends up deleted.
$ok = array();
// Composer mints the autoloader's class name per installation.
foreach ( array( 'vendor/autoload.php', 'vendor/composer/autoload_real.php', 'vendor/composer/autoload_static.php' ) as $rel ) {
	$was = file_get_contents( $root . '/' . $rel );
	file_put_contents( $root . '/' . $rel, str_replace( '0123456789abcdef0123456789abcdef', 'fedcba9876543210fedcba9876543210', $was ) );
}
$r = $run( '--check' );
$ok['a re-minted autoloader class name'] = ( 0 === $r['rc'] );
// And the root package's own git reference changes on every commit.
file_put_contents( $root . '/vendor/composer/installed.php', "<?php return array('root' => array('reference' => '" . str_repeat( 'c', 40 ) . "'));\n" );
$r = $run( '--check' );
$ok['the root commit recorded by Composer'] = ( 0 === $r['rc'] );
$tripped = array_keys( array_filter( $ok, static function ( $v ) { return ! $v; } ) );
check( 'and the two things that move for no reason of content are allowed' . ( $tripped ? ' — tripped on: ' . implode( '; ', $tripped ) : '' ), array() === $tripped );

// But the same files are still covered otherwise.
file_put_contents( $root . '/vendor/composer/autoload_static.php', "<?php\nclass ComposerStaticInitfedcba9876543210fedcba9876543210 { const X = 1; }\n" );
$r = $run( '--check' );
check( 'a real change to those same files is still refused', 0 !== $r['rc'] );

// --- The gate in the build script is not conditional (V85-01) ----------------
$build = dirname( __DIR__ ) . '/bin/build-dist.sh';
if ( is_file( $build ) ) {
	$src = (string) file_get_contents( $build );
	check( 'the build runs the check', false !== strpos( $src, 'vendor-digest.php" --check' ) );
	check(
		'and does not skip it for a checkout that had no vendor/ (V85-01)',
		false === strpos( $src, 'VENDOR_PREEXISTING' )
	);
}

// Clean up.
$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST );
foreach ( $it as $p ) {
	$p->isDir() && ! $p->isLink() ? @rmdir( $p->getPathname() ) : @unlink( $p->getPathname() );
}
@rmdir( $root );

finish();
