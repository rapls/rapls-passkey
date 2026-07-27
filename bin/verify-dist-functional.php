<?php
/**
 * Run the smoke suite against the code INSIDE a distribution ZIP.
 *
 *   php bin/verify-dist-functional.php ../rapls-passkey.zip [--tests /path/to/tests]
 *
 * bin/verify-dist.php checks the shape of the artifact — the scoped autoloader,
 * the prefixing, the third-party licences. This runs the behaviour: it extracts
 * the ZIP, drops the test suite next to the shipped `src/`, and executes it there,
 * so the classes under test are the ones the ZIP actually contains after
 * PHP-Scoper has rewritten it, not the ones in the source tree.
 *
 * Tests that name the bundled libraries directly (`\Webauthn\…`, the Composer
 * autoloader) cannot run inside a scoped artifact by construction — those symbols
 * are deliberately renamed. They are skipped, and named in the output, so the
 * report says what it did not cover.
 *
 * @package RaplsPasskey
 */

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.PHP.DevelopmentFunctions

if ( 'cli' !== PHP_SAPI ) {
	exit( 1 );
}

$argvv = $argv;
array_shift( $argvv );
$zip_path  = '';
$tests_dir = '';
$sibling   = '';
for ( $i = 0; $i < count( $argvv ); $i++ ) {
	if ( '--tests' === $argvv[ $i ] && isset( $argvv[ $i + 1 ] ) ) {
		$tests_dir = $argvv[ ++$i ];
		continue;
	}
	// Pro's suites require the free plugin's classes from a sibling directory.
	// Extracting that ZIP alongside means BOTH shipped artifacts are exercised.
	if ( '--sibling' === $argvv[ $i ] && isset( $argvv[ $i + 1 ] ) ) {
		$sibling = $argvv[ ++$i ];
		continue;
	}
	if ( '' === $zip_path ) {
		$zip_path = $argvv[ $i ];
	}
}

if ( '' === $zip_path || ! is_file( $zip_path ) ) {
	fwrite( STDERR, "usage: php bin/verify-dist-functional.php <plugin.zip> [--tests <dir>] [--sibling <other.zip>]\n" );
	exit( 2 );
}

$root = dirname( __DIR__ );
if ( '' === $tests_dir ) {
	$tests_dir = $root . '/tests';
}
if ( ! is_dir( $tests_dir ) ) {
	fwrite( STDERR, "tests directory not found: {$tests_dir}\n" );
	exit( 2 );
}

$slug = basename( $zip_path, '.zip' );
$work = sys_get_temp_dir() . '/rapls-distfn-' . bin2hex( random_bytes( 6 ) );
mkdir( $work, 0777, true );

register_shutdown_function(
	static function () use ( $work ) {
		$rm = static function ( string $dir ) use ( &$rm ) {
			foreach ( array_diff( (array) scandir( $dir ), array( '.', '..' ) ) as $entry ) {
				$path = $dir . '/' . $entry;
				is_dir( $path ) && ! is_link( $path ) ? $rm( $path ) : unlink( $path );
			}
			rmdir( $dir );
		};
		if ( is_dir( $work ) ) {
			$rm( $work );
		}
	}
);

$zip = new ZipArchive();
if ( true !== $zip->open( $zip_path ) ) {
	fwrite( STDERR, "cannot open {$zip_path}\n" );
	exit( 1 );
}
$zip->extractTo( $work );
$zip->close();

if ( '' !== $sibling && is_file( $sibling ) ) {
	$sib = new ZipArchive();
	if ( true === $sib->open( $sibling ) ) {
		$sib->extractTo( $work );
		$sib->close();
	}
}

$plugin = $work . '/' . $slug;
if ( ! is_dir( $plugin ) ) {
	fwrite( STDERR, "the ZIP does not contain a {$slug}/ directory\n" );
	exit( 1 );
}

// Put the suite where the tests expect to find it, next to the shipped src/.
$dest = $plugin . '/tests';
mkdir( $dest, 0777, true );
$copy = static function ( string $from, string $to ) use ( &$copy ) {
	foreach ( array_diff( (array) scandir( $from ), array( '.', '..' ) ) as $entry ) {
		$src = $from . '/' . $entry;
		$dst = $to . '/' . $entry;
		if ( is_dir( $src ) ) {
			@mkdir( $dst, 0777, true );
			$copy( $src, $dst );
			continue;
		}
		copy( $src, $dst );
	}
};
$copy( $tests_dir, $dest );

// A Pro suite may also require test helpers from the free plugin's tree. When the
// sibling artifact was extracted, give it its tests too — they are part of the
// harness, not of either shipped plugin.
if ( '' !== $sibling && is_dir( $work . '/rapls-passkey' ) && ! is_dir( $work . '/rapls-passkey/tests' ) ) {
	$free_tests = dirname( __DIR__ ) . '/tests';
	if ( is_dir( $free_tests ) ) {
		mkdir( $work . '/rapls-passkey/tests', 0777, true );
		$copy( $free_tests, $work . '/rapls-passkey/tests' );
	}
}

$php   = PHP_BINARY;
$files = glob( $dest . '/smoke-*.php' ) ?: array();
sort( $files );

$passed  = 0;
$failed  = 0;
$skipped = array();

echo "Functional check of the SHIPPED code: {$slug}\n";
echo '  ' . count( $files ) . " suites found in the extracted artifact\n\n";

foreach ( $files as $file ) {
	$name   = basename( $file );
	$source = (string) file_get_contents( $file );

	// A test that names the bundled libraries cannot run against a scoped build:
	// those symbols exist under a private prefix there, on purpose.
	if ( preg_match( '#(^|[^\\\\w])\\\\?Webauthn\\\\\\\\#', $source ) || false !== strpos( $source, "vendor/autoload.php" ) || false !== strpos( $source, 'ParagonIE\\' ) ) {
		$skipped[] = $name;
		continue;
	}

	$out  = array();
	$code = 0;
	exec( escapeshellarg( $php ) . ' ' . escapeshellarg( $file ) . ' 2>&1', $out, $code );
	$last = '';
	foreach ( $out as $line ) {
		if ( preg_match( '/(\d+) passed, (\d+) failed/', $line, $m ) ) {
			$last = $m[0];
		}
	}
	if ( 0 === $code ) {
		++$passed;
		echo "  PASS  {$name}  ({$last})\n";
		continue;
	}
	++$failed;
	echo "  FAIL  {$name}\n";
	foreach ( array_slice( $out, -12 ) as $line ) {
		echo '        ' . $line . "\n";
	}
}

echo "\n  {$passed} suites passed, {$failed} failed, " . count( $skipped ) . " skipped\n";
if ( array() !== $skipped ) {
	echo '  skipped (they name the bundled libraries, which are renamed in a build): ' . implode( ', ', $skipped ) . "\n";
}
exit( 0 === $failed ? 0 : 1 );
