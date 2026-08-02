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

/*
 * Which suites cannot run inside a scoped build, by name. A FIXED list, not a
 * pattern: a pattern would quietly excuse any new file that happened to mention
 * the bundled libraries, and "skipped" would grow without anyone deciding it
 * should. Adding a name here is a deliberate act, and an unexpected skip fails.
 */
$allowed_skips = array(
	// smoke-dist-inputs reads the build script and the ignore files, none of which
	// is in a plugin artifact — source-only, like smoke-docs-endpoints (V71-01).
	'rapls-passkey'     => array( 'smoke-assertion.php', 'smoke-registration.php', 'smoke-wiring.php', 'smoke-dist-inputs.php' ),
	// smoke-mds names the bundled library; the other two exercise operator tooling
	// under tools/, which is deliberately NOT part of the plugin artifact — it is
	// shipped in the verification bundle instead, where the source-tree run covers
	// both. Skipping them here says that, rather than hiding it.
	// smoke-docs-endpoints reads the licence server's router and E2E-TESTING.md,
	// neither of which is in a plugin artifact — it is a SOURCE-ONLY suite, and
	// it said so by asserting nothing here. Counted honestly as a skip now
	// (V69-04): "0 passed, 0 failed" is not a pass, and letting one through is
	// the same "green because it never ran" the doc checks were added to stop.
	// smoke-runbook-rq runs the runbook's own helper against a loopback (V79-01);
	// the document is not in a plugin artifact either, so it is source-only for
	// the same reason and named here for the same reason.
	'rapls-passkey-pro' => array( 'smoke-mds.php', 'smoke-rotation-check.php', 'smoke-seen-versions.php', 'smoke-license-store.php', 'smoke-license-api.php', 'smoke-docs-endpoints.php', 'smoke-dist-inputs.php', 'smoke-runbook-rq.php' ),
);
$expected_skips = $allowed_skips[ $slug ] ?? array();

$php   = PHP_BINARY;
$files = glob( $dest . '/smoke-*.php' ) ?: array();
sort( $files );

$passed  = 0;
$failed  = 0;
$skipped = array();

echo "Functional check of the SHIPPED code: {$slug}\n";
echo '  ' . count( $files ) . " suites found in the extracted artifact\n\n";

// No files means the suite did not run — a wrong path, a failed copy, a renamed
// directory. That is not a pass.
if ( array() === $files ) {
	fwrite( STDERR, "no smoke-*.php found in the extracted artifact — refusing to report success\n" );
	exit( 1 );
}

foreach ( $files as $file ) {
	$name   = basename( $file );
	$source = (string) file_get_contents( $file );

	// A test that names the bundled libraries cannot run against a scoped build:
	// those symbols exist under a private prefix there, on purpose. Only the names
	// on the list above may be skipped for that reason — anything else runs, and
	// fails if it cannot.
	if ( in_array( $name, $expected_skips, true ) ) {
		$skipped[] = $name;
		continue;
	}

	$out  = array();
	$code = 0;
	exec( escapeshellarg( $php ) . ' ' . escapeshellarg( $file ) . ' 2>&1', $out, $code );

	// The summary line is required, and it must say zero failures: an exit code of
	// 0 alone would let a file that asserted nothing — or that died before its last
	// line — count as a pass.
	$summary      = '';
	$fails        = null;
	$asserts      = null;
	$self_skipped = 0;
	foreach ( $out as $line ) {
		if ( preg_match( '/(\d+) passed, (\d+) failed(?:, (\d+) skipped)?/', $line, $m ) ) {
			$summary      = $m[0];
			$asserts      = (int) $m[1];
			$fails        = (int) $m[2];
			$self_skipped = isset( $m[3] ) ? (int) $m[3] : 0;
		}
	}

	$reason = '';
	if ( 0 !== $code ) {
		$reason = "exit code {$code}";
	} elseif ( '' === $summary ) {
		$reason = 'no assertion summary (the file asserted nothing, or stopped early)';
	} elseif ( 0 !== $fails ) {
		$reason = $summary;
	} elseif ( 0 === $asserts ) {
		// A FILE THAT ASSERTED NOTHING IS NOT A FILE THAT PASSED (V69-04). The
		// summary was read for FAILURES only, so a suite that skipped itself —
		// because what it tests is not in a plugin artifact — was counted as a
		// passing suite on the strength of "0 failed". That is the same "green
		// because it never ran" the documentation checks were added to stop. A
		// suite that cannot run here belongs on the fixed list above, where
		// adding it is a deliberate act and an unexpected skip still fails.
		$reason = 'asserted nothing'
			. ( $self_skipped > 0 ? " ({$self_skipped} skipped inside)" : '' )
			. ' — put it on the fixed skip list if it cannot run here';
	}

	if ( '' === $reason ) {
		++$passed;
		echo "  PASS  {$name}  ({$summary})\n";
		continue;
	}
	++$failed;
	echo "  FAIL  {$name}  ({$reason})\n";
	foreach ( array_slice( $out, -12 ) as $line ) {
		echo '        ' . $line . "\n";
	}
}

echo "\n  {$passed} suites passed, {$failed} failed, " . count( $skipped ) . " skipped\n";
if ( array() !== $skipped ) {
	echo '  skipped (named on the fixed list; they need the bundled libraries under their original names, or tooling the plugin artifact does not carry): ' . implode( ', ', $skipped ) . "\n";
}

// The skips must be EXACTLY the ones declared. A suite that was expected to be
// skipped but is missing means the file is gone; anything skipped that is not on
// the list cannot happen by construction, and is asserted anyway.
sort( $skipped );
$declared = $expected_skips;
sort( $declared );
if ( $skipped !== $declared ) {
	echo '  UNEXPECTED SKIP SET: expected [' . implode( ', ', $declared ) . '], got [' . implode( ', ', $skipped ) . "]\n";
	++$failed;
}

// And every file found must have been accounted for.
if ( count( $files ) !== $passed + $failed + count( $skipped ) ) {
	echo "  SUITE COUNT MISMATCH: " . count( $files ) . ' found, ' . ( $passed + $failed + count( $skipped ) ) . " accounted for\n";
	++$failed;
}

exit( 0 === $failed ? 0 : 1 );
