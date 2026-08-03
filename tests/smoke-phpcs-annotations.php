<?php
/**
 * Every phpcs annotation in shipped PHP must survive the distribution build.
 *
 * The plugin is shipped through php-scoper, which re-prints every file from its
 * parsed form. A comment at the END of a line is not attached to the statement
 * on that line: the printer emits it on the line AFTER. So
 *
 *     echo $this->to_csv( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
 *
 * arrives in the package as two lines, with the annotation now sitting under the
 * statement it was meant to cover — suppressing nothing, and silencing whatever
 * happens to be on the next line instead. Every one of the plugin's annotations
 * was written that way, so the source passed Plugin Check while the thing users
 * install did not: 18 errors that were invisible from the repository.
 *
 * A comment on its OWN line is a leading comment, and the printer keeps it where
 * it is. Inside inline-HTML templates even that is not enough — the printer
 * expands a template PHP block across several lines, pushing the statement out of the
 * annotation's one-line reach — so those need a phpcs:disable/enable range.
 *
 * This test reads the rule off the source: an annotation must be alone on its
 * line, and inside a template it must be a range. It cannot see the built
 * package (php-scoper is not available here), so it checks the property that
 * makes the built package correct.
 *
 * Run: php tests/smoke-phpcs-annotations.php
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

$root = dirname( __DIR__ );

/**
 * Every PHP file that goes into the package.
 *
 * @param string $root Plugin root.
 * @return array<int,string> Absolute paths.
 */
function shipped_php( string $root ): array {
	$files = array();
	foreach ( array( 'uninstall.php', 'rapls-passkey.php' ) as $one ) {
		if ( is_file( $root . '/' . $one ) ) {
			$files[] = $root . '/' . $one;
		}
	}
	$dir = $root . '/src';
	if ( is_dir( $dir ) ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( $file->isFile() && 'php' === $file->getExtension() ) {
				$files[] = $file->getPathname();
			}
		}
	}
	sort( $files );
	return $files;
}

$files = shipped_php( $root );
check( 'the shipped PHP files were found', count( $files ) > 10, count( $files ) . ' file(s)' );

$trailing = array();
$inline   = array();
$total    = 0;

foreach ( $files as $path ) {
	$rel   = ltrim( str_replace( $root, '', $path ), '/' );
	$lines = explode( "\n", (string) file_get_contents( $path ) );
	foreach ( $lines as $i => $line ) {
		if ( ! preg_match( '#//\s*phpcs:(ignore|disable|enable)\b#', $line, $m ) ) {
			continue;
		}
		++$total;
		$where  = $rel . ':' . ( $i + 1 );
		$before = substr( $line, 0, (int) strpos( $line, '//' ) );

		// Inside a template the annotation lives in its own template PHP block. An
		// ignore there reaches one line, and the printer moves that line away.
		if ( false !== strpos( $line, '<' . '?php' ) ) {
			if ( 'ignore' === $m[1] ) {
				$inline[] = $where;
			}
			continue;
		}

		// Anywhere else: nothing but whitespace may precede the annotation.
		if ( '' !== trim( $before ) ) {
			$trailing[] = $where;
		}
	}
}

check( 'the source carries phpcs annotations to check', $total > 0, "found {$total}" );
check(
	'no annotation trails a statement (the build would move it off the line it covers)',
	array() === $trailing,
	count( $trailing ) . ': ' . implode( ', ', array_slice( $trailing, 0, 6 ) )
);
check(
	'template annotations are disable/enable ranges, not one-line ignores',
	array() === $inline,
	count( $inline ) . ': ' . implode( ', ', array_slice( $inline, 0, 6 ) )
);

// A range has to be closed, or it silences the rest of the file.
$unbalanced = array();
foreach ( $files as $path ) {
	$body    = (string) file_get_contents( $path );
	$open    = preg_match_all( '#//\s*phpcs:disable\b#', $body );
	$close   = preg_match_all( '#//\s*phpcs:enable\b#', $body );
	if ( $open !== $close ) {
		$unbalanced[] = ltrim( str_replace( $root, '', $path ), '/' ) . " ({$open} disable / {$close} enable)";
	}
}
check(
	'every phpcs:disable is closed by a phpcs:enable',
	array() === $unbalanced,
	implode( ', ', $unbalanced )
);

// Direct-access protection has to be findable in the SHIPPED file, not merely
// present in the source. Two things get in the way, and both were live:
//
//   * Plugin Check reads only the first 50 lines (Direct_File_Access_Check), so a
//     guard under a long block of `use` statements is not seen — which is how
//     Pro's src/Pro.php came to be reported while carrying the standard guard.
//   * php-scoper fully qualifies the call, so `if ( ! defined( 'ABSPATH' ) )`
//     ships as `if (!\defined('ABSPATH'))`. The checker's pattern for that form
//     requires `defined` immediately after `!`, and the backslash breaks it —
//     every scoped file in both plugins was reported as unprotected.
//
// `defined( 'ABSPATH' ) || exit;` is matched by a pattern with no `!` in it, so
// the leading backslash is harmless. That is the form required here.
$late = array();
foreach ( $files as $path ) {
	$body      = (string) file_get_contents( $path );
	$body      = (string) preg_replace( '/^<\?php\s*/i', '', $body );
	$beginning = implode( "\n", array_slice( explode( "\n", $body ), 0, 50 ) );
	$stripped  = (string) preg_replace( '#/\*.*?\*/#s', '', $beginning );
	$stripped  = (string) preg_replace( '#//.*$#m', '', $stripped );

	if ( ! preg_match( "/defined\s*\(\s*['\"](?:ABSPATH|WPINC)['\"]\s*\)\s*(?:\|\||or)\s*(?:exit|die)\s*;/i", $stripped ) ) {
		$late[] = ltrim( str_replace( $root, '', $path ), '/' );
	}
}
check(
	'every shipped file guards direct access, in the form that survives the build, within its first 50 lines',
	array() === $late,
	count( $late ) . ': ' . implode( ', ', array_slice( $late, 0, 6 ) )
);

finish();
