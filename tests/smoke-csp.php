<?php
/**
 * CSP hygiene: the plugin must not ship inline event handlers or inject a
 * Content-Security-Policy header (a passkey plugin breaking the site CSP is a
 * documented competitor failure). Scripts pass config via wp_localize_script so
 * CSP-nonce plugins can cover them.
 *
 *   php tests/smoke-csp.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

$root = dirname( __DIR__ );

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
	return (bool) $cond;
}

/**
 * Recursively collect files with the given extensions.
 */
function collect( string $dir, array $exts ): array {
	if ( ! is_dir( $dir ) ) {
		return array();
	}
	$out = array();
	$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
	foreach ( $it as $file ) {
		$ext = strtolower( $file->getExtension() );
		if ( in_array( $ext, $exts, true ) ) {
			$out[] = $file->getPathname();
		}
	}
	return $out;
}

$php_files = collect( $root . '/src', array( 'php' ) );
$js_files  = collect( $root . '/assets', array( 'js' ) );
$all       = array_merge( $php_files, $js_files );

// 1) No inline DOM event-handler attributes in rendered markup.
$inline_handler = '/\son(click|load|error|submit|change|input|keyup|keydown|mouseover)\s*=\s*["\']/i';
$offenders = array();
foreach ( $all as $f ) {
	$src = (string) file_get_contents( $f );
	if ( preg_match( $inline_handler, $src ) ) {
		$offenders[] = basename( $f );
	}
}
check( 'no inline on* event-handler attributes', $offenders === array() ) or print( '         offenders: ' . implode( ', ', $offenders ) . "\n" );

// 2) The plugin never sets a Content-Security-Policy header.
$csp_offenders = array();
foreach ( $php_files as $f ) {
	$src = (string) file_get_contents( $f );
	if ( stripos( $src, 'Content-Security-Policy' ) !== false ) {
		$csp_offenders[] = basename( $f );
	}
}
check( 'no Content-Security-Policy header injection', $csp_offenders === array() ) or print( '         offenders: ' . implode( ', ', $csp_offenders ) . "\n" );

// 3) Front-end JS binds via addEventListener (sanity that handlers exist in JS).
$frontend = (string) file_get_contents( $root . '/assets/frontend.js' );
check( 'frontend.js wires handlers via addEventListener', strpos( $frontend, 'addEventListener' ) !== false );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
