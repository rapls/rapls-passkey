<?php
/**
 * Help: the "What is a passkey?" snippet — details vs inline variants, the
 * optional learn-more link (filtered), and escaping.
 *
 *   php tests/smoke-help.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace {
	if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
	define( 'ABSPATH', __DIR__ . '/' );

	$GLOBALS['filters'] = array();

	function __( $s, $d = null ) { return $s; }
	function esc_html__( $s, $d = null ) { return $s; }
	function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
	function esc_url( $s ) { return $s; }
	function esc_url_raw( $s ) { return $s; }
	function apply_filters( $tag, $value, ...$args ) {
		if ( isset( $GLOBALS['filters'][ $tag ] ) ) {
			return call_user_func( $GLOBALS['filters'][ $tag ], $value, ...$args );
		}
		return $value;
	}

	require dirname( __DIR__ ) . '/src/Support/Help.php';

	use RaplsPasskey\Support\Help;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	// --- default details variant, no link -------------------------------------
	$d = Help::html();
	check( 'details variant uses <details>', false !== strpos( $d, '<details' ) );
	check( 'details variant has a summary', false !== strpos( $d, '<summary' ) && false !== strpos( $d, 'パスキーとは?' ) );
	check( 'includes the intro text', false !== strpos( $d, 'パスワード不要' ) );
	check( 'no learn-more link by default', false === strpos( $d, '<a ' ) );

	// --- inline variant --------------------------------------------------------
	$i = Help::html( 'inline' );
	check( 'inline variant is a paragraph', false !== strpos( $i, 'rapls-pk-help-inline' ) && false === strpos( $i, '<details' ) );

	// --- learn-more link via filter -------------------------------------------
	$GLOBALS['filters']['rapls_passkey_learn_more_url'] = function ( $v ) { return 'https://example.test/passkeys'; };
	$withLink = Help::html();
	check( 'filtered URL adds a learn-more link', false !== strpos( $withLink, 'https://example.test/passkeys' ) && false !== strpos( $withLink, '詳しく' ) );
	check( 'external link is rel/noopener', false !== strpos( $withLink, 'noopener' ) );
	unset( $GLOBALS['filters']['rapls_passkey_learn_more_url'] );

	// --- render() echoes -------------------------------------------------------
	ob_start();
	Help::render();
	$echoed = ob_get_clean();
	check( 'render() echoes the snippet', false !== strpos( $echoed, '<details' ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
