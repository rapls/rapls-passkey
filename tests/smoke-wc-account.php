<?php
/**
 * WooCommerceAccount: the "パスキー" account menu item is inserted before
 * Logout, and the endpoint registers as a WooCommerce query var.
 *
 *   php tests/smoke-wc-account.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Frontend {
	// Stand-in for the real (final) Shortcodes renderer.
	class Shortcodes {
		public function render_register( $atts ) { return '<div id="rapls-passkey-manage"></div>'; }
	}
}

namespace {
	define( 'ABSPATH', __DIR__ . '/' );

	function __( $s, $d = null ) { return $s; }
	function add_action() {}
	function add_filter() {}

	require dirname( __DIR__ ) . '/src/Integrations/WooCommerceAccount.php';

	use RaplsPasskey\Frontend\Shortcodes;
	use RaplsPasskey\Integrations\WooCommerceAccount;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}

	$wca = new WooCommerceAccount( new Shortcodes() );

	// --- menu item placement ---------------------------------------------------
	$items = array(
		'dashboard'       => 'Dashboard',
		'orders'          => 'Orders',
		'edit-account'    => 'Account details',
		'customer-logout' => 'Logout',
	);
	$out  = $wca->menu_item( $items );
	$keys = array_keys( $out );

	check( 'adds the passkeys menu item', isset( $out['rapls-passkeys'] ) );
	check( 'passkeys item comes before logout', array_search( 'rapls-passkeys', $keys, true ) < array_search( 'customer-logout', $keys, true ) );
	check( 'logout stays last', end( $keys ) === 'customer-logout' );
	check( 'existing items are preserved', isset( $out['dashboard'], $out['orders'], $out['edit-account'] ) );

	// Without a logout item, it is simply appended.
	$out2 = $wca->menu_item( array( 'dashboard' => 'Dashboard' ) );
	check( 'works without a logout item', isset( $out2['rapls-passkeys'] ) && count( $out2 ) === 2 );

	// --- query var -------------------------------------------------------------
	$vars = $wca->query_var( array( 'orders' => 'orders' ) );
	check( 'registers the endpoint query var', ( $vars['rapls-passkeys'] ?? null ) === 'rapls-passkeys' );
	check( 'preserves existing query vars', ( $vars['orders'] ?? null ) === 'orders' );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
