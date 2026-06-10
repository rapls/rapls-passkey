<?php
/**
 * LoginForms: third-party login-form integrations — hook registration, the
 * once-per-request guard, logged-out gating, the per-integration enable filter,
 * and the hook-map filter.
 *
 *   php tests/smoke-login-forms.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\Frontend {
	// Stand-in for the real (final) Shortcodes renderer.
	class Shortcodes {
		public $calls = 0;
		public function render_login( $atts ) { $this->calls++; return '<button id="rapls-passkey-login-btn">passkey</button>'; }
	}
}

namespace {
	define( 'ABSPATH', __DIR__ . '/' );

	$GLOBALS['__actions']     = array();
	$GLOBALS['__filters']     = array();
	$GLOBALS['__logged_in']   = false;

	function add_action( $hook, $cb, $priority = 10, $args = 1 ) { $GLOBALS['__actions'][ $hook ] = $cb; }
	function is_user_logged_in() { return $GLOBALS['__logged_in']; }
	function esc_attr( $s ) { return $s; }
	function esc_html__( $s, $d = null ) { return $s; }
	function apply_filters( $tag, $value, ...$args ) {
		if ( isset( $GLOBALS['__filters'][ $tag ] ) ) {
			return call_user_func( $GLOBALS['__filters'][ $tag ], $value, ...$args );
		}
		return $value;
	}

	require dirname( __DIR__ ) . '/src/Integrations/LoginForms.php';

	use RaplsPasskey\Frontend\Shortcodes;
	use RaplsPasskey\Integrations\LoginForms;

	$pass = 0; $failc = 0;
	function check( $label, $cond ) {
		global $pass, $failc;
		echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
		$cond ? $pass++ : $failc++;
	}
	function fire( $hook ) {
		ob_start();
		if ( isset( $GLOBALS['__actions'][ $hook ] ) ) {
			call_user_func( $GLOBALS['__actions'][ $hook ] );
		}
		return ob_get_clean();
	}

	$sc = new Shortcodes();
	$lf = new LoginForms( $sc );
	$lf->register();

	// --- registration ----------------------------------------------------------
	check( 'hooks Ultimate Member', isset( $GLOBALS['__actions']['um_after_login_fields'] ) );
	check( 'hooks MemberPress', isset( $GLOBALS['__actions']['mepr-login-form-before-submit'] ) );
	check( 'hooks Easy Digital Downloads', isset( $GLOBALS['__actions']['edd_login_fields_after'] ) );

	// --- render once, logged out ----------------------------------------------
	$out = fire( 'um_after_login_fields' );
	check( 'renders the passkey button', false !== strpos( $out, 'rapls-passkey-login-btn' ) );
	check( 'wraps it with an integration class', false !== strpos( $out, 'rapls-pk-integration-ultimate_member' ) );

	// Second fire of the same hook: guarded, no output, renderer not called again.
	$before = $sc->calls;
	$out2   = fire( 'um_after_login_fields' );
	check( 'second fire is guarded (no output)', '' === $out2 );
	check( 'renderer not called twice', $sc->calls === $before );

	// A different integration still renders independently.
	$outEdd = fire( 'edd_login_fields_after' );
	check( 'a different integration renders', false !== strpos( $outEdd, 'rapls-pk-integration-easy_digital_downloads' ) );

	// --- logged-in gating ------------------------------------------------------
	$lf2 = new LoginForms( new Shortcodes() );
	$lf2->register();
	$GLOBALS['__logged_in'] = true;
	check( 'nothing renders when logged in', '' === fire( 'mepr-login-form-before-submit' ) );
	$GLOBALS['__logged_in'] = false;

	// --- per-integration enable filter ----------------------------------------
	$lf3 = new LoginForms( new Shortcodes() );
	$lf3->register();
	$GLOBALS['__filters']['rapls_passkey_login_integration_enabled'] = function ( $v, $key ) {
		return 'memberpress' === $key ? false : $v;
	};
	check( 'disabled integration renders nothing', '' === fire( 'mepr-login-form-before-submit' ) );
	check( 'other integrations still render', false !== strpos( fire( 'edd_login_fields_after' ), 'passkey' ) );
	unset( $GLOBALS['__filters']['rapls_passkey_login_integration_enabled'] );

	// --- hook-map filter -------------------------------------------------------
	$GLOBALS['__filters']['rapls_passkey_login_form_hooks'] = function ( $hooks ) {
		$hooks['my_custom_form'] = 'my_custom_login_hook';
		return $hooks;
	};
	$lf4 = new LoginForms( new Shortcodes() );
	$lf4->register();
	check( 'hook-map filter adds a custom integration', isset( $GLOBALS['__actions']['my_custom_login_hook'] ) );

	echo "\n  {$pass} passed, {$failc} failed\n";
	exit( $failc === 0 ? 0 : 1 );
}
