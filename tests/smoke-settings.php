<?php
if ( ! defined( 'ABSPATH' ) && 'cli' !== PHP_SAPI ) { exit; } // Dev/CLI-only file; excluded from the distributed plugin.
/**
 * Settings accessor: defaults, merge, and reCAPTCHA activation logic.
 *
 *   php tests/smoke-settings.php
 *
 * @package RaplsPasskey
 */

// phpcs:disable

define( 'ABSPATH', __DIR__ . '/' );

$GLOBALS['__opt'] = array();
function get_option( $k, $d = false ) { return $GLOBALS['__opt'][ $k ] ?? $d; }

// apply_filters identity, with an optional forced override for the veto test.
function apply_filters( $tag, $value ) {
	if ( 'rapls_passkey_recaptcha_active' === $tag && isset( $GLOBALS['__force_recaptcha'] ) ) {
		return $GLOBALS['__force_recaptcha'];
	}
	return $value;
}

spl_autoload_register( function ( $class ) {
	$prefix = 'RaplsPasskey\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}
	$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
	if ( file_exists( $path ) ) {
		require $path;
	}
} );

use RaplsPasskey\Support\Settings;

$pass = 0;
$failc = 0;
function check( $label, $cond ) {
	global $pass, $failc;
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $label . "\n";
	$cond ? $pass++ : $failc++;
}

// Defaults when nothing stored.
check( 'audit enabled by default', Settings::audit_enabled() === true );
check( 'recaptcha inactive by default', Settings::recaptcha_active() === false );
check( 'threshold default 0.5', abs( Settings::recaptcha_threshold() - 0.5 ) < 0.0001 );

// Stored values merge over defaults.
$GLOBALS['__opt']['rapls_passkey_settings'] = array(
	'recaptcha_enabled'    => true,
	'recaptcha_site_key'   => 'SITE',
	'recaptcha_secret_key' => 'SECRET',
	'recaptcha_threshold'  => 0.7,
	'audit_enabled'        => false,
);
check( 'site key read from options', Settings::recaptcha_site_key() === 'SITE' );
check( 'threshold read from options', abs( Settings::recaptcha_threshold() - 0.7 ) < 0.0001 );
check( 'audit toggled off', Settings::audit_enabled() === false );
check( 'recaptcha active when enabled with both keys', Settings::recaptcha_active() === true );

// Missing a key keeps it inactive.
$GLOBALS['__opt']['rapls_passkey_settings']['recaptcha_secret_key'] = '';
check( 'recaptcha inactive without secret', Settings::recaptcha_active() === false );

// Filter veto.
$GLOBALS['__opt']['rapls_passkey_settings']['recaptcha_secret_key'] = 'SECRET';
$GLOBALS['__force_recaptcha'] = false;
check( 'recaptcha vetoable via filter', Settings::recaptcha_active() === false );

// Max passkeys (0 = unlimited by default).
check( 'max_passkeys unlimited by default', Settings::max_passkeys() === 0 );
$GLOBALS['__opt']['rapls_passkey_settings']['max_passkeys'] = 3;
check( 'max_passkeys read from options', Settings::max_passkeys() === 3 );
$GLOBALS['__opt']['rapls_passkey_settings']['max_passkeys'] = -5;
check( 'max_passkeys clamped to 0', Settings::max_passkeys() === 0 );

// WebAuthn ceremony tuning — defaults.
check( 'timeout default 60000ms', Settings::webauthn_timeout() === 60000 );
check( 'user verification default preferred', Settings::webauthn_user_verification() === 'preferred' );
check( 'attachment default any (null)', Settings::webauthn_attachment() === null );

// From options (seconds stored, milliseconds returned).
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_timeout']           = 30;
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_user_verification'] = 'required';
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_attachment']        = 'platform';
check( 'timeout from options (s -> ms)', Settings::webauthn_timeout() === 30000 );
check( 'user verification from options', Settings::webauthn_user_verification() === 'required' );
check( 'attachment from options', Settings::webauthn_attachment() === 'platform' );

// 0 seconds => library default (null).
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_timeout'] = 0;
check( 'timeout 0 means library default (null)', Settings::webauthn_timeout() === null );

// Invalid stored values fall back to safe defaults.
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_user_verification'] = 'bogus';
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_attachment']        = 'bogus';
check( 'invalid UV falls back to preferred', Settings::webauthn_user_verification() === 'preferred' );
check( 'invalid attachment falls back to any (null)', Settings::webauthn_attachment() === null );

// Hints: default empty, validated subset, order preserved, invalid dropped.
unset( $GLOBALS['__opt']['rapls_passkey_settings']['webauthn_hints'] );
check( 'hints default empty', Settings::webauthn_hints() === array() );
$GLOBALS['__opt']['rapls_passkey_settings']['webauthn_hints'] = array( 'hybrid', 'bogus', 'security-key' );
check( 'hints keep only valid values, in order', Settings::webauthn_hints() === array( 'hybrid', 'security-key' ) );

echo "\n  {$pass} passed, {$failc} failed\n";
exit( $failc === 0 ? 0 : 1 );
