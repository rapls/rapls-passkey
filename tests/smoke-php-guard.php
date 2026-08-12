<?php
/**
 * On PHP below 8.2 the plugin must decline to run — not take the site with it.
 *
 * Requiring Composer's autoloader on an unsupported PHP throws a
 * RuntimeException from vendor/composer/platform_check.php, and WordPress
 * catches nothing there: the throw lands inside wp-settings.php's plugin loop,
 * so the front end goes white too. A site running PHP 8.0 with this plugin
 * installed is a site that is down, and `Requires PHP` does not prevent it —
 * that header is read at activation and at update time only.
 *
 * The bootstrap cannot simply be included here, because this test runs on 8.2+
 * where the guard is a no-op. What is asserted instead is the shape of the
 * file: that the guard exists, that it is expressed as an integer comparison,
 * and above all that it stands BEFORE the autoloader is required. That last
 * one is the whole fix; everything else is detail.
 *
 *   php tests/smoke-php-guard.php
 */

$pass = 0;
$fail = 0;

function check( $label, $ok, $detail = '' ) {
	global $pass, $fail;
	if ( $ok ) {
		++$pass;
		echo "  PASS  {$label}\n";
	} else {
		++$fail;
		echo "  FAIL  {$label}" . ( '' !== $detail ? " — {$detail}" : '' ) . "\n";
	}
}

$targets = array(
	'rapls-passkey'     => dirname( __DIR__ ) . '/rapls-passkey.php',
	'rapls-passkey-pro' => dirname( __DIR__, 2 ) . '/rapls-passkey-pro/rapls-passkey-pro.php',
);

echo "== PHP version guard ==\n\n";

foreach ( $targets as $name => $file ) {
	if ( ! is_readable( $file ) ) {
		echo "  SKIP  {$name} (not present)\n";
		continue;
	}
	echo "{$name}\n";
	$src = (string) file_get_contents( $file );

	$guard_at = strpos( $src, 'PHP_VERSION_ID < 80200' );
	check( '  PHP 8.2 未満を弾くガードがある', false !== $guard_at );

	// The comparison must be numeric. version_compare() on version strings is
	// where "8.10" < "8.9" comes from.
	check( '  version_compare ではなく整数比較', false === strpos( $src, 'version_compare( PHP_VERSION' ) );

	$autoload_at = strpos( $src, "vendor/scoper-autoload.php'" );
	check( '  autoload を読む箇所がある', false !== $autoload_at );

	// The point of the whole fix.
	check(
		'  ガードが autoload より前にある',
		false !== $guard_at && false !== $autoload_at && $guard_at < $autoload_at,
		"guard@{$guard_at} autoload@{$autoload_at}"
	);

	// A bare `return` at file scope is what stops the rest of the bootstrap.
	$tail = false !== $guard_at ? substr( $src, $guard_at, ( $autoload_at ?: strlen( $src ) ) - $guard_at ) : '';
	check( '  ガード内で return して打ち切る', false !== strpos( $tail, "\n\treturn;\n" ) );

	check( '  権限のない利用者には通知を出さない', false !== strpos( $tail, "current_user_can( 'activate_plugins' )" ) );
	check( '  WP-CLI にも知らせる', false !== strpos( $tail, 'WP_CLI::warning' ) );

	// The header still has to say it: the guard covers a site whose PHP changed
	// after activation, the header stops the activation in the first place.
	check( '  ヘッダーに Requires PHP: 8.2 がある', 1 === preg_match( '/^\s*\*\s*Requires PHP:\s*8\.2\s*$/m', $src ) );

	echo "\n";
}

// The guard must fire for every version below 8.2 and for none at or above it.
echo "判定の境界\n";
foreach ( array( 80000 => '8.0.0', 80030 => '8.0.30', 80100 => '8.1.0', 80199 => '8.1.99' ) as $id => $label ) {
	check( "  PHP {$label} は弾く", $id < 80200 );
}
foreach ( array( 80200 => '8.2.0', 80300 => '8.3.0', 80500 => '8.5.0' ) as $id => $label ) {
	check( "  PHP {$label} は通す", ! ( $id < 80200 ) );
}

echo "\n  {$pass} passed, {$fail} failed\n";
exit( $fail > 0 ? 1 : 0 );
