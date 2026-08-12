<?php
/**
 * The review request must be shown at most once, and only when every condition
 * holds. Each of those conditions is a way to annoy someone who did not ask to
 * be interrupted, so each one is asserted here rather than assumed.
 *
 *   php tests/smoke-review-prompt.php
 */

namespace {

define( 'ABSPATH', __DIR__ );
define( 'DAY_IN_SECONDS', 86400 );

$GLOBALS['opts']    = array();
$GLOBALS['caps']    = true;
$GLOBALS['screen']  = null;
$GLOBALS['filters'] = array();

function get_option( $k, $d = false ) {
	return array_key_exists( $k, $GLOBALS['opts'] ) ? $GLOBALS['opts'][ $k ] : $d;
}
function update_option( $k, $v, $a = null ) {
	unset( $a );
	$GLOBALS['opts'][ $k ] = $v;
	return true;
}
function current_user_can( $c ) {
	unset( $c );
	return (bool) $GLOBALS['caps'];
}
function get_current_screen() {
	return $GLOBALS['screen'];
}
function apply_filters( $tag, $value ) {
	return array_key_exists( $tag, $GLOBALS['filters'] ) ? $GLOBALS['filters'][ $tag ] : $value;
}
function add_action() {}
function esc_html_e( $s ) {
	echo $s; // phpcs:ignore
}
function esc_url( $u ) {
	return $u;
}
function add_query_arg( $k, $v ) {
	return "?{$k}={$v}";
}
function wp_nonce_url( $u ) {
	return $u . '&_wpnonce=x';
}
function sanitize_key( $s ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $s ) );
}
function wp_unslash( $s ) {
	return $s;
}
function check_admin_referer() {
	return true;
}
function remove_query_arg() {
	return '/wp-admin/';
}
// handle_dismiss() exits after redirecting, which would end the test run at
// the first case. Turn the redirect into something catchable instead.
class Redirected extends \Exception {}
function wp_add_inline_script( $handle, $js ) {
	unset( $handle );
	$GLOBALS['inline'] = $js;
	return true;
}
function wp_json_encode( $v ) {
	return json_encode( $v );
}
function admin_url( $p = '' ) {
	return '/wp-admin/' . $p;
}
function wp_create_nonce( $a = '' ) {
	unset( $a );
	return 'nonce123';
}
function check_ajax_referer() {
	return true;
}
function wp_send_json_success() {
	throw new Redirected( 'json-ok' );
}
function wp_send_json_error() {
	throw new Redirected( 'json-err' );
}
function wp_safe_redirect() {
	throw new Redirected( 'safe' );
}
function wp_redirect() {
	throw new Redirected( 'external' );
}

class Screen {
	public function __construct( public string $id ) {}
}

}

// Minimal stand-ins for the two collaborators.
namespace RaplsPasskey\Credentials {
	class CredentialRepository {
		public int $n = 1;
		public function count_all( string $s = '' ): int {
			unset( $s );
			return $this->n;
		}
	}
}

namespace RaplsPasskey\Admin {
	class CredentialsPage {
		public const SLUG = 'rapls-passkey-credentials';
	}
}

namespace {

require __DIR__ . '/../src/Admin/ReviewPrompt.php';

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

$repo = new \RaplsPasskey\Credentials\CredentialRepository();

/** Does the notice render under the current state? */
function shows( $repo ): bool {
	ob_start();
	( new \RaplsPasskey\Admin\ReviewPrompt( $repo ) )->render();
	return '' !== trim( (string) ob_get_clean() );
}

/** The state in which it SHOULD appear. */
function ready() {
	$GLOBALS['opts'] = array(
		'rapls_passkey_activated_at' => gmdate( 'Y-m-d H:i:s', time() - ( 8 * DAY_IN_SECONDS ) ),
	);
	$GLOBALS['caps']    = true;
	$GLOBALS['screen']  = new Screen( 'settings_page_rapls-passkey' );
	$GLOBALS['filters'] = array();
}

echo "== rapls-passkey: review request ==\n\n";

ready();
check( 'すべての条件が揃えば表示する', shows( $repo ) );

ready();
$GLOBALS['screen'] = new Screen( 'users_page_rapls-passkey-credentials' );
check( 'パスキー一覧画面でも表示する', shows( $repo ) );

ready();
$GLOBALS['opts']['rapls_passkey_activated_at'] = gmdate( 'Y-m-d H:i:s', time() - ( 6 * DAY_IN_SECONDS ) );
check( '7 日未満では表示しない', ! shows( $repo ) );

ready();
$repo->n = 0;
check( 'パスキーが 1 件も無ければ表示しない', ! shows( $repo ) );
$repo->n = 1;

ready();
$GLOBALS['screen'] = new Screen( 'dashboard' );
check( 'ダッシュボードには出さない', ! shows( $repo ) );

ready();
$GLOBALS['screen'] = new Screen( 'plugins' );
check( 'プラグイン一覧には出さない', ! shows( $repo ) );

ready();
$GLOBALS['screen'] = new Screen( 'options-general' );
check( '他プラグインの設定画面には出さない', ! shows( $repo ) );

ready();
$GLOBALS['screen'] = null;
check( '画面が判定できないときは出さない', ! shows( $repo ) );

ready();
$GLOBALS['caps'] = false;
check( '権限が無いユーザーには出さない', ! shows( $repo ) );

ready();
$GLOBALS['opts']['rapls_passkey_review_prompt'] = 'done';
check( '一度答えたら二度と出さない', ! shows( $repo ) );

ready();
$GLOBALS['filters']['rapls_passkey/show_review_prompt'] = false;
check( 'フィルターで完全に無効化できる', ! shows( $repo ) );

ready();
unset( $GLOBALS['opts']['rapls_passkey_activated_at'] );
check( '有効化日時が無ければ出さない（誤爆防止）', ! shows( $repo ) );

// The buttons must settle it, including the one that leaves the site.
foreach ( array( 'go', 'did', 'no' ) as $answer ) {
	ready();
	$_GET = array( 'rapls_pk_review' => $answer );
	$went = '';
	try {
		( new \RaplsPasskey\Admin\ReviewPrompt( $repo ) )->handle_dismiss();
	} catch ( Redirected $e ) {
		$went = $e->getMessage();
	}
	check( "「{$answer}」でリダイレクトする", '' !== $went, 'リダイレクトしなかった' );
	if ( 'go' === $answer ) {
		check( '「レビューを書く」は WordPress.org へ送る', 'external' === $went, $went );
	}
	check( "「{$answer}」で二度と出なくなる", ! shows( $repo ), var_export( get_option( 'rapls_passkey_review_prompt' ), true ) );
}
$_GET = array();

// The rendered markup must offer a way out.
ready();
ob_start();
( new \RaplsPasskey\Admin\ReviewPrompt( $repo ) )->render();
$html = (string) ob_get_clean();
check( '本文に「二度と出ない」と明記している', str_contains( $html, 'not come back' ) );
check( '断るボタンがある', str_contains( $html, 'No thanks' ) );
check( 'core の警告スタイルを流用していない', ! str_contains( $html, 'notice-error' ) && ! str_contains( $html, 'notice-warning' ) );
check( '× ボタンが出る (is-dismissible)', str_contains( $html, 'is-dismissible' ) );
check( '文面に「× でも二度と出ない」と書いてある', str_contains( $html, 'including closing this notice' ) );

// The close button must persist, or is-dismissible turns "asked once" into a nag.
$js = (string) ( $GLOBALS['inline'] ?? '' );
check( '× 用のスクリプトを出力している', '' !== $js );
check( '  この通知にだけ結び付けている', str_contains( $js, 'rapls-pk-review' ) );
check( '  core の .notice-dismiss を見ている', str_contains( $js, 'notice-dismiss' ) );
check( '  nonce を送っている', str_contains( $js, 'nonce123' ) );
check( '  admin-ajax へ送っている', str_contains( $js, 'admin-ajax.php' ) );

ready();
$went = '';
try {
	( new \RaplsPasskey\Admin\ReviewPrompt( $repo ) )->handle_ajax_dismiss();
} catch ( Redirected $e ) {
	$went = $e->getMessage();
}
check( '× の受け口が成功を返す', 'json-ok' === $went, $went );
check( '× で二度と出なくなる', ! shows( $repo ) );

ready();
$GLOBALS['caps'] = false;
$went = '';
try {
	( new \RaplsPasskey\Admin\ReviewPrompt( $repo ) )->handle_ajax_dismiss();
} catch ( Redirected $e ) {
	$went = $e->getMessage();
}
check( '権限が無ければ × の受け口は拒否する', 'json-err' === $went, $went );
$GLOBALS['caps'] = true;
check( '  拒否時は記録しない', '' === (string) get_option( 'rapls_passkey_review_prompt', '' ) );

echo "\n  {$pass} passed, {$fail} failed\n";
exit( $fail > 0 ? 1 : 0 );

}
