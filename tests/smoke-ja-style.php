<?php
/**
 * The Japanese catalogue against the ja.wordpress.org style guide.
 *
 * A PTE returned five strings over one rule: a half-width `?` or `!` takes a
 * space before AND after it. It is the kind of thing that comes back the moment
 * a new string is added by hand, so it is asserted here rather than remembered.
 *
 * https://ja.wordpress.org/team/handbook/translation/
 *
 *   php tests/smoke-ja-style.php
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

/**
 * Read a .po into msgid => msgstr, skipping the header and the untranslated.
 *
 * @param string $file Path to the catalogue.
 * @return array<string,string>
 */
function po_pairs( $file ) {
	$src   = (string) file_get_contents( $file );
	$pairs = array();
	foreach ( preg_split( '/\n\n+/', $src ) as $block ) {
		if ( ! preg_match( '/^msgid ((?:"(?:[^"\\\\]|\\\\.)*"\s*)+)/m', $block, $mi ) ) {
			continue;
		}
		// `msgstr[0]` as well as `msgstr`: Japanese has one plural form, so the
		// plural entries carry their whole translation in index 0.
		if ( ! preg_match( '/^msgstr(?:\[0\])? ((?:"(?:[^"\\\\]|\\\\.)*"\s*)+)/m', $block, $ms ) ) {
			continue;
		}
		$join = static function ( $raw ) {
			preg_match_all( '/"((?:[^"\\\\]|\\\\.)*)"/', $raw, $m );
			return implode( '', $m[1] );
		};
		$id = $join( $mi[1] );
		$to = $join( $ms[1] );
		if ( '' !== $id && '' !== $to ) {
			$pairs[ $id ] = $to;
		}
	}
	return $pairs;
}

$po = dirname( __DIR__ ) . '/languages/rapls-passkey-ja.po';
if ( ! is_readable( $po ) ) {
	echo "  FAIL  languages/rapls-passkey-ja.po が読めません\n";
	exit( 1 );
}

$pairs = po_pairs( $po );

echo "== 日本語カタログのスタイル ==\n\n";
check( '訳文を読み込めた', count( $pairs ) > 100, count( $pairs ) . ' 件' );

/*
 * The rule the PTE sent the plugin back over. A trailing `?` is the one place a
 * following space is wrong: GlotPress rejects a translation ending in
 * whitespace, so end-of-string counts as satisfying "space after".
 */
$unspaced = array();
foreach ( $pairs as $id => $to ) {
	$len = strlen( $to );
	for ( $i = 0; $i < $len; $i++ ) {
		if ( '?' !== $to[ $i ] && '!' !== $to[ $i ] ) {
			continue;
		}
		$before = $i > 0 && ' ' === $to[ $i - 1 ];
		$after  = ( $i === $len - 1 ) || ' ' === $to[ $i + 1 ];
		if ( ! $before || ! $after ) {
			$unspaced[] = $to;
			break;
		}
	}
}
check( '半角 ? ! の前後に半角スペースがある', array() === $unspaced, implode( ' / ', array_slice( $unspaced, 0, 3 ) ) );

// Full-width ？ ！ are not used in the guide's Japanese; the half-width forms are.
$fullwidth = array();
foreach ( $pairs as $to ) {
	if ( false !== strpos( $to, '？' ) || false !== strpos( $to, '！' ) ) {
		$fullwidth[] = $to;
	}
}
check( '全角 ？ ！ を使っていない', array() === $fullwidth, implode( ' / ', array_slice( $fullwidth, 0, 3 ) ) );

// Full-width parentheses likewise: half-width, spaced on the outside only.
$fullparen = array();
foreach ( $pairs as $to ) {
	if ( false !== strpos( $to, '（' ) || false !== strpos( $to, '）' ) ) {
		$fullparen[] = $to;
	}
}
check( '全角 （ ） を使っていない', array() === $fullparen, implode( ' / ', array_slice( $fullparen, 0, 3 ) ) );

// A space just inside a parenthesis is the other half of that rule.
$inner = array();
foreach ( $pairs as $to ) {
	if ( preg_match( '/\( | \)/', $to ) ) {
		$inner[] = $to;
	}
}
check( '半角括弧の内側にスペースがない', array() === $inner, implode( ' / ', array_slice( $inner, 0, 3 ) ) );

// Placeholders must survive translation, or the string breaks at runtime and
// GlotPress refuses it besides.
$dropped = array();
foreach ( $pairs as $id => $to ) {
	preg_match_all( '/%(?:\d+\$)?[sdx]|%%/', $id, $a );
	preg_match_all( '/%(?:\d+\$)?[sdx]|%%/', $to, $b );
	sort( $a[0] );
	sort( $b[0] );
	if ( $a[0] !== $b[0] ) {
		$dropped[] = $id;
	}
}
check( 'プレースホルダーが一致する', array() === $dropped, implode( ' / ', array_slice( $dropped, 0, 2 ) ) );

// The same for markup: GlotPress compares the tag sequence.
$tags = array();
foreach ( $pairs as $id => $to ) {
	preg_match_all( '/<[^>]+>/', $id, $a );
	preg_match_all( '/<[^>]+>/', $to, $b );
	if ( count( $a[0] ) !== count( $b[0] ) ) {
		$tags[] = $id;
	}
}
check( 'HTML タグの数が一致する', array() === $tags, implode( ' / ', array_slice( $tags, 0, 2 ) ) );

// Vocabulary the guide fixes: kana, not kanji, for these three.
$kanji = array(
	'下さい' => 'ください',
	'全て'   => 'すべて',
	'既に'   => 'すでに',
);
foreach ( $kanji as $wrong => $right ) {
	$hits = array();
	foreach ( $pairs as $to ) {
		if ( false !== strpos( $to, $wrong ) ) {
			$hits[] = $to;
		}
	}
	check( "「{$wrong}」ではなく「{$right}」", array() === $hits, implode( ' / ', array_slice( $hits, 0, 2 ) ) );
}

// WordPress is never translated, and never written ワードプレス.
$wp = array();
foreach ( $pairs as $to ) {
	if ( false !== strpos( $to, 'ワードプレス' ) ) {
		$wp[] = $to;
	}
}
check( '「ワードプレス」と書かない', array() === $wp );

// Nothing may end in whitespace — GlotPress rejects it outright.
$trailing = array();
foreach ( $pairs as $to ) {
	if ( $to !== rtrim( $to, " \t" ) ) {
		$trailing[] = $to;
	}
}
check( '末尾に空白がない', array() === $trailing, implode( ' / ', array_slice( $trailing, 0, 2 ) ) );

/*
 * Untranslated entries are what gets uploaded next, so they are worth seeing.
 *
 * Counted from the parsed blocks, not by grepping for `msgstr ""`: msgcat wraps
 * long strings by opening with an empty `msgstr ""` and continuing underneath,
 * and every wrapped translation would read as untranslated.
 */
$src   = (string) file_get_contents( $po );
$total = preg_match_all( '/^msgid "/m', $src ) - 1; // Less the header.
$empty = $total - count( $pairs );
check( '未訳が残っていない', $empty <= 0, "{$empty} 件が未訳" );

echo "\n  {$pass} passed, {$fail} failed\n";
exit( $fail > 0 ? 1 : 0 );
