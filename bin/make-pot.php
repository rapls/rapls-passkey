<?php
/**
 * Generate languages/<text-domain>.pot for this plugin without WP-CLI.
 *
 * Scans the plugin's PHP sources (skipping vendor/tests/node_modules) with the
 * tokenizer, collects the standard gettext calls whose domain matches the
 * plugin's Text Domain, preserves "translators:" comments, and writes a POT.
 *
 *   php bin/make-pot.php
 *
 * Lives in bin/ which .distignore excludes, so it never ships.
 *
 * @package RaplsPasskey
 */

// phpcs:disable WordPress.PHP.DevelopmentFunctions, WordPress.WP.AlternativeFunctions, Generic.PHP.NoSilencedErrors

$root = dirname( __DIR__ );

// --- Locate the main plugin file and read its header. -----------------------
$main = '';
foreach ( glob( $root . '/*.php' ) as $file ) {
	$head = (string) file_get_contents( $file, false, null, 0, 8192 );
	if ( false !== strpos( $head, 'Plugin Name:' ) ) {
		$main = $file;
		break;
	}
}
if ( '' === $main ) {
	fwrite( STDERR, "Could not find the main plugin file.\n" );
	exit( 1 );
}
$header  = (string) file_get_contents( $main, false, null, 0, 8192 );
$domain  = header_field( $header, 'Text Domain' );
$name    = header_field( $header, 'Plugin Name' );
$version = header_field( $header, 'Version' );
if ( '' === $domain ) {
	fwrite( STDERR, "No Text Domain header.\n" );
	exit( 1 );
}

/** Gettext functions => the role of each positional argument (domain is always last). */
$funcs = array(
	'__'          => array( 'text' ),
	'_e'          => array( 'text' ),
	'esc_html__'  => array( 'text' ),
	'esc_html_e'  => array( 'text' ),
	'esc_attr__'  => array( 'text' ),
	'esc_attr_e'  => array( 'text' ),
	'_x'          => array( 'text', 'context' ),
	'_ex'         => array( 'text', 'context' ),
	'esc_html_x'  => array( 'text', 'context' ),
	'esc_attr_x'  => array( 'text', 'context' ),
	'_n'          => array( 'text', 'plural', 'number' ),
	'_nx'         => array( 'text', 'plural', 'number', 'context' ),
);

$entries = array(); // key => ['msgid','plural','context','refs'=>[],'comments'=>[]]

$files = collect_php_files( $root );
foreach ( $files as $path ) {
	extract_file( $path, $domain, $root, $funcs, $entries );
}

// Stable order: by first reference.
uasort(
	$entries,
	static function ( $a, $b ) {
		return strcmp( $a['refs'][0] ?? '', $b['refs'][0] ?? '' );
	}
);

$out_dir = $root . '/languages';
if ( ! is_dir( $out_dir ) ) {
	mkdir( $out_dir, 0755, true );
}
$out_file = $out_dir . '/' . $domain . '.pot';
file_put_contents( $out_file, render_pot( $entries, $name, $version, $domain ) );

printf( "Wrote %s\n  %d strings from %d files.\n", $out_file, count( $entries ), count( $files ) );

// ---------------------------------------------------------------------------

/**
 * Read a single plugin-header field.
 */
function header_field( string $header, string $field ): string {
	if ( preg_match( '/^[ \t\/*#@]*' . preg_quote( $field, '/' ) . ':(.*)$/mi', $header, $m ) ) {
		return trim( $m[1] );
	}
	return '';
}

/**
 * All .php files under the plugin, minus vendor/tests/node_modules/bin.
 *
 * @return string[]
 */
function collect_php_files( string $root ): array {
	$out  = array();
	$skip = array( '/vendor/', '/tests/', '/node_modules/', '/bin/', '/languages/' );
	$it   = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
	foreach ( $it as $f ) {
		$p = $f->getPathname();
		if ( 'php' !== strtolower( $f->getExtension() ) ) {
			continue;
		}
		$rel = str_replace( $root, '', $p );
		foreach ( $skip as $s ) {
			if ( false !== strpos( $rel, $s ) ) {
				continue 2;
			}
		}
		$out[] = $p;
	}
	sort( $out );
	return $out;
}

/**
 * Tokenize one file and record matching gettext calls into $entries.
 */
function extract_file( string $path, string $domain, string $root, array $funcs, array &$entries ): void {
	$code   = (string) file_get_contents( $path );
	$tokens = @token_get_all( $code );
	$rel    = ltrim( str_replace( $root, '', $path ), '/' );
	$count  = count( $tokens );
	$comment = '';

	for ( $i = 0; $i < $count; $i++ ) {
		$tok = $tokens[ $i ];

		if ( is_array( $tok ) && T_COMMENT === $tok[0] ) {
			if ( false !== stripos( $tok[1], 'translators:' ) ) {
				$c       = preg_replace( '~^\s*(?:/\*+|//|\#)\s?~', '', $tok[1] );
				$c       = preg_replace( '~\s*\*+/\s*$~', '', (string) $c );
				$comment = trim( (string) $c );
			}
			continue;
		}
		if ( is_array( $tok ) && T_WHITESPACE === $tok[0] ) {
			continue;
		}
		// A bare ';' or '}' ends the window a translators comment can attach to.
		if ( ! is_array( $tok ) && ( ';' === $tok || '}' === $tok || '{' === $tok ) ) {
			$comment = '';
			continue;
		}

		if ( is_array( $tok ) && T_STRING === $tok[0] && isset( $funcs[ $tok[1] ] ) ) {
			// Reject method/static calls and definitions: $x->__(), Foo::__(), function __().
			$prev = prev_meaningful( $tokens, $i );
			if ( is_array( $prev ) && in_array( $prev[0], array( T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW, T_NULLSAFE_OBJECT_OPERATOR ), true ) ) {
				continue;
			}
			$open = next_meaningful_index( $tokens, $i );
			if ( null === $open || '(' !== $tokens[ $open ] ) {
				continue;
			}

			$line = is_array( $tok ) ? (int) $tok[2] : 0;
			$args = parse_args( $tokens, $open );
			record( $funcs[ $tok[1] ], $args, $domain, $rel, $line, $comment, $entries );
			$comment = '';
		}
	}
}

/**
 * Previous non-whitespace, non-comment token.
 *
 * @return array|string|null
 */
function prev_meaningful( array $tokens, int $i ) {
	for ( $j = $i - 1; $j >= 0; $j-- ) {
		$t = $tokens[ $j ];
		if ( is_array( $t ) && in_array( $t[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
			continue;
		}
		return $t;
	}
	return null;
}

/**
 * Index of the next non-whitespace token.
 */
function next_meaningful_index( array $tokens, int $i ): ?int {
	$count = count( $tokens );
	for ( $j = $i + 1; $j < $count; $j++ ) {
		$t = $tokens[ $j ];
		if ( is_array( $t ) && in_array( $t[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
			continue;
		}
		return $j;
	}
	return null;
}

/**
 * Collect the top-level call arguments as decoded strings (null = non-literal).
 * $open points at the '('.
 *
 * @return array<int,?string>
 */
function parse_args( array $tokens, int $open ): array {
	$count = count( $tokens );
	$depth = 0;
	$args  = array();
	$cur   = array(); // tokens of the current argument
	for ( $j = $open; $j < $count; $j++ ) {
		$t = $tokens[ $j ];
		if ( ! is_array( $t ) ) {
			if ( '(' === $t ) {
				$depth++;
				if ( 1 === $depth ) {
					continue; // skip the outer '('
				}
			} elseif ( ')' === $t ) {
				$depth--;
				if ( 0 === $depth ) {
					$args[] = arg_value( $cur );
					break;
				}
			} elseif ( ',' === $t && 1 === $depth ) {
				$args[] = arg_value( $cur );
				$cur    = array();
				continue;
			}
		}
		if ( $depth >= 1 ) {
			$cur[] = $t;
		}
	}
	return $args;
}

/**
 * If an argument is a single string literal, decode it; otherwise null.
 *
 * @param array $toks Tokens making up one argument.
 * @return string|null
 */
function arg_value( array $toks ): ?string {
	$strings = array();
	foreach ( $toks as $t ) {
		if ( is_array( $t ) && in_array( $t[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
			continue;
		}
		if ( is_array( $t ) && T_CONSTANT_ENCAPSED_STRING === $t[0] ) {
			$strings[] = decode_php_string( $t[1] );
			continue;
		}
		if ( ! is_array( $t ) && '.' === $t ) {
			continue; // allow simple 'a' . 'b' concatenation
		}
		return null; // anything else => non-constant argument
	}
	return array() === $strings ? null : implode( '', $strings );
}

/**
 * Decode a PHP single/double-quoted string literal.
 */
function decode_php_string( string $s ): string {
	if ( strlen( $s ) < 2 ) {
		return '';
	}
	$q    = $s[0];
	$body = substr( $s, 1, -1 );
	if ( "'" === $q ) {
		return strtr( $body, array( '\\\\' => '\\', "\\'" => "'" ) );
	}
	return (string) preg_replace_callback(
		'/\\\\(["\\\\nrtvf$])/',
		static function ( $m ) {
			switch ( $m[1] ) {
				case 'n': return "\n";
				case 't': return "\t";
				case 'r': return "\r";
				case 'v': return "\v";
				case 'f': return "\f";
				case '"': return '"';
				case '$': return '$';
				case '\\': return '\\';
			}
			return $m[0];
		},
		$body
	);
}

/**
 * Record one extracted call.
 */
function record( array $roles, array $args, string $domain, string $rel, int $line, string $comment, array &$entries ): void {
	// Domain is always the last positional argument in WP gettext calls.
	$last = end( $args );
	if ( $last !== $domain ) {
		return; // wrong/dynamic domain — skip.
	}
	$text    = $args[0] ?? null;
	$plural  = null;
	$context = null;
	foreach ( $roles as $idx => $role ) {
		if ( 'plural' === $role ) {
			$plural = $args[ $idx ] ?? null;
		} elseif ( 'context' === $role ) {
			$context = $args[ $idx ] ?? null;
		}
	}
	if ( null === $text || '' === $text ) {
		return;
	}

	$key = ( null === $context ? '' : $context . "\004" ) . $text . ( null === $plural ? '' : "\000" . $plural );
	if ( ! isset( $entries[ $key ] ) ) {
		$entries[ $key ] = array(
			'msgid'    => $text,
			'plural'   => $plural,
			'context'  => $context,
			'refs'     => array(),
			'comments' => array(),
		);
	}
	$ref = $rel . ':' . $line;
	if ( ! in_array( $ref, $entries[ $key ]['refs'], true ) ) {
		$entries[ $key ]['refs'][] = $ref;
	}
	if ( '' !== $comment && ! in_array( $comment, $entries[ $key ]['comments'], true ) ) {
		$entries[ $key ]['comments'][] = $comment;
	}
}

/**
 * Escape a string for a POT msgid/msgstr.
 */
function pot_escape( string $s ): string {
	$s = str_replace( '\\', '\\\\', $s );
	$s = str_replace( '"', '\\"', $s );
	$s = str_replace( "\t", '\\t', $s );
	$s = str_replace( "\r", '', $s );
	$s = str_replace( "\n", '\\n', $s );
	return $s;
}

/**
 * Render the full POT body.
 */
function render_pot( array $entries, string $name, string $version, string $domain ): string {
	$date = gmdate( 'Y-m-d H:iO' );
	$out  = "# Copyright (C) " . gmdate( 'Y' ) . " rapls\n";
	$out .= "# This file is distributed under the GPL-2.0-or-later license.\n";
	$out .= "msgid \"\"\n";
	$out .= "msgstr \"\"\n";
	$out .= '"Project-Id-Version: ' . $name . ' ' . $version . "\\n\"\n";
	$out .= "\"Report-Msgid-Bugs-To: https://github.com/rapls/" . $domain . "/issues\\n\"\n";
	$out .= '"POT-Creation-Date: ' . $date . "\\n\"\n";
	$out .= "\"MIME-Version: 1.0\\n\"\n";
	$out .= "\"Content-Type: text/plain; charset=UTF-8\\n\"\n";
	$out .= "\"Content-Transfer-Encoding: 8bit\\n\"\n";
	$out .= "\"Language: \\n\"\n";
	$out .= "\"Plural-Forms: nplurals=1; plural=0;\\n\"\n";
	$out .= '"X-Domain: ' . $domain . "\\n\"\n";

	foreach ( $entries as $e ) {
		$out .= "\n";
		foreach ( $e['comments'] as $c ) {
			// $c already begins with "translators:" (kept from the source comment).
			$out .= '#. ' . $c . "\n";
		}
		// References, wrapped at a sensible width.
		$line = '#:';
		foreach ( $e['refs'] as $ref ) {
			if ( strlen( $line . ' ' . $ref ) > 76 ) {
				$out .= $line . "\n";
				$line = '#:';
			}
			$line .= ' ' . $ref;
		}
		$out .= $line . "\n";

		if ( null !== $e['context'] ) {
			$out .= 'msgctxt "' . pot_escape( $e['context'] ) . "\"\n";
		}
		$out .= 'msgid "' . pot_escape( $e['msgid'] ) . "\"\n";
		if ( null !== $e['plural'] ) {
			$out .= 'msgid_plural "' . pot_escape( $e['plural'] ) . "\"\n";
			$out .= "msgstr[0] \"\"\n";
		} else {
			$out .= "msgstr \"\"\n";
		}
	}

	return $out;
}
