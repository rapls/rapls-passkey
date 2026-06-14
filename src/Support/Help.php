<?php
/**
 * Shared "What is a passkey?" help/education snippet.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A small, self-contained explainer shown at passkey enrolment/sign-in points.
 * Educating users at the decision moment is one of the most effective ways to
 * lift passkey adoption. It uses a native <details> disclosure (no JavaScript,
 * CSP-safe) and an optional "learn more" link site owners can point at their own
 * help page via a filter.
 */
final class Help {

	/**
	 * Optional "learn more" URL. Empty (the default) hides the link.
	 *
	 * @return string
	 */
	public static function learn_more_url(): string {
		/**
		 * Filter the "learn more about passkeys" URL shown in the help snippet.
		 *
		 * @param string $url Absolute URL, or '' to hide the link.
		 */
		return esc_url_raw( (string) apply_filters( 'rapls_passkey_learn_more_url', '' ) );
	}

	/**
	 * One-line plain-text explanation of passkeys.
	 *
	 * @return string
	 */
	public static function intro_text(): string {
		return __( 'A passkey lets you sign in with your fingerprint, face, or device unlock (PIN) with no password. It resists phishing and avoids the risks of password reuse and leaks.', 'rapls-passkey' );
	}

	/**
	 * The help snippet as a ready-to-output, fully escaped HTML string.
	 *
	 * @param string $variant 'details' (default, collapsible) or 'inline' (a plain paragraph).
	 * @return string
	 */
	public static function html( string $variant = 'details' ): string {
		$summary = esc_html__( 'What is a passkey?', 'rapls-passkey' );
		$intro   = esc_html( self::intro_text() );

		$link = '';
		$url  = self::learn_more_url();
		if ( '' !== $url ) {
			$link = ' <a href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">'
				. esc_html__( 'Learn more', 'rapls-passkey' ) . '</a>';
		}

		if ( 'inline' === $variant ) {
			return '<p class="rapls-pk-help-inline">' . $intro . $link . '</p>';
		}

		return '<details class="rapls-pk-help" style="margin:8px 0">'
			. '<summary style="cursor:pointer">' . $summary . '</summary>'
			. '<p style="margin:6px 0 0">' . $intro . $link . '</p>'
			. '</details>';
	}

	/**
	 * Echo the help snippet. Output is already escaped.
	 *
	 * @param string $variant See {@see html()}.
	 */
	public static function render( string $variant = 'details' ): void {
		echo self::html( $variant ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}
