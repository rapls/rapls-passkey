<?php
/**
 * Gutenberg blocks for the passkey login / management UI.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Frontend;

defined( 'ABSPATH' ) || exit;

/**
 * Registers two dynamic blocks that render through the same code as the
 * shortcodes. They are server-rendered (a `render_callback`), and the editor
 * shows a live ServerSideRender preview — so no JS build step is needed, in
 * keeping with the plugin family's no-toolchain convention.
 */
final class Blocks {

	/**
	 * @param Shortcodes $shortcodes Shared renderers.
	 */
	public function __construct( private Shortcodes $shortcodes ) {}

	/**
	 * Hook block registration.
	 */
	public function register(): void {
		add_action( 'init', array( $this, 'register_blocks' ) );
	}

	/**
	 * Register the editor script and the two blocks.
	 */
	public function register_blocks(): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		wp_register_script(
			'rapls-passkey-blocks',
			RAPLS_PASSKEY_URL . 'assets/blocks.js',
			array( 'wp-blocks', 'wp-element', 'wp-block-editor', 'wp-components', 'wp-server-side-render', 'wp-i18n' ),
			RAPLS_PASSKEY_VERSION,
			true
		);

		if ( function_exists( 'wp_set_script_translations' ) ) {
			wp_set_script_translations( 'rapls-passkey-blocks', 'rapls-passkey' );
		}

		register_block_type(
			'rapls-passkey/login',
			array(
				'api_version'     => 2,
				'editor_script'   => 'rapls-passkey-blocks',
				'render_callback' => array( $this, 'render_login' ),
				'attributes'      => array(
					'redirect' => array(
						'type'    => 'string',
						'default' => '',
					),
					'label'    => array(
						'type'    => 'string',
						'default' => '',
					),
				),
			)
		);

		register_block_type(
			'rapls-passkey/register',
			array(
				'api_version'     => 2,
				'editor_script'   => 'rapls-passkey-blocks',
				'render_callback' => array( $this, 'render_register' ),
			)
		);
	}

	/**
	 * Render the login block via the shared shortcode renderer.
	 *
	 * @param array<string,mixed> $attributes Block attributes.
	 * @return string
	 */
	public function render_login( array $attributes ): string {
		$atts = array();
		if ( ! empty( $attributes['redirect'] ) ) {
			$atts['redirect'] = (string) $attributes['redirect'];
		}
		if ( ! empty( $attributes['label'] ) ) {
			$atts['label'] = (string) $attributes['label'];
		}
		return $this->shortcodes->render_login( $atts );
	}

	/**
	 * Render the register block via the shared shortcode renderer.
	 *
	 * @return string
	 */
	public function render_register(): string {
		return $this->shortcodes->render_register( array() );
	}
}
