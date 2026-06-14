/**
 * Editor registration for the passkey blocks. No JSX / build step: plain ES5
 * using the wp.* globals. Both blocks are server-rendered, so the editor shows a
 * live ServerSideRender preview and `save` returns null.
 */
( function ( blocks, element, blockEditor, serverSideRender, i18n ) {
	'use strict';

	const el = element.createElement;
	const __ = i18n.__;
	const InspectorControls = blockEditor.InspectorControls;
	const SSR = serverSideRender;

	blocks.registerBlockType( 'rapls-passkey/login', {
		apiVersion: 2,
		title: __( 'Sign in with a passkey', 'rapls-passkey' ),
		description: __( 'Show a passkey sign-in button to logged-out visitors.', 'rapls-passkey' ),
		icon: 'lock',
		category: 'widgets',
		attributes: {
			redirect: { type: 'string', default: '' },
			label: { type: 'string', default: '' },
		},
		edit: function ( props ) {
			return el(
				element.Fragment,
				null,
				el( SSR, {
					block: 'rapls-passkey/login',
					attributes: props.attributes,
				} )
			);
		},
		save: function () {
			return null;
		},
	} );

	blocks.registerBlockType( 'rapls-passkey/register', {
		apiVersion: 2,
		title: __( 'Manage passkeys', 'rapls-passkey' ),
		description: __( 'Let logged-in users register and remove their own passkeys.', 'rapls-passkey' ),
		icon: 'admin-network',
		category: 'widgets',
		edit: function () {
			return el( SSR, { block: 'rapls-passkey/register' } );
		},
		save: function () {
			return null;
		},
	} );
} )( window.wp.blocks, window.wp.element, window.wp.blockEditor, window.wp.serverSideRender, window.wp.i18n );
