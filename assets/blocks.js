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
		title: __( 'パスキーでログイン', 'rapls-passkey' ),
		description: __( 'ログアウト中の訪問者にパスキーのサインインボタンを表示します。', 'rapls-passkey' ),
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
		title: __( 'パスキーの管理', 'rapls-passkey' ),
		description: __( 'ログイン中のユーザーが自分のパスキーを登録・削除できるUIを表示します。', 'rapls-passkey' ),
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
