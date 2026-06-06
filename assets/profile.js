/**
 * Passkey registration and removal on the user profile screen.
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyProfile || {};
	const wa = window.RaplsPasskeyWebAuthn;

	function status( msg ) {
		const el = document.getElementById( 'rapls-passkey-status' );
		if ( el ) {
			el.textContent = msg || '';
		}
	}

	function friendly( e ) {
		if ( e && e.name === 'NotAllowedError' ) {
			return cfg.i18n.cancelled;
		}
		if ( e && e.name === 'InvalidStateError' ) {
			return cfg.i18n.duplicate;
		}
		return ( e && e.message ) || cfg.i18n.failed;
	}

	async function request( path, options ) {
		const res = await fetch( cfg.restUrl + path, Object.assign(
			{
				credentials: 'same-origin',
				headers: {
					'Content-Type': 'application/json',
					'X-WP-Nonce': cfg.nonce,
				},
			},
			options
		) );
		const data = await res.json().catch( function () {
			return {};
		} );
		if ( ! res.ok ) {
			throw new Error( ( data && data.message ) || cfg.i18n.failed );
		}
		return data;
	}

	async function registerPasskey() {
		if ( ! wa || ! wa.isSupported() ) {
			status( cfg.i18n.unsupported );
			return;
		}

		status( cfg.i18n.registering );
		try {
			const options = await request( 'register/options', { method: 'POST', body: JSON.stringify( {} ) } );
			const credential = await navigator.credentials.create( {
				publicKey: wa.prepareCreation( options.publicKey ),
			} );
			const label = window.prompt( cfg.i18n.labelPrompt, '' ) || '';
			await request( 'register/verify', {
				method: 'POST',
				body: JSON.stringify( {
					state: options.state,
					credential: wa.attestationToJson( credential ),
					label: label,
				} ),
			} );
			status( cfg.i18n.success );
			window.location.reload();
		} catch ( e ) {
			status( friendly( e ) );
		}
	}

	async function deletePasskey( row ) {
		const id = row.getAttribute( 'data-id' );
		if ( ! id || ! window.confirm( cfg.i18n.confirmDel ) ) {
			return;
		}
		try {
			await request( 'credentials/' + encodeURIComponent( id ), { method: 'DELETE' } );
			row.parentNode.removeChild( row );
		} catch ( e ) {
			status( ( e && e.message ) || cfg.i18n.failed );
		}
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		const btn = document.getElementById( 'rapls-passkey-register' );
		if ( btn ) {
			btn.addEventListener( 'click', registerPasskey );
		}
		document.querySelectorAll( '.rapls-passkey-delete' ).forEach( function ( el ) {
			el.addEventListener( 'click', function () {
				const row = el.closest( 'tr' );
				if ( row ) {
					deletePasskey( row );
				}
			} );
		} );
	} );
} )();
