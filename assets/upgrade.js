/**
 * Post-login passkey upgrade prompt: run the registration ceremony for the
 * already-authenticated user, then continue to the original destination.
 * Config arrives as a non-executable JSON block (CSP-friendly).
 */
( function () {
	'use strict';

	const node = document.getElementById( 'rapls-pk-upgrade-config' );
	if ( ! node ) {
		return;
	}

	let cfg;
	try {
		cfg = JSON.parse( node.textContent );
	} catch ( e ) {
		return;
	}

	const wa = window.RaplsPasskeyWebAuthn;
	const dest = ( cfg && cfg.redirect ) || '/wp-admin/';

	function go() {
		window.location.assign( dest );
	}

	function status( msg ) {
		const el = document.getElementById( 'rapls-pk-upgrade-status' );
		if ( el ) {
			el.textContent = msg || '';
		}
	}

	async function request( path, body ) {
		const res = await fetch( cfg.restUrl + path, {
			method: 'POST',
			credentials: 'same-origin',
			headers: {
				'Content-Type': 'application/json',
				'X-WP-Nonce': cfg.nonce,
			},
			body: JSON.stringify( body || {} ),
		} );
		const data = await res.json().catch( function () {
			return {};
		} );
		if ( ! res.ok ) {
			throw new Error( ( data && data.message ) || cfg.i18n.failed );
		}
		return data;
	}

	async function create() {
		status( cfg.i18n.registering );
		try {
			const options = await request( 'register/options', {} );
			const credential = await navigator.credentials.create( {
				publicKey: wa.prepareCreation( options.publicKey ),
			} );
			await request( 'register/verify', {
				state: options.state,
				credential: wa.attestationToJson( credential ),
				label: '',
			} );
			status( cfg.i18n.success );
			go();
		} catch ( e ) {
			if ( e && e.name === 'NotAllowedError' ) {
				status( cfg.i18n.cancelled );
			} else if ( e && e.name === 'InvalidStateError' ) {
				// Already registered on this authenticator — nothing to do.
				go();
			} else {
				status( ( e && e.message ) || cfg.i18n.failed );
			}
		}
	}

	function init() {
		// Unsupported browsers: silently continue, never block the login.
		if ( ! wa || ! wa.isSupported() ) {
			go();
			return;
		}
		const btn = document.getElementById( 'rapls-pk-upgrade-create' );
		if ( btn ) {
			btn.addEventListener( 'click', create );
		}
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
} )();
