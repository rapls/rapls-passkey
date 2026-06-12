/**
 * Post-login passkey upgrade prompt: run the registration ceremony for the
 * already-authenticated user, then continue to the original destination.
 * Config arrives as a non-executable JSON block (CSP-friendly).
 */
( function () {
	'use strict';

	const cfg = window.raplsPkUpgrade;
	if ( ! cfg ) {
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

	// Automatic passkey upgrade: when the browser supports Conditional Create,
	// silently create a passkey right after the password login (no dialog). Only
	// attempted when advertised, so unsupported browsers never get a surprise
	// modal — they fall back to the explicit button below.
	async function tryConditionalCreate() {
		if ( ! cfg.conditionalCreate ) {
			return false;
		}
		try {
			if ( ! window.PublicKeyCredential || 'function' !== typeof window.PublicKeyCredential.getClientCapabilities ) {
				return false;
			}
			const caps = await window.PublicKeyCredential.getClientCapabilities();
			if ( ! caps || true !== caps.conditionalCreate ) {
				return false;
			}
			const options = await request( 'register/options', {} );
			const credential = await navigator.credentials.create( {
				publicKey: wa.prepareCreation( options.publicKey ),
				mediation: 'conditional',
			} );
			if ( ! credential ) {
				return false;
			}
			await request( 'register/verify', {
				state: options.state,
				credential: wa.attestationToJson( credential ),
				label: '',
			} );
			return true;
		} catch ( e ) {
			return false; // Fall back to the explicit prompt; never block the login.
		}
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

	async function init() {
		// Unsupported browsers: silently continue, never block the login.
		if ( ! wa || ! wa.isSupported() ) {
			go();
			return;
		}
		// Try the silent automatic upgrade first; if it succeeds we are done.
		if ( await tryConditionalCreate() ) {
			go();
			return;
		}
		// Otherwise offer the explicit one-tap creation (F6).
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
