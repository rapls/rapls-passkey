/**
 * Front-end passkey ceremonies for the [rapls_passkey_login] and
 * [rapls_passkey_register] shortcodes / blocks.
 *
 * Login reuses the public login/options + login/verify routes (same as
 * wp-login.php). Registration reuses the nonce-protected register routes (the
 * visitor is logged in). All DOM hooks are bound with addEventListener so the
 * markup carries no inline handlers (CSP-friendly).
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyFrontend || {};
	const wa = window.RaplsPasskeyWebAuthn;
	let conditionalAbort = null;

	function el( id ) {
		return document.getElementById( id );
	}

	function status( id, msg ) {
		const node = el( id );
		if ( node ) {
			node.textContent = msg || '';
		}
	}

	function loginFriendly( e ) {
		if ( e && e.name === 'NotAllowedError' ) {
			return cfg.i18n.cancelled;
		}
		return ( e && e.message ) || cfg.i18n.loginFailed;
	}

	function registerFriendly( e ) {
		if ( e && e.name === 'NotAllowedError' ) {
			return cfg.i18n.cancelled;
		}
		if ( e && e.name === 'InvalidStateError' ) {
			return cfg.i18n.duplicate;
		}
		return ( e && e.message ) || cfg.i18n.registerFailed;
	}

	async function postJson( path, body, opts ) {
		const headers = { 'Content-Type': 'application/json' };
		if ( opts && opts.nonce ) {
			headers['X-WP-Nonce'] = opts.nonce;
		}
		const res = await fetch( cfg.restUrl + path, {
			method: ( opts && opts.method ) || 'POST',
			credentials: 'same-origin',
			headers: headers,
			body: body ? JSON.stringify( body ) : undefined,
			signal: opts && opts.signal,
		} );
		const data = await res.json().catch( function () {
			return {};
		} );
		if ( ! res.ok ) {
			throw new Error( ( data && data.message ) || '' );
		}
		return data;
	}

	// --- Login --------------------------------------------------------------

	async function runLogin( mediation, signal ) {
		const root = document.querySelector( '.rapls-pk-fe-login' );
		const field = el( 'rapls-pk-fe-username' );
		const username = field ? field.value.trim() : '';

		const options = await postJson( 'login/options', { username: username }, { signal: signal } );
		const getOptions = { publicKey: wa.prepareRequest( options.publicKey ) };
		if ( mediation ) {
			getOptions.mediation = mediation;
		}
		if ( signal ) {
			getOptions.signal = signal;
		}

		const assertion = await navigator.credentials.get( getOptions );
		const result = await postJson( 'login/verify', {
			state: options.state,
			credential: wa.assertionToJson( assertion ),
			redirect_to: ( root && root.getAttribute( 'data-redirect' ) ) || '',
		}, { signal: signal } );

		window.location.href = result.redirect || window.location.href;
	}

	function abortConditional() {
		if ( conditionalAbort ) {
			try {
				conditionalAbort.abort();
			} catch ( e ) {}
			conditionalAbort = null;
		}
	}

	async function explicitLogin() {
		if ( ! wa || ! wa.isSupported() ) {
			status( 'rapls-pk-fe-login-status', cfg.i18n.unsupported );
			return;
		}
		abortConditional();
		status( 'rapls-pk-fe-login-status', cfg.i18n.authenticating );
		try {
			await runLogin( '', null );
		} catch ( e ) {
			status( 'rapls-pk-fe-login-status', loginFriendly( e ) );
		}
	}

	async function startConditional() {
		if ( ! wa || ! wa.isSupported() || ! el( 'rapls-pk-fe-username' ) ) {
			return;
		}
		if ( ! window.PublicKeyCredential || ! window.PublicKeyCredential.isConditionalMediationAvailable ) {
			return;
		}
		let available = false;
		try {
			available = await window.PublicKeyCredential.isConditionalMediationAvailable();
		} catch ( e ) {
			return;
		}
		if ( ! available ) {
			return;
		}
		conditionalAbort = new AbortController();
		try {
			await runLogin( 'conditional', conditionalAbort.signal );
		} catch ( e ) {
			// Background flow: stay silent on abort / no-selection.
		}
	}

	// --- Registration -------------------------------------------------------

	async function registerPasskey() {
		if ( ! wa || ! wa.isSupported() ) {
			status( 'rapls-pk-fe-register-status', cfg.i18n.unsupported );
			return;
		}
		status( 'rapls-pk-fe-register-status', cfg.i18n.registering );
		try {
			const options = await postJson( 'register/options', {}, { nonce: cfg.nonce } );
			const credential = await navigator.credentials.create( {
				publicKey: wa.prepareCreation( options.publicKey ),
			} );
			const label = window.prompt( cfg.i18n.labelPrompt, '' ) || '';
			await postJson( 'register/verify', {
				state: options.state,
				credential: wa.attestationToJson( credential ),
				label: label,
			}, { nonce: cfg.nonce } );
			status( 'rapls-pk-fe-register-status', cfg.i18n.registered );
			window.location.reload();
		} catch ( e ) {
			status( 'rapls-pk-fe-register-status', registerFriendly( e ) );
		}
	}

	async function deletePasskey( row ) {
		const id = row.getAttribute( 'data-id' );
		if ( ! id || ! window.confirm( cfg.i18n.confirmDel ) ) {
			return;
		}
		try {
			await postJson( 'credentials/' + encodeURIComponent( id ), null, { method: 'DELETE', nonce: cfg.nonce } );
			if ( row.parentNode ) {
				row.parentNode.removeChild( row );
			}
		} catch ( e ) {
			status( 'rapls-pk-fe-register-status', ( e && e.message ) || cfg.i18n.registerFailed );
		}
	}

	async function renamePasskey( row ) {
		const id = row.getAttribute( 'data-id' );
		const cell = row.querySelector( '.rapls-pk-fe-label' );
		if ( ! id || ! cell ) {
			return;
		}

		// An unnamed passkey shows a placeholder; do not offer it back as the name.
		const current = cell.textContent === cfg.i18n.noLabel ? '' : cell.textContent;
		const label = window.prompt( cfg.i18n.renamePrompt, current );
		if ( label === null ) {
			return;
		}

		try {
			const result = await postJson(
				'credentials/' + encodeURIComponent( id ),
				{ label: label },
				{ nonce: cfg.nonce }
			);
			cell.textContent = ( result && result.label ) || cfg.i18n.noLabel;
		} catch ( e ) {
			status( 'rapls-pk-fe-register-status', ( e && e.message ) || cfg.i18n.renameFailed );
		}
	}

	// --- Wiring -------------------------------------------------------------

	document.addEventListener( 'DOMContentLoaded', function () {
		const loginBtn = el( 'rapls-pk-fe-login-btn' );
		if ( loginBtn ) {
			loginBtn.addEventListener( 'click', explicitLogin );
			startConditional();
		}

		const registerBtn = el( 'rapls-pk-fe-register-btn' );
		if ( registerBtn ) {
			registerBtn.addEventListener( 'click', registerPasskey );
		}
		document.querySelectorAll( '.rapls-pk-fe-delete' ).forEach( function ( node ) {
			node.addEventListener( 'click', function () {
				const row = node.closest( 'tr' );
				if ( row ) {
					deletePasskey( row );
				}
			} );
		} );
		document.querySelectorAll( '.rapls-pk-fe-rename' ).forEach( function ( node ) {
			node.addEventListener( 'click', function () {
				const row = node.closest( 'tr' );
				if ( row ) {
					renamePasskey( row );
				}
			} );
		} );
	} );
} )();
