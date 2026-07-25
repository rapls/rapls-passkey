/**
 * Front-end passkey ceremonies for the [rapls_passkey_login] and
 * [rapls_passkey_register] shortcodes / blocks.
 *
 * Login reuses the public login/options + login/verify routes (same as
 * wp-login.php). Registration reuses the nonce-protected register routes (the
 * visitor is logged in). All DOM hooks are bound with addEventListener so the
 * markup carries no inline handlers (CSP-friendly).
 *
 * Every element is resolved relative to its own `.rapls-pk-fe-login` /
 * `.rapls-pk-fe-register` container, so several shortcodes (or a shortcode plus
 * the WooCommerce integration) can appear on one page without their controls
 * colliding on a shared DOM id.
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyFrontend || {};
	const wa = window.RaplsPasskeyWebAuthn;

	function status( root, msg ) {
		const node = root && root.querySelector( '.rapls-pk-fe-status' );
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
			// A passkey login that skipped user verification must still clear the
			// site's 2FA: the server returns the challenge URL — navigate there.
			if ( data && data.code === 'rapls_passkey_2fa_required' && data.data && data.data.redirect ) {
				window.location.href = data.data.redirect;
				return new Promise( function () {} );
			}
			throw new Error( ( data && data.message ) || '' );
		}
		return data;
	}

	// --- Login --------------------------------------------------------------

	async function runLogin( root, mediation, signal ) {
		const field = root.querySelector( '.rapls-pk-fe-username' );
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
			redirect_to: root.getAttribute( 'data-redirect' ) || '',
		}, { signal: signal } );

		window.location.href = result.redirect || window.location.href;
	}

	function abortConditional( root ) {
		if ( root._raplsAbort ) {
			try {
				root._raplsAbort.abort();
			} catch ( e ) {}
			root._raplsAbort = null;
		}
	}

	async function explicitLogin( root ) {
		if ( ! wa || ! wa.isSupported() ) {
			status( root, cfg.i18n.unsupported );
			return;
		}
		abortConditional( root );
		status( root, cfg.i18n.authenticating );
		try {
			await runLogin( root, '', null );
		} catch ( e ) {
			status( root, loginFriendly( e ) );
		}
	}

	async function startConditional( root ) {
		if ( ! wa || ! wa.isSupported() || ! root.querySelector( '.rapls-pk-fe-username' ) ) {
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
		root._raplsAbort = new AbortController();
		try {
			await runLogin( root, 'conditional', root._raplsAbort.signal );
		} catch ( e ) {
			// Background flow: stay silent on abort / no-selection.
		}
	}

	// --- Registration -------------------------------------------------------

	async function registerPasskey( root ) {
		if ( ! wa || ! wa.isSupported() ) {
			status( root, cfg.i18n.unsupported );
			return;
		}
		status( root, cfg.i18n.registering );
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
			status( root, cfg.i18n.registered );
			window.location.reload();
		} catch ( e ) {
			status( root, registerFriendly( e ) );
		}
	}

	async function deletePasskey( root, row ) {
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
			status( root, ( e && e.message ) || cfg.i18n.registerFailed );
		}
	}

	async function renamePasskey( root, row ) {
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
			status( root, ( e && e.message ) || cfg.i18n.renameFailed );
		}
	}

	/**
	 * Suspending stops a passkey working without destroying it — the answer to a
	 * device that is temporarily out of reach rather than gone for good.
	 */
	async function togglePasskey( root, row, button ) {
		const id = row.getAttribute( 'data-id' );
		const active = row.getAttribute( 'data-active' ) === '1';
		if ( ! id ) {
			return;
		}
		if ( active && ! window.confirm( cfg.i18n.confirmSuspend ) ) {
			return;
		}

		try {
			const result = await postJson(
				'credentials/' + encodeURIComponent( id ),
				{ active: ! active },
				{ nonce: cfg.nonce }
			);

			const now = !! ( result && result.active );
			row.setAttribute( 'data-active', now ? '1' : '0' );
			button.textContent = now ? cfg.i18n.suspend : cfg.i18n.resume;
			const state = row.querySelector( '.rapls-pk-fe-state' );
			if ( state ) {
				state.textContent = now ? cfg.i18n.active : cfg.i18n.suspended;
			}
		} catch ( e ) {
			status( root, ( e && e.message ) || cfg.i18n.registerFailed );
		}
	}

	// --- Wiring -------------------------------------------------------------

	document.addEventListener( 'DOMContentLoaded', function () {
		// Each login shortcode instance is wired independently.
		document.querySelectorAll( '.rapls-pk-fe-login' ).forEach( function ( root ) {
			const btn = root.querySelector( '.rapls-pk-fe-btn' );
			if ( btn ) {
				btn.addEventListener( 'click', function () {
					explicitLogin( root );
				} );
			}
			startConditional( root );
		} );

		// Each register / management shortcode instance is wired independently, with
		// its row controls scoped to that container.
		document.querySelectorAll( '.rapls-pk-fe-register' ).forEach( function ( root ) {
			const btn = root.querySelector( '.rapls-pk-fe-btn' );
			if ( btn ) {
				btn.addEventListener( 'click', function () {
					registerPasskey( root );
				} );
			}
			root.querySelectorAll( '.rapls-pk-fe-delete' ).forEach( function ( node ) {
				node.addEventListener( 'click', function () {
					const row = node.closest( 'tr' );
					if ( row ) {
						deletePasskey( root, row );
					}
				} );
			} );
			root.querySelectorAll( '.rapls-pk-fe-rename' ).forEach( function ( node ) {
				node.addEventListener( 'click', function () {
					const row = node.closest( 'tr' );
					if ( row ) {
						renamePasskey( root, row );
					}
				} );
			} );
			root.querySelectorAll( '.rapls-pk-fe-toggle' ).forEach( function ( node ) {
				node.addEventListener( 'click', function () {
					const row = node.closest( 'tr' );
					if ( row ) {
						togglePasskey( root, row, node );
					}
				} );
			} );
		} );
	} );
} )();
