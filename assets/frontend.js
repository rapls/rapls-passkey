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

	/**
	 * The WebAuthn slot is per PAGE, not per shortcode: the browser allows exactly
	 * one outstanding credentials.get(), so two login shortcodes on one page share
	 * this state and take turns. `current` is the ceremony holding the slot.
	 */
	let current = null;
	let busy = false;
	let leaving = false;
	let rearmTimer = null;

	/**
	 * The server forgets a ceremony a few minutes after issuing it, so a page left
	 * open would answer the autofill request with a challenge that no longer
	 * exists — the user touches the sensor and nothing happens. Replace the
	 * background request well inside that window.
	 */
	const REARM_MS = 4 * 60 * 1000;
	const REARM_RETRY_MS = 30 * 1000;
	/**
	 * How long to let the browser finish releasing a cancelled request. abort()
	 * only asks: the slot is freed promptly, but the promise from a cancelled
	 * CONDITIONAL request is not guaranteed ever to settle (the call may be handled
	 * by a password-manager extension rather than the browser), so waiting for it
	 * can wait for ever. Every wait here is bounded by this instead.
	 */
	const RELEASE_GRACE_MS = 300;

	function delay( ms ) {
		return new Promise( function ( resolve ) {
			setTimeout( resolve, ms );
		} );
	}

	function ignore() {}

	/** An error carrying a message the SERVER wrote (already translated). */
	function serverError( message, code ) {
		const e = new Error( message );
		e.raplsServer = true;
		e.raplsCode = code || '';
		return e;
	}

	/**
	 * Map a rejection onto a sentence the user can act on. Browser exceptions carry
	 * internal English text, so they are matched by name and never shown raw; only
	 * a server message (which is translated) is passed through.
	 *
	 * @param {*}      e        The rejection value.
	 * @param {string} fallback Message when nothing more specific is known.
	 * @return {string} Message to display.
	 */
	function describe( e, fallback ) {
		if ( e && e.raplsServer && e.message ) {
			return e.message;
		}
		const name = e && e.name;
		if ( 'NotAllowedError' === name || 'AbortError' === name || 'TimeoutError' === name ) {
			return cfg.i18n.cancelled;
		}
		if ( 'OperationError' === name || 'NotReadableError' === name ) {
			return cfg.i18n.busy;
		}
		if ( 'SecurityError' === name ) {
			return cfg.i18n.insecure;
		}
		if ( 'NotSupportedError' === name ) {
			return cfg.i18n.unsupported;
		}
		if ( window.console && window.console.warn ) {
			window.console.warn( '[rapls-passkey] passkey operation failed:', e );
		}
		return fallback;
	}

	function loginFriendly( e ) {
		return describe( e, cfg.i18n.loginFailed );
	}

	function registerFriendly( e ) {
		// A duplicate enrolment is the one InvalidStateError worth naming: the
		// authenticator is refusing because it already holds a passkey for this site.
		if ( e && 'InvalidStateError' === e.name ) {
			return cfg.i18n.duplicate;
		}
		return describe( e, cfg.i18n.registerFailed );
	}

	async function postJson( path, body, opts ) {
		const headers = { 'Content-Type': 'application/json' };
		if ( opts && opts.nonce ) {
			headers['X-WP-Nonce'] = opts.nonce;
		}

		let res;
		try {
			res = await fetch( cfg.restUrl + path, {
				method: ( opts && opts.method ) || 'POST',
				credentials: 'same-origin',
				headers: headers,
				body: body ? JSON.stringify( body ) : undefined,
				signal: ( opts && opts.signal ) || undefined,
			} );
		} catch ( e ) {
			if ( e && 'AbortError' === e.name ) {
				throw e;
			}
			throw serverError( cfg.i18n.network, 'network' );
		}

		let data = {};
		try {
			data = await res.json();
		} catch ( e ) {
			data = {};
		}

		if ( ! res.ok ) {
			// A passkey login that skipped user verification must still clear the
			// site's 2FA: the server returns the challenge URL — navigate there.
			if ( data && 'rapls_passkey_2fa_required' === data.code && data.data && data.data.redirect ) {
				leaving = true;
				window.location.href = data.data.redirect;
				return new Promise( function () {} );
			}
			// A REST error always carries a translated message. A response that is not
			// one (a gateway error page, an empty body) carries nothing worth showing,
			// so it is reported as the transport problem it is.
			throw serverError(
				( data && data.message ) || cfg.i18n.network,
				( data && data.code ) || 'http_' + res.status
			);
		}
		return data;
	}

	// --- Login --------------------------------------------------------------

	async function runLogin( root, mediation, signal, run ) {
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

		const assertion = await getAssertion( getOptions );
		run.answered = true;

		// No abort signal from here on: the authenticator has already signed, and
		// cancelling the verification would discard a sign-in the server is about to
		// complete, leaving the page looking inert.
		const result = await postJson( 'login/verify', {
			state: options.state,
			credential: wa.assertionToJson( assertion ),
			redirect_to: root.getAttribute( 'data-redirect' ) || '',
		}, {} );

		leaving = true;
		window.location.href = result.redirect || window.location.href;
	}

	/**
	 * Hand the WebAuthn slot back, then give the browser a moment to finish the
	 * release. A get() issued too soon is refused with "A request is already
	 * pending", so the wait is real — but capped, because a cancelled conditional
	 * request is not guaranteed ever to settle.
	 */
	async function releaseSlot() {
		if ( rearmTimer ) {
			clearTimeout( rearmTimer );
			rearmTimer = null;
		}
		const held = current;
		if ( ! held ) {
			return;
		}
		current = null;
		if ( held.abort ) {
			try {
				held.abort.abort();
			} catch ( e ) {}
		}
		await Promise.race( [ held.promise.then( ignore, ignore ), delay( RELEASE_GRACE_MS ) ] );
	}

	/**
	 * Ask the authenticator, forgiving one "already pending": the browser had not
	 * quite let go of the previous request, which is a reason to wait and ask
	 * again rather than to tell the user their passkey failed. The options are
	 * unchanged and their challenge unused, so the retry is the same ceremony.
	 *
	 * @param {Object} getOptions Argument for navigator.credentials.get().
	 * @return {Promise<Object>} The assertion.
	 */
	async function getAssertion( getOptions ) {
		try {
			return await navigator.credentials.get( getOptions );
		} catch ( e ) {
			if ( ! e || 'OperationError' !== e.name ) {
				throw e;
			}
			await delay( RELEASE_GRACE_MS );
			return navigator.credentials.get( getOptions );
		}
	}

	async function explicitLogin( root ) {
		if ( busy ) {
			return;
		}
		if ( ! wa || ! wa.isSupported() ) {
			status( root, cfg.i18n.unsupported );
			return;
		}

		busy = true;
		const btn = root.querySelector( '.rapls-pk-fe-btn' );
		if ( btn ) {
			btn.disabled = true;
		}
		status( root, cfg.i18n.authenticating );

		let mine = null;
		try {
			await releaseSlot();
			const ctrl = new AbortController();
			mine = { promise: runLogin( root, '', ctrl.signal, { answered: false } ), abort: ctrl };
			current = mine;
			await mine.promise;
		} catch ( e ) {
			status( root, loginFriendly( e ) );
		} finally {
			if ( current === mine ) {
				current = null;
			}
			busy = false;
			if ( btn ) {
				btn.disabled = false;
			}
			// Put autofill back; it was given up to make room for this attempt.
			armConditional( root );
		}
	}

	function scheduleRearm( root, ms ) {
		if ( rearmTimer ) {
			clearTimeout( rearmTimer );
		}
		rearmTimer = setTimeout( function () {
			rearmTick( root );
		}, ms );
	}

	async function rearmTick( root ) {
		rearmTimer = null;
		if ( leaving ) {
			return;
		}
		if ( busy ) {
			scheduleRearm( root, REARM_RETRY_MS );
			return;
		}
		const field = root.querySelector( '.rapls-pk-fe-username' );
		if ( field && document.activeElement === field ) {
			// The passkey list may be open in this field; replacing the request now
			// would close it under the user's hands.
			scheduleRearm( root, REARM_RETRY_MS );
			return;
		}
		await releaseSlot();
		armConditional( root );
	}

	function armConditional( root ) {
		if ( leaving || busy || current ) {
			return;
		}
		if ( ! wa || ! wa.isSupported() || ! root.querySelector( '.rapls-pk-fe-username' ) ) {
			return;
		}
		if ( ! window.PublicKeyCredential || ! window.PublicKeyCredential.isConditionalMediationAvailable ) {
			return;
		}

		window.PublicKeyCredential.isConditionalMediationAvailable().then( function ( available ) {
			if ( ! available || leaving || busy || current ) {
				return;
			}

			const ctrl = new AbortController();
			const run = { answered: false };
			const mine = { promise: runLogin( root, 'conditional', ctrl.signal, run ), abort: ctrl };
			current = mine;
			scheduleRearm( root, REARM_MS );

			mine.promise.catch( function ( e ) {
				// Silence is right only while nothing has happened: an unused or
				// cancelled background request is how conditional UI normally ends. Once
				// the authenticator has answered, a failure has to be visible, or the
				// page appears to have ignored the user entirely.
				if ( run.answered && ! leaving && e && 'AbortError' !== e.name ) {
					status( root, loginFriendly( e ) );
				}
			} ).then( function () {
				if ( current === mine ) {
					current = null;
				}
			} );
		} ).catch( function () {} );
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
