/**
 * Passkey login on wp-login.php.
 *
 * Two paths share one ceremony:
 *  - Conditional UI (autofill): a background get() with mediation:'conditional'
 *    surfaces passkeys in the username field's autocomplete dropdown.
 *  - Explicit button: a modal get() triggered by the "Sign in with a passkey" button.
 *
 * The browser allows exactly ONE outstanding credentials.get() per page, and the
 * conditional request holds it for the whole visit. Everything below is arranged
 * around that single slot: a ceremony only starts once the previous one has
 * actually finished unwinding, and the slot is handed back and re-taken rather
 * than abandoned. Getting this wrong is what makes a passkey button work
 * sometimes, fail sometimes, and appear to do nothing at other times.
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyLogin || {};
	const wa = window.RaplsPasskeyWebAuthn;

	/** The ceremony holding the WebAuthn slot: { promise, abort }, or null. */
	let current = null;
	/** A ceremony the user started and is looking at (the picker is on screen). */
	let busy = false;
	/** The page is on its way out: stay quiet and stop re-arming. */
	let leaving = false;
	/** Pending re-arm timer id. */
	let rearmTimer = null;

	/**
	 * The server forgets a ceremony a few minutes after issuing it. A login page
	 * left open outlives that, and the background request would then be answered
	 * with a challenge the server no longer holds: the user touches the sensor and
	 * nothing happens at all. So the background request is replaced with a fresh
	 * one well inside that window.
	 */
	const REARM_MS = 4 * 60 * 1000;
	/** Retry interval when the moment is wrong (the user is in the field). */
	const REARM_RETRY_MS = 30 * 1000;
	/**
	 * How long to let the browser finish releasing a cancelled request.
	 *
	 * abort() only asks. The slot is freed promptly, but the promise from a
	 * cancelled CONDITIONAL request is not guaranteed ever to settle — observed on
	 * a live login page, and the WebAuthn call may be handled by a password-manager
	 * extension rather than the browser itself, so what settles and when is not
	 * ours to assume. Waiting for that settlement can therefore wait for ever and
	 * leave the button permanently dead, so every wait here is bounded by this.
	 */
	const RELEASE_GRACE_MS = 300;

	function delay( ms ) {
		return new Promise( function ( resolve ) {
			setTimeout( resolve, ms );
		} );
	}

	function ignore() {}

	function el( id ) {
		return document.getElementById( id );
	}

	function status( msg ) {
		const node = el( 'rapls-passkey-login-status' );
		if ( node ) {
			node.textContent = msg || '';
		}
	}

	/** An error carrying a message the SERVER wrote (already translated). */
	function serverError( message, code ) {
		const e = new Error( message );
		e.raplsServer = true;
		e.raplsCode = code || '';
		return e;
	}

	/**
	 * A sentence the user can act on.
	 *
	 * Browser exceptions carry internal English text ("A request is already
	 * pending."), so they are mapped by name and never shown raw. Only a message
	 * the server wrote is passed through, because that one is translated and meant
	 * to be read.
	 *
	 * @param {*} e The rejection value.
	 * @return {string} Message to display.
	 */
	function friendly( e ) {
		if ( e && e.raplsServer && e.message ) {
			return e.message;
		}
		const name = e && e.name;
		if ( 'NotAllowedError' === name || 'AbortError' === name || 'TimeoutError' === name ) {
			return cfg.i18n.cancelled;
		}
		if ( 'InvalidStateError' === name || 'OperationError' === name || 'NotReadableError' === name ) {
			return cfg.i18n.busy;
		}
		if ( 'SecurityError' === name ) {
			return cfg.i18n.insecure;
		}
		if ( 'NotSupportedError' === name ) {
			return cfg.i18n.unsupported;
		}
		// Nothing recognised. The visible text stays generic, but the real exception
		// goes to the console so a failure that gets reported can be diagnosed
		// instead of guessed at.
		if ( window.console && window.console.warn ) {
			window.console.warn( '[rapls-passkey] sign-in failed:', e );
		}
		return cfg.i18n.failed;
	}

	async function postJson( path, body, signal ) {
		let res;
		try {
			res = await fetch( cfg.restUrl + path, {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify( body ),
				signal: signal || undefined,
			} );
		} catch ( e ) {
			if ( e && 'AbortError' === e.name ) {
				throw e;
			}
			// Offline, DNS, TLS, a dropped connection. Not a passkey problem, and the
			// browser's own wording for it is internal English.
			throw serverError( cfg.i18n.network, 'network' );
		}

		let data = {};
		try {
			data = await res.json();
		} catch ( e ) {
			data = {};
		}

		if ( ! res.ok ) {
			// A passkey login that did not perform user verification (or another
			// weaker path) must still clear the site's 2FA: the server parks it and
			// returns the challenge URL. Navigate there instead of erroring.
			if ( data && 'rapls_passkey_2fa_required' === data.code && data.data && data.data.redirect ) {
				leaving = true;
				window.location.href = data.data.redirect;
				return new Promise( function () {} ); // navigating away; never resolves
			}
			// Every REST error from this plugin carries a translated message. A
			// response that is NOT one — a gateway error page, an empty body, anything
			// that did not come from WordPress — carries nothing worth showing, so it
			// is reported as what it is (the site could not be reached properly)
			// rather than as a passkey that failed.
			throw serverError(
				( data && data.message ) || cfg.i18n.network,
				( data && data.code ) || 'http_' + res.status
			);
		}
		return data;
	}

	/**
	 * Run options -> get() -> verify -> redirect.
	 *
	 * @param {string|null}      mediation 'conditional' for autofill, else modal.
	 * @param {AbortSignal|null} signal    Abort signal for the get() and its options call.
	 * @param {Object}           run       Progress flags; `run.answered` is set once
	 *                                     the authenticator has responded.
	 */
	async function runCeremony( mediation, signal, run ) {
		const field = el( 'user_login' );
		const username = field ? field.value.trim() : '';

		const options = await postJson( 'login/options', { username: username }, signal );
		const getOptions = { publicKey: wa.prepareRequest( options.publicKey ) };
		if ( mediation ) {
			getOptions.mediation = mediation;
		}
		if ( signal ) {
			getOptions.signal = signal;
		}

		const assertion = await getAssertion( getOptions );
		run.answered = true;

		// Past this point the user has done their part and the authenticator has
		// signed. The verification therefore carries NO abort signal on purpose:
		// cancelling it here — because the button was pressed, or the password form
		// was submitted — would throw away a sign-in the server is about to complete,
		// and the page would simply sit there.
		const rememberEl = el( 'rememberme' );
		const result = await postJson( 'login/verify', {
			state: options.state,
			credential: wa.assertionToJson( assertion ),
			redirect_to: cfg.redirectTo || '',
			rememberme: rememberEl && rememberEl.checked ? 1 : 0,
		}, null );

		leaving = true;
		window.location.href = result.redirect || window.location.href;
	}

	/**
	 * Hand the WebAuthn slot back, then give the browser a moment to finish the
	 * release before anything else asks for it. Issuing get() too soon is answered
	 * with "A request is already pending" — the intermittent failure this avoids —
	 * so the wait is real, but capped (see RELEASE_GRACE_MS), because a cancelled
	 * conditional request is not guaranteed ever to settle.
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
	 * Ask the authenticator, and forgive one "already pending".
	 *
	 * If the browser had not quite finished letting go of the previous request, the
	 * right answer is to wait a little longer and ask again — not to tell the user
	 * their passkey failed. The options are unchanged and their challenge is still
	 * unused, so the retry is the same ceremony, not a new one.
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

	async function explicitLogin() {
		if ( busy ) {
			// The picker is already on screen. A second get() would be refused outright
			// and the one the user is looking at is still waiting for them.
			return;
		}
		if ( ! wa || ! wa.isSupported() ) {
			status( cfg.i18n.unsupported );
			return;
		}

		busy = true;
		const btn = el( 'rapls-passkey-login-btn' );
		if ( btn ) {
			btn.disabled = true;
		}
		status( cfg.i18n.authenticating );

		let mine = null;
		try {
			await releaseSlot();
			const ctrl = new AbortController();
			mine = { promise: runCeremony( '', ctrl.signal, { answered: false } ), abort: ctrl };
			current = mine;
			await mine.promise;
		} catch ( e ) {
			status( friendly( e ) );
		} finally {
			if ( current === mine ) {
				current = null;
			}
			busy = false;
			if ( btn ) {
				btn.disabled = false;
			}
			// Autofill was given up to make room for this attempt. Put it back, or the
			// username field silently stops offering passkeys for the rest of the visit.
			armConditional();
		}
	}

	function scheduleRearm( ms ) {
		if ( rearmTimer ) {
			clearTimeout( rearmTimer );
		}
		rearmTimer = setTimeout( rearmTick, ms );
	}

	async function rearmTick() {
		rearmTimer = null;
		if ( leaving ) {
			return;
		}
		if ( busy ) {
			scheduleRearm( REARM_RETRY_MS );
			return;
		}
		const field = el( 'user_login' );
		if ( field && document.activeElement === field ) {
			// The passkey list may be open in this field right now; replacing the
			// request would close it under the user's hands.
			scheduleRearm( REARM_RETRY_MS );
			return;
		}
		await releaseSlot();
		armConditional();
	}

	function armConditional() {
		if ( leaving || busy || current ) {
			return;
		}
		if ( ! wa || ! wa.isSupported() ) {
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
			const mine = { promise: runCeremony( 'conditional', ctrl.signal, run ), abort: ctrl };
			current = mine;
			scheduleRearm( REARM_MS );

			mine.promise.catch( function ( e ) {
				// An unused or cancelled background request is how conditional UI
				// normally ends, and reporting that would be noise. But once the
				// authenticator has answered, the user believes they have signed in: a
				// failure after that point must be said out loud, or the page just sits
				// there having apparently ignored them.
				if ( run.answered && ! leaving && e && 'AbortError' !== e.name ) {
					status( friendly( e ) );
				}
			} ).then( function () {
				if ( current === mine ) {
					current = null;
				}
			} );
		} ).catch( function () {} );
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		const field = el( 'user_login' );
		if ( field ) {
			// Opt the username field into passkey autofill.
			field.setAttribute( 'autocomplete', 'username webauthn' );
		}
		const btn = el( 'rapls-passkey-login-btn' );
		if ( btn ) {
			btn.addEventListener( 'click', explicitLogin );
		}
		// Submitting the password form gives the WebAuthn slot back. A verification
		// already under way is untouched, because it carries no abort signal.
		const form = el( 'loginform' );
		if ( form ) {
			form.addEventListener( 'submit', function () {
				releaseSlot();
			} );
		}
		window.addEventListener( 'pagehide', function () {
			leaving = true;
		} );

		armConditional();
	} );
} )();
