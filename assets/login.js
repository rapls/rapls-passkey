/**
 * Passkey login on wp-login.php.
 *
 * Two paths share one ceremony:
 *  - Conditional UI (autofill): a background get() with mediation:'conditional'
 *    surfaces passkeys in the username field's autocomplete dropdown.
 *  - Explicit button: a modal get() triggered by the "Sign in with a passkey" button.
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyLogin || {};
	const wa = window.RaplsPasskeyWebAuthn;
	let conditionalAbort = null;

	function status( msg ) {
		const el = document.getElementById( 'rapls-passkey-login-status' );
		if ( el ) {
			el.textContent = msg || '';
		}
	}

	function friendly( e ) {
		if ( e && e.name === 'NotAllowedError' ) {
			return cfg.i18n.cancelled;
		}
		return ( e && e.message ) || cfg.i18n.failed;
	}

	async function postJson( path, body, signal ) {
		const res = await fetch( cfg.restUrl + path, {
			method: 'POST',
			credentials: 'same-origin',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify( body ),
			signal: signal,
		} );
		const data = await res.json().catch( function () {
			return {};
		} );
		if ( ! res.ok ) {
			// A passkey login that did not perform user verification (or another
			// weaker path) must still clear the site's 2FA: the server parks it and
			// returns the challenge URL. Navigate there instead of erroring.
			if ( data && data.code === 'rapls_passkey_2fa_required' && data.data && data.data.redirect ) {
				window.location.href = data.data.redirect;
				return new Promise( function () {} ); // navigating away; never resolves
			}
			throw new Error( ( data && data.message ) || cfg.i18n.failed );
		}
		return data;
	}

	/**
	 * Run options -> get() -> verify -> redirect.
	 *
	 * @param {string|null}      mediation 'conditional' for autofill, else modal.
	 * @param {AbortSignal|null} signal    Abort signal, for the conditional flow.
	 */
	async function runCeremony( mediation, signal ) {
		const field = document.getElementById( 'user_login' );
		const username = field ? field.value.trim() : '';

		const options = await postJson( 'login/options', { username: username }, signal );
		const getOptions = { publicKey: wa.prepareRequest( options.publicKey ) };
		if ( mediation ) {
			getOptions.mediation = mediation;
		}
		if ( signal ) {
			getOptions.signal = signal;
		}

		const assertion = await navigator.credentials.get( getOptions );
		const rememberEl = document.getElementById( 'rememberme' );
		const result = await postJson( 'login/verify', {
			state: options.state,
			credential: wa.assertionToJson( assertion ),
			redirect_to: cfg.redirectTo || '',
			rememberme: rememberEl && rememberEl.checked ? 1 : 0,
		}, signal );

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
			status( cfg.i18n.unsupported );
			return;
		}
		abortConditional();
		status( cfg.i18n.authenticating );
		try {
			await runCeremony( '', null );
		} catch ( e ) {
			status( friendly( e ) );
		}
	}

	async function startConditional() {
		if ( ! wa || ! wa.isSupported() ) {
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
			await runCeremony( 'conditional', conditionalAbort.signal );
		} catch ( e ) {
			// Background flow: stay silent on abort / no-selection. The explicit
			// button remains available for an error-reported attempt.
		}
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		const field = document.getElementById( 'user_login' );
		if ( field ) {
			// Opt the username field into passkey autofill.
			field.setAttribute( 'autocomplete', 'username webauthn' );
		}
		const btn = document.getElementById( 'rapls-passkey-login-btn' );
		if ( btn ) {
			btn.addEventListener( 'click', explicitLogin );
		}
		// Submitting the password form cancels the background conditional request.
		const form = document.getElementById( 'loginform' );
		if ( form ) {
			form.addEventListener( 'submit', abortConditional );
		}

		startConditional();
	} );
} )();
