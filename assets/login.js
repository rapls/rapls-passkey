/**
 * Passkey login on wp-login.php (username + passkey; usernameless when the
 * username field is left blank and discoverable credentials exist).
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyLogin || {};
	const wa = window.RaplsPasskeyWebAuthn;

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

	async function postJson( path, body ) {
		const res = await fetch( cfg.restUrl + path, {
			method: 'POST',
			credentials: 'same-origin',
			headers: {
				'Content-Type': 'application/json',
				'X-RAPLS-Nonce': cfg.nonce,
			},
			body: JSON.stringify( body ),
		} );
		const data = await res.json().catch( function () {
			return {};
		} );
		if ( ! res.ok ) {
			throw new Error( ( data && data.message ) || cfg.i18n.failed );
		}
		return data;
	}

	async function login() {
		if ( ! wa || ! wa.isSupported() ) {
			status( cfg.i18n.unsupported );
			return;
		}

		const field = document.getElementById( 'user_login' );
		const username = field ? field.value.trim() : '';

		status( cfg.i18n.authenticating );
		try {
			const options = await postJson( 'login/options', { username: username } );
			const assertion = await navigator.credentials.get( {
				publicKey: wa.prepareRequest( options.publicKey ),
			} );
			const result = await postJson( 'login/verify', {
				state: options.state,
				credential: wa.assertionToJson( assertion ),
				redirect_to: cfg.redirectTo || '',
			} );
			window.location.href = result.redirect || window.location.href;
		} catch ( e ) {
			status( friendly( e ) );
		}
	}

	document.addEventListener( 'DOMContentLoaded', function () {
		const btn = document.getElementById( 'rapls-passkey-login-btn' );
		if ( btn ) {
			btn.addEventListener( 'click', login );
		}
	} );
} )();
