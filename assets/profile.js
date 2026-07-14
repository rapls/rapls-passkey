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

	async function registerPasskey( event ) {
		if ( ! wa || ! wa.isSupported() ) {
			status( cfg.i18n.unsupported );
			return;
		}

		// Set when an administrator is enrolling on someone else's behalf from that
		// user's profile screen; absent on your own.
		const button = event && event.currentTarget;
		const forUser = button && button.getAttribute( 'data-user' );
		const owner = forUser ? { user: parseInt( forUser, 10 ) } : {};

		status( cfg.i18n.registering );
		try {
			const options = await request( 'register/options', {
				method: 'POST',
				body: JSON.stringify( owner ),
			} );
			const credential = await navigator.credentials.create( {
				publicKey: wa.prepareCreation( options.publicKey ),
			} );
			const label = window.prompt( cfg.i18n.labelPrompt, '' ) || '';
			await request( 'register/verify', {
				method: 'POST',
				body: JSON.stringify( Object.assign( {
					state: options.state,
					credential: wa.attestationToJson( credential ),
					label: label,
				}, owner ) ),
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

	async function renamePasskey( row ) {
		const id = row.getAttribute( 'data-id' );
		const cell = row.querySelector( '.rapls-passkey-label' );
		if ( ! id || ! cell ) {
			return;
		}

		// An unnamed passkey shows a placeholder; do not offer it back as the name.
		const current = cell.textContent === cfg.i18n.noName ? '' : cell.textContent;
		const label = window.prompt( cfg.i18n.renamePrompt, current );
		if ( label === null ) {
			return;
		}

		try {
			const result = await request( 'credentials/' + encodeURIComponent( id ), {
				method: 'POST',
				body: JSON.stringify( { label: label } ),
			} );
			cell.textContent = result.label || cfg.i18n.noName;
		} catch ( e ) {
			status( ( e && e.message ) || cfg.i18n.renameFailed );
		}
	}

	/**
	 * Suspending stops a passkey working without destroying it — the answer to a
	 * device that is temporarily out of reach rather than gone for good.
	 */
	async function togglePasskey( row, button ) {
		const id = row.getAttribute( 'data-id' );
		const active = row.getAttribute( 'data-active' ) === '1';
		if ( ! id ) {
			return;
		}
		if ( active && ! window.confirm( cfg.i18n.confirmSuspend ) ) {
			return;
		}

		try {
			const result = await request( 'credentials/' + encodeURIComponent( id ), {
				method: 'POST',
				body: JSON.stringify( { active: ! active } ),
			} );

			const now = !! result.active;
			row.setAttribute( 'data-active', now ? '1' : '0' );
			button.textContent = now ? cfg.i18n.suspend : cfg.i18n.resume;
			const state = row.querySelector( '.rapls-passkey-state' );
			if ( state ) {
				state.textContent = now ? cfg.i18n.active : cfg.i18n.suspended;
			}
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
		document.querySelectorAll( '.rapls-passkey-rename' ).forEach( function ( el ) {
			el.addEventListener( 'click', function () {
				const row = el.closest( 'tr' );
				if ( row ) {
					renamePasskey( row );
				}
			} );
		} );
		document.querySelectorAll( '.rapls-passkey-toggle' ).forEach( function ( el ) {
			el.addEventListener( 'click', function () {
				const row = el.closest( 'tr' );
				if ( row ) {
					togglePasskey( row, el );
				}
			} );
		} );
	} );
} )();
