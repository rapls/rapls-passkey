/**
 * Smoke test for the wp-login.php passkey client (assets/login.js).
 *
 * The browser allows ONE outstanding credentials.get() per page, and conditional
 * UI (autofill) holds it for the whole visit. Every intermittent "sometimes it
 * signs me in, sometimes it says it failed, sometimes nothing happens" report
 * comes back to that slot being mismanaged, so this test drives the real file
 * against stubs and asserts the invariants that keep it honest:
 *
 *   - two ceremonies are never outstanding at once,
 *   - the verification is never cancellable once the authenticator has signed,
 *   - a background failure the user caused by touching the sensor is SHOWN,
 *   - a background request that was simply abandoned stays silent,
 *   - a browser DOMException is never printed at the user raw.
 *
 *   node tests/smoke-js-login.js
 */

'use strict';

// Kept before the page stubs replace the global console.
const out = console.log.bind( console );

let pass = 0;
let failc = 0;
function check( label, cond ) {
	out( ( cond ? '  PASS  ' : '  FAIL  ' ) + label );
	cond ? pass++ : failc++;
}

const I18N = {
	authenticating: 'AUTHENTICATING',
	failed: 'FAILED',
	unsupported: 'UNSUPPORTED',
	cancelled: 'CANCELLED',
	busy: 'BUSY',
	network: 'NETWORK',
	insecure: 'INSECURE',
	needUsername: 'NEEDUSERNAME',
};

function sleep( ms ) {
	return new Promise( function ( r ) {
		setTimeout( r, ms );
	} );
}

function tick( n ) {
	// Let queued microtasks and setTimeout(0) callbacks drain.
	let p = Promise.resolve();
	for ( let i = 0; i < ( n || 12 ); i++ ) {
		p = p.then( function () {
			return new Promise( function ( r ) {
				setTimeout( r, 0 );
			} );
		} );
	}
	return p;
}

/**
 * Build a fresh page: stub DOM, fetch and authenticator, then load login.js.
 *
 * @param {Object} opts Behaviour switches for the stubs.
 * @return {Object} Handles the test drives the page through.
 */
function makePage( opts ) {
	opts = opts || {};

	const log = {
		getCalls: [],        // one entry per credentials.get()
		maxConcurrent: 0,
		verifySignalled: null, // whether login/verify carried an abort signal
		refused: 0,            // get() calls the browser turned away as already pending
		warned: [],
	};

	let outstanding = 0;
	const statusNode = { textContent: '' };
	const usernameField = { value: '', attrs: {}, setAttribute( k, v ) { this.attrs[ k ] = v; } };
	const button = { disabled: false, handlers: [], addEventListener( t, fn ) { this.handlers.push( [ t, fn ] ); } };
	const rememberBox = { checked: false };
	const form = { handlers: [], addEventListener( t, fn ) { this.handlers.push( [ t, fn ] ); } };

	const elements = {
		'rapls-passkey-login-status': statusNode,
		user_login: usernameField,
		'rapls-passkey-login-btn': button,
		rememberme: rememberBox,
		loginform: form,
	};

	const ready = [];
	global.window = global;
	window.location = { href: 'https://example.test/wp-login.php' };
	window.console = { log: out, warn( ...a ) { log.warned.push( a ); } };
	window.raplsPasskeyLogin = { restUrl: 'https://example.test/wp-json/rapls-passkey/v1/', redirectTo: '', i18n: I18N };

	global.document = {
		activeElement: null,
		getElementById( id ) {
			return elements[ id ] || null;
		},
		addEventListener( type, fn ) {
			if ( 'DOMContentLoaded' === type ) {
				ready.push( fn );
			}
		},
	};
	window.addEventListener = function () {};

	window.PublicKeyCredential = {
		isConditionalMediationAvailable() {
			return Promise.resolve( opts.conditional !== false );
		},
	};

	Object.defineProperty( global, 'navigator', {
		value: {
			credentials: {
				get( getOptions ) {
					const entry = {
						mediation: getOptions.mediation || '',
						hasSignal: !! getOptions.signal,
						settled: false,
					};
					log.getCalls.push( entry );

					// What the browser really does, and the whole point of this test: a
					// second call while one is outstanding is refused outright. Observed on
					// a live login page in Chrome — the exception is an OperationError
					// reading "A request is already pending."
					if ( outstanding > 0 ) {
						log.refused++;
						const busyErr = new Error( 'A request is already pending.' );
						busyErr.name = 'OperationError';
						entry.settled = true;
						return Promise.reject( busyErr );
					}

					outstanding++;
					log.maxConcurrent = Math.max( log.maxConcurrent, outstanding );

					return new Promise( function ( resolve, reject ) {
						const done = function ( fn, value ) {
							if ( entry.settled ) {
								return;
							}
							entry.settled = true;
							outstanding--;
							fn( value );
						};
						entry.resolveWith = function ( cred ) {
							done( resolve, cred );
						};
						entry.rejectWith = function ( err ) {
							done( reject, err );
						};
						if ( getOptions.signal ) {
							getOptions.signal.addEventListener( 'abort', function () {
								// abort() only ASKS, and the browser acts on it a turn later —
								// which is why calling get() straight after abort() is answered
								// with "already pending". Worse, a cancelled CONDITIONAL request
								// can free the slot without ever settling the promise it handed
								// out (observed on a live login page), so anything that waits for
								// that settlement waits for ever.
								outstanding--;
								if ( opts.abortNeverSettles && 'conditional' === entry.mediation ) {
									entry.settled = true; // slot released; promise left dangling
									return;
								}
								setTimeout( function () {
									if ( entry.settled ) {
										return;
									}
									entry.settled = true;
									const e = new Error( 'aborted' );
									e.name = 'AbortError';
									reject( e );
								}, 0 );
							} );
						}
					} );
				},
			},
		},
		configurable: true,
		writable: true,
	} );

	global.fetch = function ( url, init ) {
		const isVerify = url.indexOf( 'login/verify' ) !== -1;
		if ( isVerify ) {
			log.verifySignalled = !! init.signal;
		}
		if ( init.signal && init.signal.aborted ) {
			const e = new Error( 'aborted' );
			e.name = 'AbortError';
			return Promise.reject( e );
		}
		const reply = isVerify ? ( opts.verify || { ok: true, body: { redirect: '/wp-admin/' } } )
			: { ok: true, body: { state: 'st', publicKey: { challenge: 'AAAA', allowCredentials: [] } } };
		return Promise.resolve( {
			ok: reply.ok,
			status: reply.status || ( reply.ok ? 200 : 400 ),
			json() {
				return reply.nonJson ? Promise.reject( new Error( 'not json' ) ) : Promise.resolve( reply.body );
			},
		} );
	};

	window.RaplsPasskeyWebAuthn = {
		isSupported() {
			return true;
		},
		prepareRequest( pk ) {
			return pk;
		},
		assertionToJson() {
			return { id: 'cred' };
		},
	};

	delete require.cache[ require.resolve( '../assets/login.js' ) ];
	require( '../assets/login.js' );
	ready.forEach( function ( fn ) {
		fn();
	} );

	return { log, statusNode, button, usernameField, form, elements };
}

// -------------------------------------------------------------------------
// 1. Autofill arms itself, and the button never collides with it.
// -------------------------------------------------------------------------
( async function () {
	const page = makePage( {} );
	await tick();

	check( 'conditional request is armed on load', page.log.getCalls.length === 1 && page.log.getCalls[ 0 ].mediation === 'conditional' );
	check( 'the username field is opted into passkey autofill', page.usernameField.attrs.autocomplete === 'username webauthn' );

	// Press the button while the background request is still outstanding.
	page.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await tick();

	check( 'pressing the button starts a second ceremony', page.log.getCalls.length === 2 );
	check( 'the modal ceremony is not a conditional one', page.log.getCalls[ 1 ].mediation === '' );
	check( 'the background request was released first (never two at once)', page.log.maxConcurrent === 1 );
	check( 'the button is disabled while its ceremony is on screen', page.button.disabled === true );

	// A second press must not fire a get() that the browser would refuse.
	page.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await tick();
	check( 'a second press while the picker is open starts nothing', page.log.getCalls.length === 2 );
	check( 'the browser never had to refuse a request as already pending', page.log.refused === 0 );

	// Finish it.
	page.log.getCalls[ 1 ].resolveWith( { id: 'cred' } );
	await tick();
	check( 'the verification carries no abort signal', page.log.verifySignalled === false );
	check( 'a successful sign-in navigates', window.location.href === '/wp-admin/' );

	// ---------------------------------------------------------------------
	// 2. A failure AFTER the authenticator answered must be visible.
	// ---------------------------------------------------------------------
	const p2 = makePage( { verify: { ok: false, status: 400, body: { code: 'rapls_passkey_login_failed', message: 'SERVER SAID NO' } } } );
	await tick();
	p2.log.getCalls[ 0 ].resolveWith( { id: 'cred' } );
	await tick();
	check( 'a background failure after the user signed is shown', p2.statusNode.textContent === 'SERVER SAID NO' );
	check( 'the background verification is not cancellable either', p2.log.verifySignalled === false );

	// ---------------------------------------------------------------------
	// 3. A background request nobody used stays silent.
	// ---------------------------------------------------------------------
	const p3 = makePage( {} );
	await tick();
	p3.form.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} ); // password sign-in: give the slot back
	await tick();
	check( 'an abandoned background request says nothing', p3.statusNode.textContent === '' );

	// ---------------------------------------------------------------------
	// 4. Browser exceptions are translated, never shown raw.
	// ---------------------------------------------------------------------
	const p4 = makePage( { conditional: false } );
	await tick();
	check( 'nothing is armed when conditional UI is unavailable', p4.log.getCalls.length === 0 );

	function alreadyPending() {
		const e = new Error( 'A request is already pending.' );
		e.name = 'OperationError';
		return e;
	}

	p4.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await tick();
	p4.log.getCalls[ 0 ].rejectWith( alreadyPending() );
	await sleep( 500 );
	check( 'an "already pending" refusal is retried, not reported', p4.log.getCalls.length === 2 );

	// The retry succeeds: the user signs in and never learns anything went wrong.
	p4.log.getCalls[ 1 ].resolveWith( { id: 'cred' } );
	await tick();
	check( 'a retried ceremony completes the sign-in', window.location.href === '/wp-admin/' );
	check( 'nothing was reported to the user for a refusal that recovered', p4.statusNode.textContent === I18N.authenticating );

	// A refusal that does NOT recover is reported in the site's own words.
	const p4b = makePage( { conditional: false } );
	await tick();
	p4b.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await tick();
	p4b.log.getCalls[ 0 ].rejectWith( alreadyPending() );
	await sleep( 500 );
	p4b.log.getCalls[ 1 ].rejectWith( alreadyPending() );
	await tick();
	check( 'a refusal that persists is reported as "busy", not in English', p4b.statusNode.textContent === I18N.busy );
	check( 'the raw exception text never reaches the user', p4b.statusNode.textContent.indexOf( 'pending' ) === -1 );
	check( 'the button is re-enabled after a failure', p4b.button.disabled === false );

	const p5 = makePage( { conditional: false } );
	await tick();
	p5.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await tick();
	const cancel = new Error( 'The operation either timed out or was not allowed.' );
	cancel.name = 'NotAllowedError';
	p5.log.getCalls[ 0 ].rejectWith( cancel );
	await tick();
	check( 'a cancelled prompt reports cancellation', p5.statusNode.textContent === I18N.cancelled );

	// ---------------------------------------------------------------------
	// 5. A reply that is not a REST error (gateway page, empty body) is
	//    reported as a transport problem, not as a mystery passkey failure.
	// ---------------------------------------------------------------------
	const p6 = makePage( { conditional: false, verify: { ok: false, status: 502, nonJson: true } } );
	await tick();
	p6.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await tick();
	p6.log.getCalls[ 0 ].resolveWith( { id: 'cred' } );
	await tick();
	check( 'a non-JSON error response is reported as a connection problem', p6.statusNode.textContent === I18N.network );

	// ---------------------------------------------------------------------
	// 6. A cancelled conditional request can free the slot without ever settling
	//    its promise. Waiting for that settlement hangs the button for ever — a
	//    dead "Sign in with a passkey" that does nothing at all.
	// ---------------------------------------------------------------------
	const p7 = makePage( { abortNeverSettles: true } );
	await tick();
	check( 'the background request is armed', p7.log.getCalls.length === 1 );
	p7.button.handlers.forEach( function ( h ) {
		h[ 1 ]();
	} );
	await sleep( 500 );
	check( 'the button still starts its ceremony when the cancelled one never settles', p7.log.getCalls.length === 2 );
	check( 'and it did so without being refused', p7.log.refused === 0 );
	p7.log.getCalls[ 1 ].resolveWith( { id: 'cred' } );
	await tick();
	check( 'that ceremony completes', window.location.href === '/wp-admin/' );

	out( '\n' + pass + ' passed, ' + failc + ' failed' );
	process.exit( failc ? 1 : 0 );
}() );
