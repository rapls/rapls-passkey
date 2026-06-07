/**
 * Smoke test for the shared WebAuthn browser helpers (assets/webauthn.js):
 * base64url <-> buffer round-tripping, options preparation, and response
 * serialisation. Runs under node with minimal window/navigator stubs.
 *
 *   node tests/smoke-js-webauthn.js
 */

'use strict';

// --- Minimal browser globals ---------------------------------------------
global.window = global;
window.atob = global.atob;
window.btoa = global.btoa;
// `navigator` is a read-only global in modern node; override it.
Object.defineProperty( global, 'navigator', {
	value: { credentials: {} },
	configurable: true,
	writable: true,
} );
window.PublicKeyCredential = function () {};

require( '../assets/webauthn.js' );
const wa = window.RaplsPasskeyWebAuthn;

let pass = 0;
let failc = 0;
function check( label, cond ) {
	console.log( ( cond ? '  PASS  ' : '  FAIL  ' ) + label );
	cond ? pass++ : failc++;
}

function buf( str ) {
	return new TextEncoder().encode( str ).buffer;
}
function sameBytes( ab, str ) {
	const a = new Uint8Array( ab );
	const b = new TextEncoder().encode( str );
	if ( a.length !== b.length ) {
		return false;
	}
	for ( let i = 0; i < a.length; i++ ) {
		if ( a[ i ] !== b[ i ] ) {
			return false;
		}
	}
	return true;
}

check( 'exports the helper namespace', !! wa );
check( 'isSupported() true with PublicKeyCredential + credentials', wa.isSupported() === true );

// base64url round-trips (incl. high bytes that need - and _).
check( 'b64url decodes "SGVsbG8" to Hello', sameBytes( wa.b64urlToBuf( 'SGVsbG8' ), 'Hello' ) );
const bytes = new Uint8Array( [ 0, 1, 2, 250, 251, 255 ] );
const round = new Uint8Array( wa.b64urlToBuf( wa.bufToB64url( bytes.buffer ) ) );
check( 'buffer -> base64url -> buffer is lossless', round.length === bytes.length && round.every( function ( v, i ) { return v === bytes[ i ]; } ) );
check( 'base64url output has no +, /, or =', /^[A-Za-z0-9_-]*$/.test( wa.bufToB64url( bytes.buffer ) ) );

// prepareRequest converts the binary fields to ArrayBuffers.
const req = wa.prepareRequest( {
	challenge: 'SGVsbG8',
	rpId: 'example.test',
	allowCredentials: [ { id: 'SGVsbG8', type: 'public-key', transports: [ 'internal' ] } ],
	userVerification: 'preferred',
} );
check( 'prepareRequest: challenge -> ArrayBuffer', req.challenge instanceof ArrayBuffer );
check( 'prepareRequest: allowCredentials[].id -> ArrayBuffer', req.allowCredentials[ 0 ].id instanceof ArrayBuffer );
check( 'prepareRequest: rpId preserved', req.rpId === 'example.test' );

// prepareCreation converts challenge, user.id, excludeCredentials ids.
const create = wa.prepareCreation( {
	challenge: 'SGVsbG8',
	user: { id: 'SGVsbG8', name: 'alice', displayName: 'Alice' },
	excludeCredentials: [ { id: 'SGVsbG8', type: 'public-key' } ],
} );
check( 'prepareCreation: challenge -> ArrayBuffer', create.challenge instanceof ArrayBuffer );
check( 'prepareCreation: user.id -> ArrayBuffer', create.user.id instanceof ArrayBuffer );
check( 'prepareCreation: user.name preserved', create.user.name === 'alice' );
check( 'prepareCreation: excludeCredentials[].id -> ArrayBuffer', create.excludeCredentials[ 0 ].id instanceof ArrayBuffer );

// assertionToJson produces base64url strings the server can decode.
const assertion = wa.assertionToJson( {
	id: 'SGVsbG8',
	rawId: buf( 'Hello' ),
	type: 'public-key',
	response: {
		clientDataJSON: buf( '{}' ),
		authenticatorData: buf( 'authdata' ),
		signature: buf( 'sig' ),
		userHandle: buf( 'uh' ),
	},
	getClientExtensionResults: function () {
		return {};
	},
} );
check( 'assertionToJson: rawId base64url matches', assertion.rawId === wa.bufToB64url( buf( 'Hello' ) ) );
check( 'assertionToJson: signature present', assertion.response.signature === wa.bufToB64url( buf( 'sig' ) ) );
check( 'assertionToJson: userHandle present', assertion.response.userHandle === wa.bufToB64url( buf( 'uh' ) ) );
check( 'assertionToJson: no attestationObject', ! ( 'attestationObject' in assertion.response ) );

// assertionToJson tolerates a null userHandle.
const noHandle = wa.assertionToJson( {
	id: 'SGVsbG8',
	rawId: buf( 'Hello' ),
	type: 'public-key',
	response: { clientDataJSON: buf( '{}' ), authenticatorData: buf( 'a' ), signature: buf( 's' ), userHandle: null },
	getClientExtensionResults: function () {
		return {};
	},
} );
check( 'assertionToJson: null userHandle stays null', noHandle.response.userHandle === null );

console.log( '\n  ' + pass + ' passed, ' + failc + ' failed' );
process.exit( failc === 0 ? 0 : 1 );
