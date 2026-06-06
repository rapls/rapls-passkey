/**
 * Shared WebAuthn browser helpers for rapls-passkey.
 *
 * Converts between the base64url JSON the server speaks and the ArrayBuffers the
 * WebAuthn API requires, and serialises authenticator responses back to JSON.
 */
( function () {
	'use strict';

	function b64urlToBuf( value ) {
		const pad = '='.repeat( ( 4 - ( value.length % 4 ) ) % 4 );
		const base64 = ( value + pad ).replace( /-/g, '+' ).replace( /_/g, '/' );
		const raw = window.atob( base64 );
		const buf = new Uint8Array( raw.length );
		for ( let i = 0; i < raw.length; i++ ) {
			buf[ i ] = raw.charCodeAt( i );
		}
		return buf.buffer;
	}

	function bufToB64url( buffer ) {
		const bytes = new Uint8Array( buffer );
		let str = '';
		for ( let i = 0; i < bytes.length; i++ ) {
			str += String.fromCharCode( bytes[ i ] );
		}
		return window.btoa( str ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=+$/, '' );
	}

	function isSupported() {
		return typeof window.PublicKeyCredential !== 'undefined' && !! navigator.credentials;
	}

	/** Convert server creation options (base64url) into a navigator-ready object. */
	function prepareCreation( publicKey ) {
		const pk = Object.assign( {}, publicKey );
		pk.challenge = b64urlToBuf( publicKey.challenge );
		pk.user = Object.assign( {}, publicKey.user, { id: b64urlToBuf( publicKey.user.id ) } );
		if ( Array.isArray( publicKey.excludeCredentials ) ) {
			pk.excludeCredentials = publicKey.excludeCredentials.map( function ( c ) {
				return Object.assign( {}, c, { id: b64urlToBuf( c.id ) } );
			} );
		}
		return pk;
	}

	/** Convert server request options (base64url) into a navigator-ready object. */
	function prepareRequest( publicKey ) {
		const pk = Object.assign( {}, publicKey );
		pk.challenge = b64urlToBuf( publicKey.challenge );
		if ( Array.isArray( publicKey.allowCredentials ) ) {
			pk.allowCredentials = publicKey.allowCredentials.map( function ( c ) {
				return Object.assign( {}, c, { id: b64urlToBuf( c.id ) } );
			} );
		}
		return pk;
	}

	/** Serialise an attestation (registration) credential to server JSON. */
	function attestationToJson( cred ) {
		const r = cred.response;
		const out = {
			id: cred.id,
			rawId: bufToB64url( cred.rawId ),
			type: cred.type,
			response: {
				clientDataJSON: bufToB64url( r.clientDataJSON ),
				attestationObject: bufToB64url( r.attestationObject ),
			},
			clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
		};
		if ( typeof r.getTransports === 'function' ) {
			out.response.transports = r.getTransports();
		}
		return out;
	}

	/** Serialise an assertion (authentication) credential to server JSON. */
	function assertionToJson( cred ) {
		const r = cred.response;
		return {
			id: cred.id,
			rawId: bufToB64url( cred.rawId ),
			type: cred.type,
			response: {
				clientDataJSON: bufToB64url( r.clientDataJSON ),
				authenticatorData: bufToB64url( r.authenticatorData ),
				signature: bufToB64url( r.signature ),
				userHandle: r.userHandle ? bufToB64url( r.userHandle ) : null,
			},
			clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
		};
	}

	window.RaplsPasskeyWebAuthn = {
		isSupported: isSupported,
		b64urlToBuf: b64urlToBuf,
		bufToB64url: bufToB64url,
		prepareCreation: prepareCreation,
		prepareRequest: prepareRequest,
		attestationToJson: attestationToJson,
		assertionToJson: assertionToJson,
	};
} )();
