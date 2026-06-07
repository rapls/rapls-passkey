/**
 * Attaches a reCAPTCHA v3 token to the login form before it submits.
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyRecaptcha || {};

	document.addEventListener( 'DOMContentLoaded', function () {
		const form = document.getElementById( 'loginform' );
		const field = document.getElementById( cfg.field );
		if ( ! form || ! field || ! cfg.siteKey || typeof window.grecaptcha === 'undefined' ) {
			return;
		}

		form.addEventListener( 'submit', function ( e ) {
			if ( field.value ) {
				return; // Token already obtained; let the submit proceed.
			}
			e.preventDefault();
			window.grecaptcha.ready( function () {
				window.grecaptcha.execute( cfg.siteKey, { action: cfg.action } ).then( function ( token ) {
					field.value = token;
					form.submit();
				} ).catch( function () {
					// On failure, submit anyway; the server treats a missing token
					// as a failed check.
					form.submit();
				} );
			} );
		} );
	} );
} )();
