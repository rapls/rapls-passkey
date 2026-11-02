/**
 * Attaches a reCAPTCHA v3 token to the login form before it submits.
 */
( function () {
	'use strict';

	const cfg = window.raplsPasskeyRecaptcha || {};

	document.addEventListener( 'DOMContentLoaded', function () {
		if ( ! cfg.siteKey || typeof window.grecaptcha === 'undefined' ) {
			return;
		}
		// One field per login form: wp-login.php's #loginform, or a front-end
		// form such as WP-Members' that fires login_form too.
		document.querySelectorAll( 'input[name="' + cfg.field + '"]' ).forEach( function ( field ) {
			const form = field.form;
			if ( ! form ) {
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
						HTMLFormElement.prototype.submit.call( form );
					} ).catch( function () {
						// On failure, submit anyway; the server treats a missing
						// token as a failed check.
						HTMLFormElement.prototype.submit.call( form );
					} );
				} );
			} );
		} );
	} );
} )();
