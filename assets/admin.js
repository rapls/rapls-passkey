/**
 * Small admin helper for the Rapls Passkey settings screens.
 *
 * CSP-safe: no inline handlers. Any form carrying a `data-rapls-confirm`
 * attribute asks for confirmation before submitting (used by the destructive
 * "Reset to defaults" button on the Free and Pro settings pages).
 */
( function () {
	'use strict';

	function wire() {
		var forms = document.querySelectorAll( 'form[data-rapls-confirm]' );
		Array.prototype.forEach.call( forms, function ( form ) {
			form.addEventListener( 'submit', function ( event ) {
				var message = form.getAttribute( 'data-rapls-confirm' );
				if ( message && ! window.confirm( message ) ) {
					event.preventDefault();
				}
			} );
		} );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', wire );
	} else {
		wire();
	}
} )();
