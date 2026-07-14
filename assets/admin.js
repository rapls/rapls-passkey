/**
 * Small admin helper for the Rapls Passkey settings screens.
 *
 * CSP-safe: no inline handlers. Anything carrying a `data-rapls-confirm`
 * attribute asks for confirmation before it acts — a form before it submits
 * ("Reset to defaults" on the settings pages), a link before it is followed
 * (deleting a passkey from the Users -> Passkeys list).
 */
( function () {
	'use strict';

	function confirmed( node ) {
		var message = node.getAttribute( 'data-rapls-confirm' );
		return ! message || window.confirm( message );
	}

	function wire() {
		var forms = document.querySelectorAll( 'form[data-rapls-confirm]' );
		Array.prototype.forEach.call( forms, function ( form ) {
			form.addEventListener( 'submit', function ( event ) {
				if ( ! confirmed( form ) ) {
					event.preventDefault();
				}
			} );
		} );

		var links = document.querySelectorAll( 'a[data-rapls-confirm]' );
		Array.prototype.forEach.call( links, function ( link ) {
			link.addEventListener( 'click', function ( event ) {
				if ( ! confirmed( link ) ) {
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
