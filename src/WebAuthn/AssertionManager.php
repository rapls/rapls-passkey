<?php
/**
 * Authentication (assertion) ceremony.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use RaplsPasskey\Support\Settings;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates credential-request options and verifies the assertion the browser
 * returns against a stored credential record.
 */
final class AssertionManager {

	/**
	 * @param RelyingParty   $rp         Relying party identity.
	 * @param Codec          $codec      Serialisation bridge.
	 * @param ChallengeStore $challenges Ceremony state store.
	 * @param Ceremonies     $ceremonies Verification pipelines.
	 */
	public function __construct(
		private RelyingParty $rp,
		private Codec $codec,
		private ChallengeStore $challenges,
		private Ceremonies $ceremonies
	) {}

	/**
	 * Build request options.
	 *
	 * @param CredentialRecord[] $allowed_records Records to allow (empty = discoverable / usernameless).
	 * @param string|null        $user_verification Override the UV requirement
	 *        (required|preferred|discouraged). MFA contexts (step-up, QR second
	 *        factor) pass "required" so the library enforces the UV flag; null uses
	 *        the site's compatibility-first setting for ordinary login.
	 * @return array{state:string,publicKey:array<string,mixed>}
	 */
	public function create_options( array $allowed_records, ?string $user_verification = null ): array {
		$allow = array();
		foreach ( $allowed_records as $record ) {
			$allow[] = PublicKeyCredentialDescriptor::create(
				PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
				$record->publicKeyCredentialId,
				$record->transports
			);
		}

		$uv = in_array( $user_verification, array( 'required', 'preferred', 'discouraged' ), true )
			? $user_verification
			: Settings::webauthn_user_verification();

		$options = PublicKeyCredentialRequestOptions::create(
			random_bytes( 32 ),
			$this->rp->id(),
			$allow,
			$uv,
			Settings::webauthn_timeout()
		);

		$json      = $this->codec->request_options_to_json( $options );
		$state     = $this->challenges->put( $json );
		$public_key = json_decode( $json, true );

		// Client UI hints only steer the browser picker and are not verified, so
		// they are added to the client-facing options, not the stored ceremony.
		$hints = Settings::webauthn_hints();
		if ( array() !== $hints ) {
			$public_key['hints'] = $hints;
		}

		return array(
			'state'     => $state,
			'publicKey' => $public_key,
		);
	}

	/**
	 * Verify the assertion response against a stored record.
	 *
	 * @param string           $state           State id from create_options().
	 * @param string           $credential_json Browser credential JSON.
	 * @param CredentialRecord $stored          The looked-up stored record.
	 * @return CredentialRecord Updated record (counter advanced) to persist.
	 * @throws \RuntimeException When the ceremony is unknown/expired or invalid.
	 */
	public function verify( string $state, string $credential_json, CredentialRecord $stored ): CredentialRecord {
		$options_json = $this->challenges->take( $state );
		if ( null === $options_json ) {
			throw new \RuntimeException( 'ceremony_expired' );
		}

		$options = $this->codec->request_options_from_json( $options_json );
		$pkc     = $this->codec->public_key_credential_from_json( $credential_json );

		$response = $pkc->response;
		if ( ! $response instanceof AuthenticatorAssertionResponse ) {
			throw new \RuntimeException( 'not_an_assertion' );
		}

		$validator = AuthenticatorAssertionResponseValidator::create( $this->ceremonies->request() );

		// The expected user handle must match the stored record's; passing the
		// record's own handle satisfies CheckUserHandle for both discoverable and
		// non-discoverable credentials.
		return $validator->check(
			$stored,
			$response,
			$options,
			$this->rp->id(),
			$stored->userHandle
		);
	}
}
