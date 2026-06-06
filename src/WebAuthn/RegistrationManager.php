<?php
/**
 * Registration (attestation) ceremony.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use Cose\Algorithms;
use RaplsPasskey\Credentials\UserHandle;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialUserEntity;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Generates credential-creation options and verifies the attestation the
 * browser returns, yielding a CredentialRecord ready to store.
 */
final class RegistrationManager {

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
	 * Build creation options for a logged-in user.
	 *
	 * @param int               $user_id           User registering a passkey.
	 * @param string            $username          Account name (WebAuthn user.name).
	 * @param string            $display_name      Display name.
	 * @param CredentialRecord[] $existing_records Already-registered records to exclude.
	 * @return array{state:string,publicKey:array<string,mixed>}
	 */
	public function create_options( int $user_id, string $username, string $display_name, array $existing_records ): array {
		$user = PublicKeyCredentialUserEntity::create(
			$username,
			UserHandle::raw( $user_id ),
			'' !== $display_name ? $display_name : $username
		);

		$exclude = array();
		foreach ( $existing_records as $record ) {
			$exclude[] = PublicKeyCredentialDescriptor::create(
				PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
				$record->publicKeyCredentialId,
				$record->transports
			);
		}

		$options = PublicKeyCredentialCreationOptions::create(
			$this->rp->entity(),
			$user,
			random_bytes( 32 ),
			array(
				PublicKeyCredentialParameters::create( 'public-key', Algorithms::COSE_ALGORITHM_ES256 ),
				PublicKeyCredentialParameters::create( 'public-key', Algorithms::COSE_ALGORITHM_RS256 ),
			),
			AuthenticatorSelectionCriteria::create(
				null,
				AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
				AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED
			),
			PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
			$exclude
		);

		$json  = $this->codec->creation_options_to_json( $options );
		$state = $this->challenges->put( $json );

		return array(
			'state'     => $state,
			'publicKey' => json_decode( $json, true ),
		);
	}

	/**
	 * Verify the attestation response for a pending ceremony.
	 *
	 * @param string $state          State id from create_options().
	 * @param string $credential_json Browser credential JSON.
	 * @return CredentialRecord Verified record ready to persist.
	 * @throws \RuntimeException When the ceremony is unknown/expired or invalid.
	 */
	public function verify( string $state, string $credential_json ): CredentialRecord {
		$options_json = $this->challenges->take( $state );
		if ( null === $options_json ) {
			throw new \RuntimeException( 'ceremony_expired' );
		}

		$options = $this->codec->creation_options_from_json( $options_json );
		$pkc     = $this->codec->public_key_credential_from_json( $credential_json );

		$response = $pkc->response;
		if ( ! $response instanceof AuthenticatorAttestationResponse ) {
			throw new \RuntimeException( 'not_an_attestation' );
		}

		$validator = AuthenticatorAttestationResponseValidator::create( $this->ceremonies->creation() );

		return $validator->check( $response, $options, $this->rp->id() );
	}
}
