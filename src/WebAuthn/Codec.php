<?php
/**
 * JSON (de)serialisation bridge for WebAuthn objects.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wraps web-auth's Symfony serializer so the rest of the plugin works with
 * plain JSON strings: options go out to the browser as JSON, the browser's
 * credential responses come back as JSON, and stored CredentialRecords are
 * round-tripped to/from the database as JSON.
 */
final class Codec {

	/**
	 * Underlying serializer.
	 *
	 * @var SerializerInterface
	 */
	private SerializerInterface $serializer;

	public function __construct() {
		$attestation = new AttestationStatementSupportManager(
			array( NoneAttestationStatementSupport::create() )
		);
		$this->serializer = ( new WebauthnSerializerFactory( $attestation ) )->create();
	}

	/**
	 * Serialise any WebAuthn object to JSON, dropping null fields so the browser
	 * receives a clean PublicKeyCredential options object.
	 *
	 * @param object $object Object to serialise.
	 * @return string
	 */
	private function to_json( object $object ): string {
		return $this->serializer->serialize(
			$object,
			'json',
			array( AbstractObjectNormalizer::SKIP_NULL_VALUES => true )
		);
	}

	/**
	 * Creation options -> JSON.
	 *
	 * @param PublicKeyCredentialCreationOptions $options Options.
	 * @return string
	 */
	public function creation_options_to_json( PublicKeyCredentialCreationOptions $options ): string {
		return $this->to_json( $options );
	}

	/**
	 * Request options -> JSON.
	 *
	 * @param PublicKeyCredentialRequestOptions $options Options.
	 * @return string
	 */
	public function request_options_to_json( PublicKeyCredentialRequestOptions $options ): string {
		return $this->to_json( $options );
	}

	/**
	 * JSON -> creation options.
	 *
	 * @param string $json JSON.
	 * @return PublicKeyCredentialCreationOptions
	 */
	public function creation_options_from_json( string $json ): PublicKeyCredentialCreationOptions {
		return $this->serializer->deserialize( $json, PublicKeyCredentialCreationOptions::class, 'json' );
	}

	/**
	 * JSON -> request options.
	 *
	 * @param string $json JSON.
	 * @return PublicKeyCredentialRequestOptions
	 */
	public function request_options_from_json( string $json ): PublicKeyCredentialRequestOptions {
		return $this->serializer->deserialize( $json, PublicKeyCredentialRequestOptions::class, 'json' );
	}

	/**
	 * Browser credential JSON -> PublicKeyCredential.
	 *
	 * @param string $json JSON from navigator.credentials.{create,get}.
	 * @return PublicKeyCredential
	 */
	public function public_key_credential_from_json( string $json ): PublicKeyCredential {
		return $this->serializer->deserialize( $json, PublicKeyCredential::class, 'json' );
	}

	/**
	 * Base64url credential id extracted from a browser credential JSON, for
	 * looking up the stored record before verifying an assertion.
	 *
	 * @param string $json JSON from navigator.credentials.get.
	 * @return string Base64url credential id.
	 */
	public function credential_id_from_json( string $json ): string {
		$pkc = $this->public_key_credential_from_json( $json );
		return Base64UrlSafe::encodeUnpadded( $pkc->rawId );
	}

	/**
	 * CredentialRecord -> JSON (for storage).
	 *
	 * @param CredentialRecord $record Record.
	 * @return string
	 */
	public function record_to_json( CredentialRecord $record ): string {
		return $this->serializer->serialize( $record, 'json' );
	}

	/**
	 * JSON -> CredentialRecord (from storage).
	 *
	 * @param string $json JSON.
	 * @return CredentialRecord
	 */
	public function record_from_json( string $json ): CredentialRecord {
		return $this->serializer->deserialize( $json, CredentialRecord::class, 'json' );
	}
}
