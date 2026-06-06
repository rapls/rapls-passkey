<?php
/**
 * Ceremony step manager factory wrapper.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\WebAuthn;

use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds the verification ceremony pipelines, configured for this site's RP.
 *
 * The factory carries sensible defaults (ES256 + RS256 algorithms, the "none"
 * attestation statement, a clone-detecting counter checker). We only pin the
 * allowed origin and the secured RP ID so origin / rpIdHash checks match the
 * site exactly.
 */
final class Ceremonies {

	/**
	 * Configured library factory.
	 *
	 * @var CeremonyStepManagerFactory
	 */
	private CeremonyStepManagerFactory $factory;

	/**
	 * @param RelyingParty $rp Relying party identity.
	 */
	public function __construct( RelyingParty $rp ) {
		$factory = new CeremonyStepManagerFactory();
		$factory->setAllowedOrigins( array( $rp->origin() ), false );
		$factory->setSecuredRelyingPartyId( array( $rp->id() ) );
		$this->factory = $factory;
	}

	/**
	 * Pipeline for the registration (attestation) ceremony.
	 *
	 * @return CeremonyStepManager
	 */
	public function creation(): CeremonyStepManager {
		return $this->factory->creationCeremony();
	}

	/**
	 * Pipeline for the authentication (assertion) ceremony.
	 *
	 * @return CeremonyStepManager
	 */
	public function request(): CeremonyStepManager {
		return $this->factory->requestCeremony();
	}
}
