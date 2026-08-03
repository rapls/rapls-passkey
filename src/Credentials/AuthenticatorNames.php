<?php
/**
 * Maps an authenticator's AAGUID to a human-readable provider name.
 *
 * Passkey providers (iCloud Keychain, Google Password Manager, Windows Hello,
 * 1Password, hardware security keys, …) identify themselves with a 128-bit
 * AAGUID embedded in the credential record. Showing the provider name instead of
 * a raw id helps users tell their passkeys apart ("which device is this?") and
 * helps admins audit what is in use.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

defined( 'ABSPATH' ) || exit;

/**
 * Curated AAGUID -> provider-name lookup.
 *
 * The bundled list is a deliberately small, high-confidence subset of the
 * community AAGUID registry (the most common platform providers, password
 * managers, and security keys). It is not exhaustive — extend or override it
 * with the `rapls_passkey/authenticator_names` filter. Unknown or privacy-zeroed
 * AAGUIDs simply resolve to no name (callers fall back to the user label).
 */
final class AuthenticatorNames {

	/** The all-zero AAGUID reported when the provider is hidden for privacy. */
	public const ZERO_AAGUID = '00000000-0000-0000-0000-000000000000';

	/**
	 * Bundled AAGUID (lowercase canonical UUID) -> display name map.
	 *
	 * @return array<string,string>
	 */
	private static function map(): array {
		$map = array(
			// Platform & synced credential providers.
			'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => 'Google Password Manager',
			'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' => 'iCloud Keychain',
			'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' => 'iCloud Keychain (Managed)',
			'08987058-cadc-4b81-b6e1-30de50dcbe96' => 'Windows Hello',
			'9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => 'Windows Hello',
			'6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => 'Windows Hello',
			'adce0002-35bc-c60a-648b-0b25f1f05503' => 'Chrome on Mac',

			// Password managers.
			'bada5566-a7aa-401f-bd96-45619a55122d' => '1Password',
			'd548826e-79b4-db40-a3d8-11116f7e8349' => 'Bitwarden',
			'531126d6-e717-415c-9320-3d9aa6986aa2' => 'Dashlane',
			'b84e4048-15dc-4dd0-8640-f4f60813c8af' => 'NordPass',
			'0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6' => 'Keeper',
			'f3809540-7f14-49c1-a8b3-8f813b225541' => 'Enpass',

			// Hardware security keys (Yubico).
			'ee882879-721c-4913-9775-3dfcce97072a' => 'YubiKey 5 Series',
			'fa2b99dc-9e39-4257-8f92-4a30d23c4118' => 'YubiKey 5 Series',
			'cb69481e-8ff7-4039-93ec-0a2729a154a8' => 'YubiKey 5 Series',
			'2fc0579f-8113-47ea-b116-bb5a8db9202a' => 'YubiKey 5 Series',
			'73bb0cd4-e502-49b8-9c6f-b59445bf720b' => 'YubiKey 5 FIPS Series',
			'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd' => 'YubiKey 5 FIPS Series',
			'd8522d9f-575b-4866-88a9-ba99fa02f35b' => 'YubiKey Bio Series',
			'f8a011f3-8c0a-4d15-8006-17111f9edc7d' => 'Security Key by Yubico',
			'b92c3f9a-c014-4056-887f-140a2501163b' => 'Security Key by Yubico',
		);

		/**
		 * Filter the AAGUID -> provider-name map.
		 *
		 * Keys must be lowercase canonical UUID strings. Use this to add
		 * authenticators the bundled list does not cover, or to localise names.
		 *
		 * @param array<string,string> $map AAGUID => display name.
		 */
		return (array) apply_filters( 'rapls_passkey/authenticator_names', $map );
	}

	/**
	 * Pull the (non-zero) AAGUID out of a stored CredentialRecord JSON.
	 *
	 * @param string $record_json Serialised CredentialRecord.
	 * @return string|null Lowercase canonical UUID, or null when absent/zeroed.
	 */
	public static function aaguid_from_record( string $record_json ): ?string {
		$data = json_decode( $record_json, true );
		if ( ! is_array( $data ) || empty( $data['aaguid'] ) || ! is_string( $data['aaguid'] ) ) {
			return null;
		}

		$aaguid = strtolower( trim( $data['aaguid'] ) );
		if ( '' === $aaguid || self::ZERO_AAGUID === $aaguid ) {
			return null;
		}

		return $aaguid;
	}

	/**
	 * Provider name for an AAGUID, or null if unknown.
	 *
	 * @param string|null $aaguid Lowercase or mixed-case UUID.
	 * @return string|null
	 */
	public static function name_for_aaguid( ?string $aaguid ): ?string {
		if ( null === $aaguid || '' === $aaguid ) {
			return null;
		}
		$map = self::map();
		return $map[ strtolower( $aaguid ) ] ?? null;
	}

	/**
	 * Provider name derived from a stored CredentialRecord JSON, or null.
	 *
	 * @param string $record_json Serialised CredentialRecord.
	 * @return string|null
	 */
	public static function name_for_record( string $record_json ): ?string {
		return self::name_for_aaguid( self::aaguid_from_record( $record_json ) );
	}

	/**
	 * Display string for a record: the provider name, else the given fallback.
	 *
	 * @param string $record_json Serialised CredentialRecord.
	 * @param string $fallback    Returned when the provider is unknown.
	 * @return string
	 */
	public static function display( string $record_json, string $fallback = '' ): string {
		$name = self::name_for_record( $record_json );
		return ( null !== $name ) ? $name : $fallback;
	}
}
