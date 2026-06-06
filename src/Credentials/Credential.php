<?php
/**
 * Stored credential value object.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Credentials;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One row of the credentials table. `record_json` is the serialised
 * CredentialRecord (the source of truth verified against on assertion); the
 * other fields are denormalised for lookup and display.
 */
final class Credential {

	/**
	 * @param int         $id            Row id.
	 * @param int         $user_id       Owning WordPress user id.
	 * @param string      $credential_id Base64url credential id.
	 * @param string      $record_json   Serialised CredentialRecord JSON.
	 * @param int         $sign_count    Last seen signature counter.
	 * @param string|null $label         User-given label.
	 * @param string      $created_at    Creation timestamp (UTC).
	 * @param string|null $last_used_at  Last assertion timestamp (UTC), if any.
	 */
	public function __construct(
		public int $id,
		public int $user_id,
		public string $credential_id,
		public string $record_json,
		public int $sign_count,
		public ?string $label,
		public string $created_at,
		public ?string $last_used_at
	) {}
}
