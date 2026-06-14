<?php
/**
 * WordPress privacy (GDPR) integration: personal-data exporter and eraser, plus
 * cleanup when a user is deleted.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Privacy;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Credentials\UserHandle;
use RaplsPasskey\Security\Notifications;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hooks the WordPress privacy tools so a user's passkey data participates in
 * "Export Personal Data" and "Erase Personal Data" requests, and is removed
 * when the WordPress account itself is deleted.
 *
 * Exported: each registered passkey (label, dates, credential id) and the
 * user's audit-log rows (event, time, IP). Erased: those same records plus the
 * device-recognition and user-handle meta. The stored public key is the user's
 * own credential, not a site secret, so surfacing its id in an export is safe.
 */
final class PersonalData {

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Register the privacy hooks.
	 */
	public function register(): void {
		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_eraser' ) );
		add_action( 'deleted_user', array( $this, 'purge_user' ) );
	}

	/**
	 * Add our exporter.
	 *
	 * @param mixed $exporters Registered exporters.
	 * @return array<string,mixed>
	 */
	public function register_exporter( $exporters ): array {
		$exporters = is_array( $exporters ) ? $exporters : array();
		$exporters['rapls-passkey'] = array(
			'exporter_friendly_name' => __( 'Rapls Passkey (Passkey)', 'rapls-passkey' ),
			'callback'               => array( $this, 'export' ),
		);
		return $exporters;
	}

	/**
	 * Add our eraser.
	 *
	 * @param mixed $erasers Registered erasers.
	 * @return array<string,mixed>
	 */
	public function register_eraser( $erasers ): array {
		$erasers = is_array( $erasers ) ? $erasers : array();
		$erasers['rapls-passkey'] = array(
			'eraser_friendly_name' => __( 'Rapls Passkey (Passkey)', 'rapls-passkey' ),
			'callback'             => array( $this, 'erase' ),
		);
		return $erasers;
	}

	/**
	 * Export a user's passkey and audit data.
	 *
	 * @param string $email Email address of the data subject.
	 * @param int    $page  Page number (all data fits on page 1 here).
	 * @return array{data:array<int,array<string,mixed>>,done:bool}
	 */
	public function export( $email, $page = 1 ): array {
		unset( $page );
		$data = array();
		$user = get_user_by( 'email', (string) $email );

		if ( $user ) {
			$uid = (int) $user->ID;

			foreach ( $this->repository->find_by_user( $uid ) as $c ) {
				$data[] = array(
					'group_id'    => 'rapls-passkey-credentials',
					'group_label' => __( 'Passkey', 'rapls-passkey' ),
					'item_id'     => 'rapls-passkey-credential-' . $c->id,
					'data'        => array(
						array(
							'name'  => __( 'Name', 'rapls-passkey' ),
							'value' => ( null !== $c->label && '' !== $c->label ) ? $c->label : '—',
						),
						array(
							'name'  => __( 'Registered', 'rapls-passkey' ),
							'value' => $c->created_at,
						),
						array(
							'name'  => __( 'Last used', 'rapls-passkey' ),
							'value' => $c->last_used_at ? $c->last_used_at : '—',
						),
						array(
							'name'  => __( 'Credential ID', 'rapls-passkey' ),
							'value' => $c->credential_id,
						),
					),
				);
			}

			foreach ( AuditLog::for_user( $uid ) as $row ) {
				$data[] = array(
					'group_id'    => 'rapls-passkey-audit',
					'group_label' => __( 'Passkey audit log', 'rapls-passkey' ),
					'item_id'     => 'rapls-passkey-audit-' . (int) $row['id'],
					'data'        => array(
						array(
							'name'  => __( 'Event', 'rapls-passkey' ),
							'value' => (string) $row['event'],
						),
						array(
							'name'  => __( 'Date/time (UTC)', 'rapls-passkey' ),
							'value' => (string) $row['created_at'],
						),
						array(
							'name'  => 'IP',
							'value' => (string) ( $row['ip'] ?? '' ),
						),
					),
				);
			}
		}

		return array(
			'data' => $data,
			'done' => true,
		);
	}

	/**
	 * Erase a user's passkey and audit data.
	 *
	 * @param string $email Email address of the data subject.
	 * @param int    $page  Page number (single pass here).
	 * @return array{items_removed:bool,items_retained:bool,messages:array<int,string>,done:bool}
	 */
	public function erase( $email, $page = 1 ): array {
		unset( $page );
		$removed = false;
		$user    = get_user_by( 'email', (string) $email );
		if ( $user ) {
			$removed = $this->purge_user( (int) $user->ID );
		}

		return array(
			'items_removed'  => $removed,
			'items_retained' => false,
			'messages'       => array(),
			'done'           => true,
		);
	}

	/**
	 * Remove every stored trace of a user: credentials, audit rows, and the
	 * device-recognition / user-handle meta. Also the `deleted_user` callback.
	 *
	 * @param int $user_id User id.
	 * @return bool True if anything was removed.
	 */
	public function purge_user( $user_id ): bool {
		$uid = (int) $user_id;
		if ( $uid <= 0 ) {
			return false;
		}

		$removed = $this->repository->delete_all_for_user( $uid ) > 0;
		if ( AuditLog::delete_for_user( $uid ) ) {
			$removed = true;
		}
		if ( delete_user_meta( $uid, Notifications::SEEN_META ) ) {
			$removed = true;
		}
		if ( delete_user_meta( $uid, UserHandle::META ) ) {
			$removed = true;
		}

		return $removed;
	}
}
