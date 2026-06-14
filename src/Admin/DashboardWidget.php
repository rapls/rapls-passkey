<?php
/**
 * At-a-glance passkey adoption widget for the WordPress dashboard.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Audit\AuditLog;
use RaplsPasskey\Credentials\CredentialRepository;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds a dashboard widget summarising passkey adoption — total passkeys, how
 * many users have one (and the share of all users), and recent activity — so
 * administrators can monitor the rollout without opening the settings screen.
 * Visible only to users who can manage options.
 */
final class DashboardWidget {

	/**
	 * @param CredentialRepository $repository Credential storage.
	 */
	public function __construct( private CredentialRepository $repository ) {}

	/**
	 * Hook the dashboard setup.
	 */
	public function register(): void {
		add_action( 'wp_dashboard_setup', array( $this, 'add_widget' ) );
	}

	/**
	 * Register the widget for capable users.
	 */
	public function add_widget(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			'rapls_passkey_adoption',
			__( 'Rapls Passkey: Adoption', 'rapls-passkey' ),
			array( $this, 'render' )
		);
	}

	/**
	 * Render the widget body.
	 */
	public function render(): void {
		$stats = $this->repository->stats();
		$total = (int) $stats['total'];
		$users = (int) $stats['users'];

		$all_users = 0;
		if ( function_exists( 'count_users' ) ) {
			$counts    = count_users();
			$all_users = isset( $counts['total_users'] ) ? (int) $counts['total_users'] : 0;
		}
		$pct = $all_users > 0 ? (int) round( $users / $all_users * 100 ) : 0;

		$recent = $this->recent_activity( 30 );

		echo '<ul style="margin:0">';
		printf(
			'<li><strong>%s</strong>: %s</li>',
			esc_html__( 'Registered passkeys', 'rapls-passkey' ),
			esc_html( number_format_i18n( $total ) )
		);
		printf(
			'<li><strong>%s</strong>: %s</li>',
			esc_html__( 'Users with a passkey', 'rapls-passkey' ),
			esc_html(
				$all_users > 0
					/* translators: 1: users with a passkey, 2: total users, 3: percentage. */
					? sprintf( __( '%1$s / %2$s (%3$d%%)', 'rapls-passkey' ), number_format_i18n( $users ), number_format_i18n( $all_users ), $pct )
					: number_format_i18n( $users )
			)
		);
		printf(
			'<li><strong>%s</strong>: %s</li>',
			esc_html__( 'Last 30 days', 'rapls-passkey' ),
			esc_html(
				sprintf(
					/* translators: 1: passkey logins, 2: new registrations. */
					__( '%1$s logins / %2$s new registrations', 'rapls-passkey' ),
					number_format_i18n( $recent['login'] ),
					number_format_i18n( $recent['registered'] )
				)
			)
		);
		echo '</ul>';

		$links = array();
		if ( current_user_can( 'list_users' ) ) {
			$links[] = '<a href="' . esc_url( admin_url( 'users.php' ) ) . '">' . esc_html__( 'Users list', 'rapls-passkey' ) . '</a>';
		}
		$links[] = '<a href="' . esc_url( admin_url( 'options-general.php?page=rapls-passkey' ) ) . '">' . esc_html__( 'Settings', 'rapls-passkey' ) . '</a>';
		echo '<p style="margin:8px 0 0">' . wp_kses_post( implode( ' · ', $links ) ) . '</p>';
	}

	/**
	 * Count recent audit events by type within the last $days days.
	 *
	 * Reads a bounded slice of the audit log and tallies in PHP, so it adds no
	 * new query shape. With heavy traffic the slice may not reach a full 30 days;
	 * the figure is a lightweight indicator, not an exact report.
	 *
	 * @param int $days Window in days.
	 * @return array{login:int,registered:int}
	 */
	private function recent_activity( int $days ): array {
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, $days ) * DAY_IN_SECONDS );
		$out    = array(
			'login'      => 0,
			'registered' => 0,
		);
		foreach ( AuditLog::recent( 500 ) as $row ) {
			$created = (string) ( $row['created_at'] ?? '' );
			if ( '' === $created || $created < $cutoff ) {
				continue;
			}
			$event = (string) ( $row['event'] ?? '' );
			if ( isset( $out[ $event ] ) ) {
				++$out[ $event ];
			}
		}
		return $out;
	}
}
