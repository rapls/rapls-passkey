<?php
/**
 * Site Health self-checks for common passkey setup problems.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Admin;

use RaplsPasskey\Support\OneTimeStore;

use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Support\Compat;
use RaplsPasskey\WebAuthn\RelyingParty;

defined( 'ABSPATH' ) || exit;

/**
 * Adds checks under Tools → Site Health for the things that most often break a
 * passkey setup — no HTTPS, the WebAuthn library missing, the custom tables not
 * created, an unexpected RP ID — so a site owner can spot and fix them before
 * users get locked out, instead of opening a support ticket.
 */
final class SiteHealth {

	/** Key of the marker used to prove the object cache spans two requests. */
	private const CACHE_CANARY = 'cachecanary';

	/**
	 * Hook the Site Health tests.
	 */
	public function register(): void {
		add_filter( 'site_status_tests', array( $this, 'add_tests' ) );
		add_filter( 'debug_information', array( $this, 'add_debug_info' ) );
	}

	/**
	 * Add a "Rapls Passkey" panel to Site Health → Info (and the export). This is
	 * the tab most admins look at; the pass/fail checks live under Status.
	 *
	 * @param array<string,mixed> $info Existing debug information.
	 * @return array<string,mixed>
	 */
	public function add_debug_info( $info ): array {
		$info = is_array( $info ) ? $info : array();

		$secure   = is_ssl() || $this->is_local_host();
		$library  = class_exists( \Webauthn\PublicKeyCredentialSource::class );
		$tables   = $this->tables_exist();
		$detected = Compat::detect();

		$yes = __( 'Yes', 'rapls-passkey' );
		$no  = __( 'No', 'rapls-passkey' );

		$info['rapls-passkey'] = array(
			'label'  => __( 'Rapls Passkey', 'rapls-passkey' ),
			'fields' => array(
				'version'         => array(
					'label' => __( 'Version', 'rapls-passkey' ),
					'value' => defined( 'RAPLS_PASSKEY_VERSION' ) ? RAPLS_PASSKEY_VERSION : '',
				),
				'https'           => array(
					'label' => __( 'HTTPS / secure context', 'rapls-passkey' ),
					'value' => $secure ? $yes : $no,
					'debug' => $secure ? 'true' : 'false',
				),
				'library'         => array(
					'label' => __( 'WebAuthn library', 'rapls-passkey' ),
					'value' => $library ? __( 'Loaded', 'rapls-passkey' ) : __( 'Not found', 'rapls-passkey' ),
					'debug' => $library ? 'true' : 'false',
				),
				'tables'          => array(
					'label' => __( 'Database tables', 'rapls-passkey' ),
					'value' => $tables ? __( 'Present', 'rapls-passkey' ) : __( 'Not created', 'rapls-passkey' ),
					'debug' => $tables ? 'true' : 'false',
				),
				'rp_id'           => array(
					'label' => 'RP ID',
					'value' => RelyingParty::from_site()->id(),
				),
				'registered'      => array(
					'label' => __( 'Total registered passkeys', 'rapls-passkey' ),
					'value' => (string) $this->total_credentials(),
				),
				'security_plugins' => array(
					'label' => __( 'Detected security plugins', 'rapls-passkey' ),
					'value' => array() === $detected ? __( 'None', 'rapls-passkey' ) : implode( ', ', $detected ),
				),
			),
		);

		return $info;
	}

	/**
	 * Register our direct (synchronous) tests.
	 *
	 * @param array<string,mixed> $tests Existing tests.
	 * @return array<string,mixed>
	 */
	public function add_tests( $tests ): array {
		$tests = is_array( $tests ) ? $tests : array();

		$tests['direct']['rapls_passkey_https']   = array(
			'label' => __( 'Rapls Passkey: HTTPS', 'rapls-passkey' ),
			'test'  => array( $this, 'test_https' ),
		);
		$tests['direct']['rapls_passkey_library'] = array(
			'label' => __( 'Rapls Passkey: WebAuthn library', 'rapls-passkey' ),
			'test'  => array( $this, 'test_library' ),
		);
		$tests['direct']['rapls_passkey_tables']  = array(
			'label' => __( 'Rapls Passkey: Database', 'rapls-passkey' ),
			'test'  => array( $this, 'test_tables' ),
		);
		$tests['direct']['rapls_passkey_rp']      = array(
			'label' => __( 'Rapls Passkey: RP ID', 'rapls-passkey' ),
			'test'  => array( $this, 'test_rp' ),
		);
		$tests['direct']['rapls_passkey_cache']   = array(
			'label' => __( 'Rapls Passkey: Object cache', 'rapls-passkey' ),
			'test'  => array( $this, 'test_object_cache' ),
		);

		return $tests;
	}

	// --- Tests ---------------------------------------------------------------

	/**
	 * HTTPS / secure context.
	 *
	 * @return array<string,mixed>
	 */
	public function test_https(): array {
		$secure = is_ssl() || $this->is_local_host();
		$desc   = $secure
			? __( 'The site is served over a secure context (HTTPS).', 'rapls-passkey' )
			: __( 'Passkeys require HTTPS (a secure context). Install an SSL certificate and serve the site over HTTPS (except on localhost).', 'rapls-passkey' );

		return $this->result( 'rapls_passkey_https', __( 'Rapls Passkey: HTTPS', 'rapls-passkey' ), self::https_status( $secure ), $desc );
	}

	/**
	 * WebAuthn library availability.
	 *
	 * @return array<string,mixed>
	 */
	public function test_library(): array {
		$present = class_exists( \Webauthn\PublicKeyCredentialSource::class );
		$desc    = $present
			? __( 'The WebAuthn library is loaded.', 'rapls-passkey' )
			: __( 'The WebAuthn library was not found. Run `composer install` to install dependencies. Passkey authentication is disabled.', 'rapls-passkey' );

		return $this->result( 'rapls_passkey_library', __( 'Rapls Passkey: WebAuthn library', 'rapls-passkey' ), self::library_status( $present ), $desc );
	}

	/**
	 * Custom tables present.
	 *
	 * @return array<string,mixed>
	 */
	public function test_tables(): array {
		$present = $this->tables_exist();
		$desc    = $present
			? __( 'The credential and audit-log tables exist.', 'rapls-passkey' )
			: __( 'The plugin database tables were not found. Deactivate and reactivate the plugin to create them.', 'rapls-passkey' );

		return $this->result( 'rapls_passkey_tables', __( 'Rapls Passkey: Database', 'rapls-passkey' ), self::tables_status( $present ), $desc );
	}

	/**
	 * Relying Party ID information (always informational).
	 *
	 * @return array<string,mixed>
	 */
	public function test_rp(): array {
		$rp_id     = RelyingParty::from_site()->id();
		$host      = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$detected  = Compat::detect();
		$compat    = array() === $detected
			? __( 'No known login-security plugins are detected.', 'rapls-passkey' )
			: sprintf(
				/* translators: %s: comma-separated plugin names. */
				__( 'Detected security plugins: %s. The plugin adapts automatically to work even when the REST API is restricted.', 'rapls-passkey' ),
				implode( ', ', $detected )
			);

		$desc = sprintf(
			/* translators: 1: RP ID, 2: site host. */
			__( 'The current RP ID is %1$s and the site host is %2$s. The RP ID determines the scope of passkeys (changeable via the rapls_passkey_rp_id filter).', 'rapls-passkey' ),
			$rp_id,
			$host
		) . ' ' . $compat;

		return $this->result( 'rapls_passkey_rp', __( 'Rapls Passkey: RP ID', 'rapls-passkey' ), 'good', $desc );
	}

	// --- Pure status decisions (unit-testable) -------------------------------

	/**
	 * @param bool $secure Secure context.
	 * @return string
	 */
	/**
	 * Whether the object cache actually carries a value from one request to the
	 * next.
	 *
	 * WordPress treats an installed `object-cache.php` as one store that carries
	 * a value from one request to the next. Whether it does is up to the host:
	 * separate PHP-FPM instances and separate servers do not share an APCu
	 * segment, and any cache can evict an entry or lose the generation counter a
	 * drop-in namespaces by. When it does not carry, anything spanning two
	 * requests fails at random — sign-ins among them. This plugin no longer
	 * depends on it (login state goes straight to the database), but the rest of
	 * the site still does, so it is worth saying out loud.
	 *
	 * The check leaves a value behind and looks for it on the next run, because
	 * the two have to happen in different requests to prove anything. Nothing is
	 * reported until a miss has actually been seen.
	 *
	 * @return array<string,mixed>
	 */
	public function test_object_cache(): array {
		$label = __( 'Rapls Passkey: Object cache', 'rapls-passkey' );
		$key   = 'rapls_passkey_cache';

		if ( ! function_exists( 'wp_using_ext_object_cache' ) || ! wp_using_ext_object_cache() ) {
			return $this->result(
				$key,
				$label,
				'good',
				__( 'No persistent object cache is installed, so nothing sits between one request and the next.', 'rapls-passkey' )
			);
		}

		// The database is the reference: it is the same for every worker.
		$expected = OneTimeStore::peek( self::CACHE_CANARY );
		$seen     = wp_cache_get( self::CACHE_CANARY, 'rapls_passkey' );

		// Leave a fresh marker for the next run before answering.
		$nonce = bin2hex( random_bytes( 8 ) );
		OneTimeStore::put( self::CACHE_CANARY, $nonce, HOUR_IN_SECONDS );
		wp_cache_set( self::CACHE_CANARY, $nonce, 'rapls_passkey', HOUR_IN_SECONDS );

		if ( null === $expected ) {
			return $this->result(
				$key,
				$label,
				'good',
				__( 'A persistent object cache is installed. Reload this page once to confirm that it carries values between requests.', 'rapls-passkey' )
			);
		}

		if ( is_string( $seen ) && hash_equals( $expected, $seen ) ) {
			return $this->result(
				$key,
				$label,
				'good',
				__( 'The object cache carries values between requests, which is what WordPress expects of it.', 'rapls-passkey' )
			);
		}

		return $this->result(
			$key,
			$label,
			'recommended',
			__( 'The object cache did not return a value written by an earlier request. Anything that spans two requests — signing in, a two-factor challenge, a form token — can then fail at random. Common causes are an APCu cache too small for the site (entries are evicted), and more than one PHP-FPM instance or server, which do not share one APCu segment. Check the cache size and hit rate, or remove wp-content/object-cache.php.', 'rapls-passkey' )
		);
	}

	// --- Status helpers ------------------------------------------------------

	public static function https_status( bool $secure ): string {
		return $secure ? 'good' : 'critical';
	}

	/**
	 * @param bool $present Library present.
	 * @return string
	 */
	public static function library_status( bool $present ): string {
		return $present ? 'good' : 'critical';
	}

	/**
	 * @param bool $present Tables present.
	 * @return string
	 */
	public static function tables_status( bool $present ): string {
		return $present ? 'good' : 'recommended';
	}

	// --- Helpers -------------------------------------------------------------

	/**
	 * Build a Site Health result array.
	 *
	 * @param string $key         Test key.
	 * @param string $label       Test label.
	 * @param string $status      good|recommended|critical.
	 * @param string $description Plain-text description.
	 * @return array<string,mixed>
	 */
	private function result( string $key, string $label, string $status, string $description ): array {
		$colors = array(
			'good'        => 'green',
			'recommended' => 'orange',
			'critical'    => 'red',
		);

		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'rapls-passkey' ),
				'color' => $colors[ $status ] ?? 'gray',
			),
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'test'        => $key,
		);
	}

	/**
	 * Whether the site host is a local development host (HTTPS not required).
	 *
	 * @return bool
	 */
	private function is_local_host(): bool {
		// Only true loopback hosts are secure contexts without HTTPS. Browsers do
		// not exempt .local/.test, so neither do we — matching SetupWizard so the
		// two screens never disagree about whether the site can use WebAuthn.
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		return in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true );
	}

	/**
	 * Total registered passkeys (0 if the table is missing).
	 *
	 * @return int
	 */
	private function total_credentials(): int {
		if ( ! $this->tables_exist() ) {
			return 0;
		}
		global $wpdb;
		$table = Schema::credentials_table();
		// phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
	}

	/**
	 * Whether both custom tables exist.
	 *
	 * @return bool
	 */
	private function tables_exist(): bool {
		global $wpdb;
		foreach ( array( Schema::credentials_table(), Schema::audit_table() ) as $table ) {
			// phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
			if ( $found !== $table ) {
				return false;
			}
		}
		return true;
	}
}
