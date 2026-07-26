<?php
/**
 * Integration test: the SHIPPED plugin classes against a real MySQL/MariaDB.
 *
 * Where tests/db/concurrency.php proves the database serialises unique claims,
 * this proves the plugin's own code does the right thing on a real server —
 * migration from the previous schema, the cap refusing when its index is gone,
 * fail-closed on a database error, an idempotent replay, and the attempt limit
 * under simultaneous processes.
 *
 * Usage:
 *   php tests/db/integration.php --host=127.0.0.1 --port=3306 --db=test \
 *       --user=root --pass=secret [--workers=20] [--json=out.json]
 *   php tests/db/integration.php --socket=/path/mysqld.sock --db=local --user=root --pass=root
 *
 * Exit code 0 only when every scenario passes.
 *
 * @package RaplsPasskey
 */

// phpcs:disable

namespace RaplsPasskey\WebAuthn {
	class RegistrationManager {}
	class AssertionManager {}
	class Codec {
		public function record_to_json( $record ) { return '{}'; }
	}
}
namespace RaplsPasskey\Support {
	class Str {
		public static function substr( $s, $a, $b ) { return substr( $s, $a, $b ); }
	}
	class Settings {
		public static $max = 0;
		public static function max_passkeys(): int { return self::$max; }
		public static function login_rate_max(): int { return 0; }
		public static function login_rate_window(): int { return 300; }
	}
}
namespace RaplsPasskey\Audit {
	class AuditLog {
		const REGISTERED = 'registered';
		public static function record( ...$a ) {}
	}
}

namespace {

$opts = array(
	'host'    => '127.0.0.1',
	'port'    => 3306,
	'socket'  => null,
	'db'      => 'test',
	'user'    => 'root',
	'pass'    => '',
	'workers' => 20,
	'json'    => '',
	'worker'  => '',
	'arg'     => '',
	'start'   => '',
);
foreach ( array_slice( $argv, 1 ) as $a ) {
	if ( preg_match( '/^--([a-z]+)=(.*)$/s', $a, $m ) ) {
		$opts[ $m[1] ] = $m[2];
	}
}
$opts['workers'] = max( 2, (int) $opts['workers'] );

define( 'ABSPATH', __DIR__ . '/' );
if ( ! defined( 'ARRAY_A' ) ) { define( 'ARRAY_A', 'ARRAY_A' ); }

// --- The WordPress surface the classes under test touch ---------------------

$GLOBALS['__options'] = array();
function get_option( $k, $default = false ) { return $GLOBALS['__options'][ $k ] ?? $default; }
function update_option( $k, $v, $autoload = null ) { $GLOBALS['__options'][ $k ] = $v; return true; }
function delete_option( $k ) { unset( $GLOBALS['__options'][ $k ] ); return true; }
function wp_rand( $min = 0, $max = 1 ) { return random_int( $min, $max ); }
function apply_filters( $tag, $value ) { return $value; }
function esc_sql( $s ) { return $s; }
function dbDelta( $sql ) {
	global $wpdb;
	// The real dbDelta diffs the schema; for a fresh test table CREATE TABLE IF
	// NOT EXISTS plus the ADD COLUMN the migration needs is enough.
	foreach ( array_filter( array_map( 'trim', explode( ";\n", $sql . "\n" ) ) ) as $stmt ) {
		if ( '' === $stmt ) { continue; }
		$wpdb->query( str_replace( 'CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', rtrim( $stmt, ';' ) ) );
	}
	// Bring an older table up to the current column set (what dbDelta does for us
	// on a real site).
	$table = $wpdb->prefix . 'rapls_passkey_credentials';
	$cols  = $wpdb->get_col( "SHOW COLUMNS FROM {$table}" );
	if ( $cols && ! in_array( 'slot_no', $cols, true ) ) {
		$wpdb->query( "ALTER TABLE {$table} ADD COLUMN slot_no bigint(20) unsigned DEFAULT NULL AFTER user_id" );
	}
	return array();
}
@mkdir( __DIR__ . '/wp-admin/includes', 0777, true );
if ( ! file_exists( __DIR__ . '/wp-admin/includes/upgrade.php' ) ) {
	file_put_contents( __DIR__ . '/wp-admin/includes/upgrade.php', "<?php\n" );
}

class WP_Error {
	private $code; private $message; private $data;
	public function __construct( $code = '', $message = '', $data = array() ) {
		$this->code = $code; $this->message = $message; $this->data = $data;
	}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
	public function get_error_data() { return $this->data; }
}
class WP_REST_Request {}
class WP_REST_Response {}
class WP_REST_Server { const READABLE = 'GET'; const CREATABLE = 'POST'; const EDITABLE = 'PUT'; const DELETABLE = 'DELETE'; }
function __( $s, $d = null ) { return $s; }
function esc_html__( $s, $d = null ) { return $s; }
function add_action( ...$a ) {}
function add_filter( ...$a ) {}
function do_action( ...$a ) {}
function is_user_logged_in() { return true; }
function wp_get_current_user() { return (object) array( 'ID' => 1 ); }
function rest_ensure_response( $r ) { return $r; }
function sanitize_text_field( $s ) { return is_string( $s ) ? trim( $s ) : ''; }
function wp_unslash( $s ) { return $s; }
function hash_equals_stub() {}

require_once __DIR__ . '/wpdb-lite.php';
require_once dirname( __DIR__, 2 ) . '/src/Credentials/Schema.php';
require_once dirname( __DIR__, 2 ) . '/src/Credentials/Credential.php';
require_once dirname( __DIR__, 2 ) . '/src/Credentials/CredentialRepository.php';
require_once dirname( __DIR__, 2 ) . '/src/Support/RateLimit.php';
require_once dirname( __DIR__, 2 ) . '/src/Rest/Endpoints.php';

use RaplsPasskey\Credentials\CredentialRepository;
use RaplsPasskey\Credentials\Schema;
use RaplsPasskey\Rest\Endpoints;
use RaplsPasskey\Support\RateLimit;
use RaplsPasskey\Support\Settings;

$GLOBALS['wpdb'] = new WPDB_Lite( WPDB_Lite::connect( $opts ) );
$wpdb            = $GLOBALS['wpdb'];
$table           = Schema::credentials_table();

/**
 * Call the SHIPPED Rest\Endpoints::store_credential() — the code that actually
 * runs in production — rather than a copy of its logic. Returns the stored row id,
 * or the negative HTTP status the endpoint would answer with.
 */
function claim_credential( CredentialRepository $repo, int $user_id, string $credential_id, int $max ): int {
	Settings::$max = $max;
	$ep  = ( new ReflectionClass( Endpoints::class ) )->newInstanceWithoutConstructor();
	$ref = new ReflectionClass( Endpoints::class );
	foreach ( array( 'repository' => $repo, 'codec' => new RaplsPasskey\WebAuthn\Codec() ) as $prop => $value ) {
		$p = $ref->getProperty( $prop );
		$p->setAccessible( true );
		$p->setValue( $ep, $value );
	}
	$m = $ref->getMethod( 'store_credential' );
	$m->setAccessible( true );

	$record = new stdClass();
	$record->counter = 0;

	$out = $m->invoke( $ep, $user_id, $credential_id, $record, null );
	if ( $out instanceof WP_Error ) {
		$data = $out->get_error_data();
		return -( (int) ( $data['status'] ?? 500 ) );
	}
	return (int) $out;
}

// --- Worker mode ------------------------------------------------------------

if ( '' !== $opts['worker'] ) {
	Schema::flush_cap_cache();
	$target = (float) $opts['start'];
	while ( microtime( true ) * 1e6 < $target ) {
		usleep( 200 );
	}
	if ( 'register' === $opts['worker'] ) {
		list( $user_id, $max, $tag ) = explode( ':', $opts['arg'] );
		$id = claim_credential( new CredentialRepository(), (int) $user_id, $tag, (int) $max );
		echo ( $id > 0 ? "OK id={$id}\n" : "NO {$id}\n" );
		exit( 0 );
	}
	if ( 'admit' === $opts['worker'] ) {
		list( $key, $window, $max ) = explode( ':', $opts['arg'] );
		$slot = RateLimit::admit( $key, (int) $window, (int) $max );
		echo ( $slot > 0 ? "OK slot={$slot}\n" : "NO 0\n" );
		exit( 0 );
	}
	echo "NO unknown\n";
	exit( 0 );
}

// --- Controller -------------------------------------------------------------

$php  = PHP_BINARY;
$self = __FILE__;
$conn = $opts['socket']
	? '--socket=' . escapeshellarg( $opts['socket'] )
	: '--host=' . escapeshellarg( $opts['host'] ) . ' --port=' . (int) $opts['port'];
$conn .= ' --db=' . escapeshellarg( $opts['db'] ) . ' --user=' . escapeshellarg( $opts['user'] ) . ' --pass=' . escapeshellarg( $opts['pass'] );

function run( string $mode, string $arg, int $n, string $php, string $self, string $conn ): array {
	$start = (string) (int) ( ( microtime( true ) + 1.5 ) * 1e6 );
	$procs = array();
	$pipes = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$cmd = escapeshellarg( $php ) . ' ' . escapeshellarg( $self ) . " {$conn}"
			. ' --worker=' . escapeshellarg( $mode )
			. ' --arg=' . escapeshellarg( str_replace( '{i}', (string) $i, $arg ) )
			. ' --start=' . escapeshellarg( $start );
		$p = proc_open( $cmd, array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pp );
		if ( is_resource( $p ) ) { $procs[ $i ] = $p; $pipes[ $i ] = $pp; }
	}
	$out = array();
	foreach ( $procs as $i => $p ) {
		$out[] = trim( (string) stream_get_contents( $pipes[ $i ][1] ) );
		fclose( $pipes[ $i ][1] );
		fclose( $pipes[ $i ][2] );
		proc_close( $p );
	}
	return $out;
}

$results = array();
$failed  = 0;
function report( string $name, bool $ok, array $detail, array &$results, int &$failed ): void {
	echo ( $ok ? '  PASS  ' : '  FAIL  ' ) . $name . ' — ' . json_encode( $detail ) . "\n";
	$results[] = array( 'scenario' => $name, 'pass' => $ok ) + $detail;
	if ( ! $ok ) { ++$failed; }
}
function ok_count( array $out ): int {
	return count( array_filter( $out, static fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
}

$server = $wpdb->get_var( 'SELECT VERSION()' );
echo "Plugin integration test against a real database\n";
echo '  server: ' . $server . ', workers: ' . $opts['workers'] . ', php: ' . PHP_VERSION . "\n\n";

$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
$wpdb->query( 'DROP TABLE IF EXISTS ' . Schema::audit_table() );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->options}" );
$wpdb->query(
	"CREATE TABLE {$wpdb->options} (
		option_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		option_name varchar(191) NOT NULL,
		option_value longtext NOT NULL,
		autoload varchar(20) NOT NULL DEFAULT 'yes',
		PRIMARY KEY (option_id),
		UNIQUE KEY option_name (option_name)
	)"
);

// 1. Migration from the PREVIOUS schema: a v4-shaped table with rows that have no
//    slot numbers must come out numbered, indexed, and reported as enforceable.
$wpdb->query(
	"CREATE TABLE {$table} (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		user_id bigint(20) unsigned NOT NULL,
		credential_id varchar(191) NOT NULL,
		credential_data longtext NOT NULL,
		sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
		label varchar(191) DEFAULT NULL,
		active tinyint(1) NOT NULL DEFAULT 1,
		created_at datetime NOT NULL,
		last_used_at datetime DEFAULT NULL,
		PRIMARY KEY (id),
		UNIQUE KEY credential_id (credential_id),
		KEY user_id (user_id)
	)"
);
foreach ( array( array( 7, 'old-a' ), array( 7, 'old-b' ), array( 9, 'old-c' ) ) as $row ) {
	$wpdb->query( "INSERT INTO {$table} (user_id, credential_id, credential_data, created_at) VALUES ({$row[0]}, '{$row[1]}', '{}', NOW())" );
}

$installed = Schema::install();
Schema::flush_cap_cache();
$repo  = new CredentialRepository();
$slots = $repo->used_slots( 7 );
sort( $slots );
report(
	'migration from the previous schema numbers existing rows and adds the index',
	$installed && array( 1, 2 ) === $slots && array( 1 ) === $repo->used_slots( 9 ) && Schema::cap_enforceable(),
	array( 'install' => $installed, 'user7_slots' => $slots, 'cap_enforceable' => Schema::cap_enforceable() ),
	$results,
	$failed
);

// 2. The cap under simultaneous registrations, through the plugin's own code.
$wpdb->query( "DELETE FROM {$table}" );
$out = run( 'register', '101:1:c1-{i}', $opts['workers'], $php, $self, $conn );
$n   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE user_id = 101" );
report( 'cap=1: exactly one registration succeeds', 1 === ok_count( $out ) && 1 === $n, array( 'workers' => $opts['workers'], 'admitted' => ok_count( $out ), 'rows' => $n ), $results, $failed );

$out = run( 'register', '102:3:c3-{i}', $opts['workers'], $php, $self, $conn );
$n   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE user_id = 102" );
report( 'cap=3: exactly three registrations succeed', 3 === ok_count( $out ) && 3 === $n, array( 'workers' => $opts['workers'], 'admitted' => ok_count( $out ), 'rows' => $n ), $results, $failed );

// 3. V15-01: with the unique index dropped after migration, a configured cap must
//    REFUSE — the plugin may not register on a database that cannot enforce it.
$wpdb->query( "ALTER TABLE {$table} DROP INDEX user_slot" );
Schema::flush_cap_cache();
$enforceable = Schema::cap_enforceable();
$refused     = claim_credential( $repo, 103, 'no-index', 1 );
$rows_103    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE user_id = 103" );
report(
	'index dropped after migration: a configured cap fails closed (V15-01)',
	false === $enforceable && -503 === $refused && 0 === $rows_103,
	array( 'cap_enforceable' => $enforceable, 'result' => $refused, 'rows' => $rows_103 ),
	$results,
	$failed
);

// 3b. V16-01: the index must have the RIGHT SHAPE. A same-named index that is not
//     unique, or is over other columns, enforces nothing — and must not be
//     mistaken for the real constraint.
$wpdb->query( "ALTER TABLE {$table} ADD INDEX user_slot (user_id, slot_no)" );   // same name, NOT unique
Schema::flush_cap_cache();
$shape_ok  = Schema::cap_enforceable();
$shape_res = claim_credential( $repo, 107, 'non-unique-index', 1 );
$wpdb->query( "ALTER TABLE {$table} DROP INDEX user_slot" );
report(
	'a same-named NON-UNIQUE index is not accepted as the constraint (V16-01)',
	false === $shape_ok && -503 === $shape_res,
	array( 'cap_enforceable' => $shape_ok, 'result' => $shape_res ),
	$results,
	$failed
);

$wpdb->query( "ALTER TABLE {$table} ADD UNIQUE INDEX user_slot (user_id, credential_id)" ); // unique, wrong columns
Schema::flush_cap_cache();
$cols_ok  = Schema::cap_enforceable();
$cols_res = claim_credential( $repo, 108, 'wrong-columns-index', 1 );
$wpdb->query( "ALTER TABLE {$table} DROP INDEX user_slot" );
report(
	'a unique index over the WRONG columns is not accepted (V16-01)',
	false === $cols_ok && -503 === $cols_res,
	array( 'cap_enforceable' => $cols_ok, 'result' => $cols_res ),
	$results,
	$failed
);

// 3c. V16-01: the check must be answered by the SERVER THAT TAKES THE WRITES. The
//     plugin proves it by writing — two rows claiming one slot, the second of
//     which must be refused — so an index that only a replica still has cannot
//     make the cap look enforced.
$wrote_probe = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE user_id = 0 AND credential_id LIKE 'rapls-probe-%'" );
Schema::flush_cap_cache();
Schema::cap_enforceable();
$probe_left = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE user_id = 0 AND credential_id LIKE 'rapls-probe-%'" );
report(
	'the writer is probed with a real duplicate write, and the probe cleans up (V16-01)',
	0 === $wrote_probe && 0 === $probe_left,
	array( 'probe_rows_before' => $wrote_probe, 'probe_rows_after' => $probe_left ),
	$results,
	$failed
);

// …and an uncapped site still works, because there is no cap to guarantee.
$unlimited = claim_credential( $repo, 104, 'no-cap-ok', 0 );
report( 'with no cap configured, registration still works', $unlimited > 0, array( 'id' => $unlimited ), $results, $failed );

// 4. The migration puts the index back on the next run, and reports success.
$installed = Schema::install();
Schema::flush_cap_cache();
report( 'a later migration restores the index', $installed && Schema::cap_enforceable(), array( 'install' => $installed ), $results, $failed );

// 5. Fail closed when the table cannot be read at all.
$wpdb->query( "ALTER TABLE {$table} RENAME TO {$table}_hidden" );
Schema::flush_cap_cache();
$on_error = claim_credential( $repo, 105, 'db-error', 1 );
$wpdb->query( "ALTER TABLE {$table}_hidden RENAME TO {$table}" );
Schema::flush_cap_cache();
report( 'a database error refuses the registration (never "under the limit")', -503 === $on_error, array( 'result' => $on_error ), $results, $failed );

// 6. A replayed write (what wpdb does after a reconnect) stores one row, not two.
$first  = claim_credential( $repo, 106, 'replay-me', 3 );
$second = claim_credential( $repo, 106, 'replay-me', 3 );
$rows   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE user_id = 106" );
report( 'replaying the same credential is idempotent', $first > 0 && $first === $second && 1 === $rows, array( 'first' => $first, 'second' => $second, 'rows' => $rows ), $results, $failed );

// 7. V15-02/V15-03: the attempt limit through the shipped RateLimit, with N
//    simultaneous processes — including a window that ends within the run, which
//    is where an inconsistent boundary rule used to open a hole.
$key = 'it_login|' . bin2hex( random_bytes( 4 ) );
$out = run( 'admit', "{$key}:3600:5", $opts['workers'], $php, $self, $conn );
report( 'attempt limit: exactly max admitted out of N simultaneous', 5 === ok_count( $out ), array( 'workers' => $opts['workers'], 'max' => 5, 'admitted' => ok_count( $out ) ), $results, $failed );

$boundary_key = 'it_edge|' . bin2hex( random_bytes( 4 ) );
$out = run( 'admit', "{$boundary_key}:1:1", $opts['workers'], $php, $self, $conn );
$admitted_edge = ok_count( $out );
report(
	'one-second windows: never more than one admission per window (V15-02)',
	$admitted_edge >= 1 && $admitted_edge <= 2,
	array( 'workers' => $opts['workers'], 'max_per_window' => 1, 'admitted' => $admitted_edge, 'note' => 'the run can straddle at most two one-second windows' ),
	$results,
	$failed
);

// Clean up.
$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
$wpdb->query( 'DROP TABLE IF EXISTS ' . Schema::audit_table() );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->options}" );
@unlink( __DIR__ . '/wp-admin/includes/upgrade.php' );
@rmdir( __DIR__ . '/wp-admin/includes' );
@rmdir( __DIR__ . '/wp-admin' );

if ( '' !== $opts['json'] ) {
	file_put_contents(
		$opts['json'],
		json_encode(
			array(
				'server'    => $server,
				'php'       => PHP_VERSION,
				'workers'   => $opts['workers'],
				'found_rows_flag' => (bool) getenv( 'RAPLS_CLIENT_FOUND_ROWS' ),
				'scenarios' => $results,
				'passed'    => 0 === $failed,
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		) . "\n"
	);
}

echo "\n  " . ( count( $results ) - $failed ) . ' passed, ' . $failed . " failed\n";
exit( 0 === $failed ? 0 : 1 );

} // namespace
