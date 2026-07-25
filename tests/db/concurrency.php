<?php
/**
 * REAL-DATABASE concurrency test for the two invariants that the PHP-double smoke
 * tests cannot prove: the per-user passkey cap and the per-window quota.
 *
 * Both are enforced by UNIQUE constraints (credentials: UNIQUE (user_id, slot_no);
 * reservations: UNIQUE option_name), so this exercises them the only way that
 * counts — many OS processes hammering one MySQL/MariaDB at the same instant,
 * released together by a barrier — and reports the numbers the review asks for:
 * admitted count, final row count, and the per-scenario verdict.
 *
 * Usage:
 *   php tests/db/concurrency.php --dsn=host=127.0.0.1;port=3306;dbname=test \
 *       --user=root --pass=secret [--workers=100] [--json=results.json]
 *   php tests/db/concurrency.php --socket=/path/mysqld.sock --db=local \
 *       --user=root --pass=root
 *
 * Exit code 0 only when every scenario passes.
 *
 * @package RaplsPasskey
 */

// phpcs:disable

$opts = array(
	'host'    => '127.0.0.1',
	'port'    => 3306,
	'socket'  => null,
	'db'      => 'test',
	'user'    => 'root',
	'pass'    => '',
	'workers' => 100,
	'json'    => '',
	'worker'  => '',   // internal: run as a child worker
	'arg'     => '',   // internal: worker payload
	'start'   => '',   // internal: barrier release time (microseconds)
);
foreach ( array_slice( $argv, 1 ) as $a ) {
	if ( preg_match( '/^--([a-z]+)=(.*)$/s', $a, $m ) ) {
		$opts[ $m[1] ] = $m[2];
	}
}
$opts['port']    = (int) $opts['port'];
$opts['workers'] = max( 2, (int) $opts['workers'] );

const CRED_TABLE = 'rapls_ct_credentials';
const OPT_TABLE  = 'rapls_ct_options';

/**
 * Open a connection. Every worker opens its OWN connection, which is the point:
 * the guarantee must come from the database, not from anything session-local.
 */
function db( array $o ): mysqli {
	mysqli_report( MYSQLI_REPORT_OFF );

	// With RAPLS_CLIENT_FOUND_ROWS=1 the connection reports MATCHED rather than
	// CHANGED rows — the configuration that broke a previous design which read
	// success from affected rows. Nothing here may depend on that flag, so the
	// suite is run both ways.
	if ( getenv( 'RAPLS_CLIENT_FOUND_ROWS' ) ) {
		$c = mysqli_init();
		$ok = $o['socket']
			? @$c->real_connect( 'localhost', $o['user'], $o['pass'], $o['db'], null, $o['socket'], MYSQLI_CLIENT_FOUND_ROWS )
			: @$c->real_connect( $o['host'], $o['user'], $o['pass'], $o['db'], $o['port'], null, MYSQLI_CLIENT_FOUND_ROWS );
		if ( ! $ok ) {
			fwrite( STDERR, 'connect failed: ' . mysqli_connect_error() . "\n" );
			exit( 2 );
		}
		return $c;
	}

	$c = $o['socket']
		? @new mysqli( 'localhost', $o['user'], $o['pass'], $o['db'], null, $o['socket'] )
		: @new mysqli( $o['host'], $o['user'], $o['pass'], $o['db'], $o['port'] );
	if ( $c->connect_errno ) {
		fwrite( STDERR, "connect failed: {$c->connect_error}\n" );
		exit( 2 );
	}
	return $c;
}

/**
 * Sleep until the shared barrier time, so every worker starts within a few
 * hundred microseconds of the others. Staggered starts would hide exactly the
 * race this test exists to find.
 */
function barrier( string $start_us ): void {
	$target = (float) $start_us;
	while ( microtime( true ) * 1e6 < $target ) {
		usleep( 200 );
	}
}

// --- Worker mode ------------------------------------------------------------
// Prints one line: "OK <detail>" when it won a slot, "NO <reason>" otherwise.

if ( '' !== $opts['worker'] ) {
	$c = db( $opts );
	barrier( $opts['start'] );

	if ( 'cap' === $opts['worker'] ) {
		// Claim the lowest free slot within the cap, exactly as
		// Rest\Endpoints::store_credential() does.
		list( $user_id, $cap, $tag ) = explode( ':', $opts['arg'] );
		$user_id = (int) $user_id;
		$cap     = (int) $cap;

		for ( $attempt = 0; $attempt < 40; $attempt++ ) {
			$used = array();
			$res  = $c->query( 'SELECT slot_no FROM ' . CRED_TABLE . " WHERE user_id = {$user_id} AND slot_no IS NOT NULL" );
			if ( $res ) {
				while ( $row = $res->fetch_row() ) {
					$used[] = (int) $row[0];
				}
			}
			$slot = 0;
			for ( $s = 1; $s <= $cap; $s++ ) {
				if ( ! in_array( $s, $used, true ) ) { $slot = $s; break; }
			}
			if ( 0 === $slot ) {
				echo "NO cap-full\n";
				exit( 0 );
			}
			$cid = $c->real_escape_string( $tag . '-' . $attempt );
			$ok  = $c->query( 'INSERT INTO ' . CRED_TABLE . " (user_id, slot_no, credential_id) VALUES ({$user_id}, {$slot}, '{$cid}')" );
			if ( $ok ) {
				echo "OK slot={$slot}\n";
				exit( 0 );
			}
			// 1062 = duplicate key: somebody else took this slot; try the next.
			if ( 1062 !== $c->errno ) {
				echo "NO db-error:{$c->errno}\n";
				exit( 0 );
			}
		}
		echo "NO exhausted\n";
		exit( 0 );
	}

	if ( 'quota' === $opts['worker'] ) {
		// Claim a numbered reservation row, exactly as Support\RateLimit::reserve()
		// does — including deciding ownership by READING THE ROW BACK, never by an
		// affected-row count.
		list( $key, $cap, $end ) = explode( ':', $opts['arg'] );
		$cap   = (int) $cap;
		$nonce = bin2hex( random_bytes( 12 ) );

		for ( $slot = 1; $slot <= $cap; $slot++ ) {
			$name  = $c->real_escape_string( "rs_{$key}_{$end}_{$slot}" );
			$value = $c->real_escape_string( "{$end}:{$nonce}" );
			$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('{$name}', '{$value}')" );
			$res    = $c->query( 'SELECT option_value FROM ' . OPT_TABLE . " WHERE option_name = '{$name}'" );
			$stored = $res ? ( $res->fetch_row()[0] ?? null ) : null;
			if ( null === $stored && '' !== $c->error ) {
				echo "NO read-error\n";
				exit( 0 );
			}
			if ( (string) $stored === "{$end}:{$nonce}" ) {
				echo "OK slot={$slot}\n";
				exit( 0 );
			}
		}
		echo "NO cap-full\n";
		exit( 0 );
	}

	if ( 'admit' === $opts['worker'] ) {
		// Atomic admission: consume one attempt, then decide — the V14-03 order.
		list( $name, $max, $window_end ) = explode( ':', $opts['arg'] );
		$name = $c->real_escape_string( $name );
		$max  = (int) $max;
		$init = "1:{$window_end}";
		$c->query(
			'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('{$name}', '{$init}')
			 ON DUPLICATE KEY UPDATE option_value = CONCAT(
				CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) + 1, ':', SUBSTRING_INDEX(option_value, ':', -1))"
		);
		$res    = $c->query( 'SELECT option_value FROM ' . OPT_TABLE . " WHERE option_name = '{$name}'" );
		$stored = $res ? ( $res->fetch_row()[0] ?? null ) : null;
		$count  = is_string( $stored ) ? (int) explode( ':', $stored )[0] : PHP_INT_MAX;
		echo ( $count <= $max ? "OK count={$count}\n" : "NO over={$count}\n" );
		exit( 0 );
	}

	echo "NO unknown-worker\n";
	exit( 0 );
}

// --- Controller -------------------------------------------------------------

$php  = PHP_BINARY;
$self = __FILE__;
$conn = $opts['socket']
	? '--socket=' . escapeshellarg( $opts['socket'] )
	: '--host=' . escapeshellarg( $opts['host'] ) . ' --port=' . (int) $opts['port'];
$conn .= ' --db=' . escapeshellarg( $opts['db'] ) . ' --user=' . escapeshellarg( $opts['user'] ) . ' --pass=' . escapeshellarg( $opts['pass'] );

$c = db( $opts );
$server = $c->query( 'SELECT VERSION()' )->fetch_row()[0];

// Fresh tables carrying the same constraints the plugin ships.
$c->query( 'DROP TABLE IF EXISTS ' . CRED_TABLE );
$c->query( 'DROP TABLE IF EXISTS ' . OPT_TABLE );
$c->query(
	'CREATE TABLE ' . CRED_TABLE . ' (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		user_id bigint(20) unsigned NOT NULL,
		slot_no bigint(20) unsigned DEFAULT NULL,
		credential_id varchar(191) NOT NULL,
		PRIMARY KEY (id),
		UNIQUE KEY credential_id (credential_id),
		UNIQUE KEY user_slot (user_id, slot_no)
	)'
);
$c->query(
	'CREATE TABLE ' . OPT_TABLE . ' (
		option_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		option_name varchar(191) NOT NULL,
		option_value longtext NOT NULL,
		PRIMARY KEY (option_id),
		UNIQUE KEY option_name (option_name)
	)'
);

$results = array();
$failed  = 0;

/**
 * Launch $n workers that all unblock at the same instant, and collect their
 * verdicts.
 */
function run( string $mode, string $arg, int $n, string $php, string $self, string $conn ): array {
	$start = (string) (int) ( ( microtime( true ) + 1.5 ) * 1e6 ); // 1.5 s to spawn
	$procs = array();
	$pipes = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$cmd = escapeshellarg( $php ) . ' ' . escapeshellarg( $self ) . " {$conn}"
			. ' --worker=' . escapeshellarg( $mode )
			. ' --arg=' . escapeshellarg( str_replace( '{i}', (string) $i, $arg ) )
			. ' --start=' . escapeshellarg( $start );
		$p = proc_open( $cmd, array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pp );
		if ( is_resource( $p ) ) {
			$procs[ $i ] = $p;
			$pipes[ $i ] = $pp;
		}
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

function report( string $name, bool $ok, array $detail, array &$results, int &$failed ): void {
	echo ( $ok ? '  PASS  ' : '  FAIL  ' ) . $name . ' — ' . json_encode( $detail ) . "\n";
	$results[] = array( 'scenario' => $name, 'pass' => $ok ) + $detail;
	if ( ! $ok ) {
		$failed++;
	}
}

echo "Real-database concurrency test\n";
echo '  server: ' . $server . ', workers: ' . $opts['workers'] . "\n\n";

// 1. cap = 1, N concurrent registrations for one user.
$out      = run( 'cap', '101:1:c1-{i}', $opts['workers'], $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows     = (int) $c->query( 'SELECT COUNT(*) FROM ' . CRED_TABLE . ' WHERE user_id = 101' )->fetch_row()[0];
report( 'cap=1: admitted<=1 and final rows<=1', $admitted <= 1 && $rows <= 1, array( 'workers' => $opts['workers'], 'admitted' => $admitted, 'rows' => $rows ), $results, $failed );

// 2. cap = 3, N concurrent registrations for one user.
$out      = run( 'cap', '102:3:c3-{i}', $opts['workers'], $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows     = (int) $c->query( 'SELECT COUNT(*) FROM ' . CRED_TABLE . ' WHERE user_id = 102' )->fetch_row()[0];
report( 'cap=3: admitted<=3 and final rows<=3', $admitted <= 3 && $rows <= 3, array( 'workers' => $opts['workers'], 'admitted' => $admitted, 'rows' => $rows ), $results, $failed );

// 3. Quota cap = 5, N concurrent reservations in one window.
$end      = ( intdiv( time(), 3600 ) + 1 ) * 3600;
$out      = run( 'quota', "q1:5:{$end}", $opts['workers'], $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows     = (int) $c->query( 'SELECT COUNT(*) FROM ' . OPT_TABLE . " WHERE option_name LIKE 'rs\\_q1\\_%'" )->fetch_row()[0];
report( 'quota cap=5: admitted<=5 and final rows<=5', $admitted <= 5 && $rows <= 5, array( 'workers' => $opts['workers'], 'admitted' => $admitted, 'rows' => $rows ), $results, $failed );

// 4. Admission with the counter at max-1: at most ONE of N may proceed.
$win = time() + 3600;
$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('rl_a', '4:{$win}')" );
$out      = run( 'admit', "rl_a:5:{$win}", 20, $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
report( 'count=max-1: at most 1 of 20 admitted', $admitted <= 1, array( 'workers' => 20, 'admitted' => $admitted ), $results, $failed );

// 5. Admission with the counter already at max: none may proceed.
$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('rl_b', '5:{$win}')" );
$out      = run( 'admit', "rl_b:5:{$win}", 20, $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
report( 'count=max: 0 of 20 admitted', 0 === $admitted, array( 'workers' => 20, 'admitted' => $admitted ), $results, $failed );

// 6. The cap must survive losing the connection mid-flight: a worker that
//    reconnects and replays its INSERT must not create a second row (the unique
//    credential_id makes the write idempotent). Simulated by replaying the exact
//    same statement on a brand-new connection.
$c2 = db( $opts );
$c2->query( 'INSERT INTO ' . CRED_TABLE . " (user_id, slot_no, credential_id) VALUES (103, 1, 'replay-1')" );
$c3 = db( $opts ); // a different connection == the post-reconnect one
$c3->query( 'INSERT INTO ' . CRED_TABLE . " (user_id, slot_no, credential_id) VALUES (103, 1, 'replay-1')" );
$rows = (int) $c->query( 'SELECT COUNT(*) FROM ' . CRED_TABLE . ' WHERE user_id = 103' )->fetch_row()[0];
report( 'reconnect replay stores exactly one row', 1 === $rows, array( 'rows' => $rows, 'replay_errno' => $c3->errno ), $results, $failed );

// 7. The same, one connection later: a NEW connection cannot exceed the cap
//    either — the constraint is server-side, not session-side. (This is what a
//    session-scoped GET_LOCK could not guarantee.)
$c4  = db( $opts );
$ok4 = $c4->query( 'INSERT INTO ' . CRED_TABLE . " (user_id, slot_no, credential_id) VALUES (103, 1, 'other-conn')" );
report( 'a different connection cannot take a claimed slot', ! $ok4 && 1062 === $c4->errno, array( 'errno' => $c4->errno ), $results, $failed );

$c->query( 'DROP TABLE IF EXISTS ' . CRED_TABLE );
$c->query( 'DROP TABLE IF EXISTS ' . OPT_TABLE );

if ( '' !== $opts['json'] ) {
	file_put_contents(
		$opts['json'],
		json_encode(
			array(
				'server'    => $server,
				'workers'   => $opts['workers'],
				'php'       => PHP_VERSION,
				'scenarios' => $results,
				'passed'    => 0 === $failed,
			),
			JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
		) . "\n"
	);
}

echo "\n  " . ( count( $results ) - $failed ) . ' passed, ' . $failed . " failed\n";
exit( 0 === $failed ? 0 : 1 );
