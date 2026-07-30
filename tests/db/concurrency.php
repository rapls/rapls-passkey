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

// How long the controller waits for one worker before treating it as failed.
// Generous: these workers do a handful of queries after a 1.5 s barrier.
// Overridable so the timeout path itself can be exercised (set it to 1).
define( 'WORKER_TIMEOUT', (float) ( getenv( 'RAPLS_WORKER_TIMEOUT' ) ?: 120 ) );
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
		// The shipped admission: claim a numbered attempt slot, prove ownership by
		// reading the row back. No total is ever read, so a replica cannot inflate
		// the budget and a window boundary cannot open a hole.
		list( $key, $max, $end ) = explode( ':', $opts['arg'] );
		$max   = (int) $max;
		$nonce = bin2hex( random_bytes( 12 ) );
		for ( $slot = 1; $slot <= $max; $slot++ ) {
			$name  = $c->real_escape_string( "ra_{$key}_{$end}_{$slot}" );
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
		echo "NO budget-gone\n";
		exit( 0 );
	}

	if ( 'lock' === $opts['worker'] ) {
		// A SINGLE-HOLDER lock on the options table, and its takeover.
		//
		// The obvious way to write this in WordPress is add_option(), and
		// add_option() is not it: it calls get_option() first and then INSERTs
		// ON DUPLICATE KEY UPDATE, so two callers can both find nothing there and
		// both come away believing they hold the lock. What settles it is the bare
		// INSERT — one row, one winner, decided by the unique index — and, for a
		// lock whose holder died, a compare-and-set on the exact value found.
		// The value is "<unix time>:<random>", as the shipped lock stores it: the
		// time is what makes an abandoned lock recoverable, and the random half is
		// what a would-be stealer compares against.
		list( $name, $mode, $ttl ) = array_pad( explode( ':', $opts['arg'] ), 3, '120' );
		$n    = $c->real_escape_string( $name );
		$mine = time() . ':' . bin2hex( random_bytes( 8 ) );
		$v    = $c->real_escape_string( $mine );

		if ( 'take' === $mode ) {
			if ( $c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('{$n}', '{$v}')" ) ) {
				echo "OK held\n";
				exit( 0 );
			}
			echo "NO busy:{$c->errno}\n";
			exit( 0 );
		}

		// Takeover, in full. Reading a lock is not taking one, and the STALENESS
		// CHECK is half of it: without it this is not a race between claimants but
		// a chain of them — each worker reads whatever the last one wrote and
		// steals that, so most of a hundred come away holding it in turn. (That is
		// not hypothetical: the first version of this worker omitted the check and
		// 65 to 79 of 100 reported success, which is what put this comment here.)
		$res  = $c->query( 'SELECT option_value FROM ' . OPT_TABLE . " WHERE option_name = '{$n}'" );
		$held = $res ? (string) ( $res->fetch_row()[0] ?? '' ) : '';
		if ( '' === $held ) {
			echo "NO no-lock\n";
			exit( 0 );
		}
		if ( time() - (int) strtok( $held, ':' ) < (int) $ttl ) {
			echo "NO busy\n";     // a fresh holder — including one that just won below
			exit( 0 );
		}
		$h = $c->real_escape_string( $held );
		$c->query( 'UPDATE ' . OPT_TABLE . " SET option_value = '{$v}' WHERE option_name = '{$n}' AND option_value = '{$h}'" );
		if ( 1 === $c->affected_rows ) {
			echo "OK stole\n";
			exit( 0 );
		}
		echo "NO lost\n";
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
	// Collect with a deadline. A worker that never answers used to block this
	// loop for as long as the machine stayed up: the suite printed nothing more
	// and the run looked slow rather than broken. A wedged worker is now a
	// FAILED assertion — "NO timeout" is not "OK", so the count comes out wrong
	// and the test says so — instead of an answer that never arrives.
	$out      = array();
	$deadline = microtime( true ) + WORKER_TIMEOUT;
	foreach ( $procs as $i => $p ) {
		$fh = $pipes[ $i ][1];
		stream_set_blocking( $fh, false );
		$buf = '';
		while ( ! feof( $fh ) ) {
			$left = $deadline - microtime( true );
			if ( $left <= 0 ) {
				proc_terminate( $p, 9 );
				$buf .= "\nNO timeout";
				break;
			}
			$r = array( $fh );
			$w = null;
			$e = null;
			if ( stream_select( $r, $w, $e, 0, 200000 ) > 0 ) {
				$buf .= (string) fread( $fh, 8192 );
			}
		}
		$out[] = trim( $buf );
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
report( 'cap=1: exactly 1 admitted, exactly 1 row', 1 === $admitted && 1 === $rows, array( 'workers' => $opts['workers'], 'admitted' => $admitted, 'rows' => $rows ), $results, $failed );

// 2. cap = 3, N concurrent registrations for one user.
$out      = run( 'cap', '102:3:c3-{i}', $opts['workers'], $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows     = (int) $c->query( 'SELECT COUNT(*) FROM ' . CRED_TABLE . ' WHERE user_id = 102' )->fetch_row()[0];
report( 'cap=3: exactly 3 admitted, exactly 3 rows', 3 === $admitted && 3 === $rows, array( 'workers' => $opts['workers'], 'admitted' => $admitted, 'rows' => $rows ), $results, $failed );

// 3. Quota cap = 5, N concurrent reservations in one window.
$end      = ( intdiv( time(), 3600 ) + 1 ) * 3600;
$out      = run( 'quota', "q1:5:{$end}", $opts['workers'], $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows     = (int) $c->query( 'SELECT COUNT(*) FROM ' . OPT_TABLE . " WHERE option_name LIKE 'rs\\_q1\\_%'" )->fetch_row()[0];
report( 'quota cap=5: exactly 5 admitted, exactly 5 rows', 5 === $admitted && 5 === $rows, array( 'workers' => $opts['workers'], 'admitted' => $admitted, 'rows' => $rows ), $results, $failed );

// 4. Admission with the budget at max-1: exactly ONE of N may proceed.
$win = time() + 3600;
for ( $s = 1; $s <= 4; $s++ ) {                        // 4 of 5 attempts already spent
	$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('ra_rl_a_{$win}_{$s}', '{$win}:taken')" );
}
$out      = run( 'admit', "rl_a:5:{$win}", 20, $php, $self, $conn );
$admitted = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
report( 'count=max-1: exactly 1 of 20 admitted', 1 === $admitted, array( 'workers' => 20, 'admitted' => $admitted ), $results, $failed );

// 5. Admission with the budget already spent: none may proceed.
for ( $s = 1; $s <= 5; $s++ ) {
	$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('ra_rl_b_{$win}_{$s}', '{$win}:taken')" );
}
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

// 8. A single-holder lock: N workers, exactly one may hold it, one row exists.
//    This is the primitive behind any "one at a time on this site" guard, and
//    the one add_option() cannot give — it reads before it writes.
$out  = run( 'lock', 'lk_a:take', $opts['workers'], $php, $self, $conn );
$held = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows = (int) $c->query( 'SELECT COUNT(*) FROM ' . OPT_TABLE . " WHERE option_name = 'lk_a'" )->fetch_row()[0];
report( 'single-holder lock: exactly 1 of N holds it, exactly 1 row', 1 === $held && 1 === $rows, array( 'workers' => $opts['workers'], 'held' => $held, 'rows' => $rows ), $results, $failed );

// 9. Taking over an abandoned lock. Two things have to hold at once: of the
//    workers that see the SAME stale value, only one compare-and-set can match
//    it; and a worker arriving after that one must see a fresh timestamp and
//    stand down rather than steal in turn.
$stale = ( time() - 3600 ) . ':abandoned';
$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('lk_b', '{$stale}')" );
$out  = run( 'lock', 'lk_b:steal:120', $opts['workers'], $php, $self, $conn );
$won  = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$rows = (int) $c->query( 'SELECT COUNT(*) FROM ' . OPT_TABLE . " WHERE option_name = 'lk_b'" )->fetch_row()[0];
$left = (string) $c->query( 'SELECT option_value FROM ' . OPT_TABLE . " WHERE option_name = 'lk_b'" )->fetch_row()[0];
report( 'abandoned lock: exactly 1 of N takes it over, and the stale value is gone', 1 === $won && 1 === $rows && $stale !== $left, array( 'workers' => $opts['workers'], 'won' => $won, 'rows' => $rows ), $results, $failed );

// 10. And a lock whose holder is alive is not taken over at all.
$c->query( 'INSERT INTO ' . OPT_TABLE . " (option_name, option_value) VALUES ('lk_c', '" . time() . ":alive')" );
$out  = run( 'lock', 'lk_c:steal:120', $opts['workers'], $php, $self, $conn );
$won  = count( array_filter( $out, fn( $l ) => 0 === strpos( $l, 'OK' ) ) );
$left = (string) $c->query( 'SELECT option_value FROM ' . OPT_TABLE . " WHERE option_name = 'lk_c'" )->fetch_row()[0];
report( 'a live lock is taken over by none of N', 0 === $won && str_ends_with( $left, ':alive' ), array( 'workers' => $opts['workers'], 'won' => $won ), $results, $failed );

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
