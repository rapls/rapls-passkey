<?php
/**
 * A minimal but REAL wpdb: the subset of the API the plugin uses, executed
 * against a live MySQL/MariaDB over mysqli.
 *
 * The smoke suites run the plugin against hand-written doubles, which can only
 * ever prove control flow. This adapter lets the SAME shipped classes —
 * Credentials\Schema, Credentials\CredentialRepository, Support\RateLimit — run
 * against a real server, so migrations, unique constraints and concurrency are
 * exercised as they will be in production.
 *
 * @package RaplsPasskey
 */

// phpcs:disable

class WPDB_Lite {

	public $prefix        = 'rapls_it_';
	public $options       = 'rapls_it_options';
	public $users         = 'rapls_it_users';
	public $usermeta      = 'rapls_it_usermeta';
	public $insert_id     = 0;
	public $rows_affected = 0;
	public $last_error    = '';

	/** @var mysqli */
	public $db;

	public function __construct( mysqli $db ) {
		$this->db = $db;
	}

	/**
	 * Open a connection. Set RAPLS_CLIENT_FOUND_ROWS=1 to use the connection flag
	 * that reports matched instead of changed rows — nothing in the plugin may
	 * depend on it.
	 */
	public static function connect( array $o ): mysqli {
		mysqli_report( MYSQLI_REPORT_OFF );
		if ( getenv( 'RAPLS_CLIENT_FOUND_ROWS' ) ) {
			$db = mysqli_init();
			$ok = $o['socket']
				? @$db->real_connect( 'localhost', $o['user'], $o['pass'], $o['db'], null, $o['socket'], MYSQLI_CLIENT_FOUND_ROWS )
				: @$db->real_connect( $o['host'], $o['user'], $o['pass'], $o['db'], (int) $o['port'], null, MYSQLI_CLIENT_FOUND_ROWS );
			if ( ! $ok ) {
				fwrite( STDERR, 'connect failed: ' . mysqli_connect_error() . "\n" );
				exit( 2 );
			}
			return $db;
		}
		$db = $o['socket']
			? @new mysqli( 'localhost', $o['user'], $o['pass'], $o['db'], null, $o['socket'] )
			: @new mysqli( $o['host'], $o['user'], $o['pass'], $o['db'], (int) $o['port'] );
		if ( $db->connect_errno ) {
			fwrite( STDERR, "connect failed: {$db->connect_error}\n" );
			exit( 2 );
		}
		return $db;
	}

	// --- wpdb API ------------------------------------------------------------

	public function prepare( $query, ...$args ) {
		if ( 1 === count( $args ) && is_array( $args[0] ) ) {
			$args = $args[0];
		}
		$out = '';
		$i   = 0;
		$len = strlen( $query );
		for ( $p = 0; $p < $len; $p++ ) {
			if ( '%' === $query[ $p ] && isset( $query[ $p + 1 ] ) && in_array( $query[ $p + 1 ], array( 'd', 's', 'f' ), true ) ) {
				$type = $query[ ++$p ];
				$val  = $args[ $i++ ] ?? null;
				if ( 'd' === $type ) {
					$out .= (int) $val;
				} elseif ( 'f' === $type ) {
					$out .= (float) $val;
				} else {
					$out .= null === $val ? 'NULL' : "'" . $this->db->real_escape_string( (string) $val ) . "'";
				}
				continue;
			}
			$out .= $query[ $p ];
		}
		return $out;
	}

	public function esc_like( $text ) {
		return addcslashes( (string) $text, '_%\\' );
	}

	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
	}

	public function query( $sql ) {
		$this->last_error = '';
		$res              = $this->db->query( $sql );
		if ( false === $res ) {
			$this->last_error    = $this->db->error;
			$this->rows_affected = 0;
			return false;
		}
		$this->rows_affected = $this->db->affected_rows;
		$this->insert_id     = $this->db->insert_id;
		return true === $res ? $this->rows_affected : $res->num_rows;
	}

	public function get_var( $sql ) {
		$this->last_error = '';
		$res              = $this->db->query( $sql );
		if ( false === $res ) {
			$this->last_error = $this->db->error;
			return null;
		}
		$row = $res->fetch_row();
		return $row ? $row[0] : null;
	}

	public function get_col( $sql ) {
		$this->last_error = '';
		$res              = $this->db->query( $sql );
		if ( false === $res ) {
			$this->last_error = $this->db->error;
			return array();
		}
		$out = array();
		while ( $row = $res->fetch_row() ) {
			$out[] = $row[0];
		}
		return $out;
	}

	public function get_results( $sql, $output = ARRAY_A ) {
		$this->last_error = '';
		$res              = $this->db->query( $sql );
		if ( false === $res ) {
			$this->last_error = $this->db->error;
			return array();
		}
		$out = array();
		while ( $row = $res->fetch_assoc() ) {
			$out[] = ARRAY_A === $output ? $row : (object) $row;
		}
		return $out;
	}

	public function get_row( $sql, $output = ARRAY_A ) {
		$rows = $this->get_results( $sql, $output );
		return $rows[0] ?? null;
	}

	public function insert( $table, $data, $formats = null ) {
		$cols = array();
		$vals = array();
		foreach ( $data as $col => $value ) {
			$cols[] = '`' . $col . '`';
			$vals[] = null === $value ? 'NULL' : "'" . $this->db->real_escape_string( (string) $value ) . "'";
		}
		$sql = "INSERT INTO {$table} (" . implode( ',', $cols ) . ') VALUES (' . implode( ',', $vals ) . ')';
		$ok  = $this->query( $sql );
		if ( false === $ok ) {
			return false;
		}
		$this->insert_id = $this->db->insert_id;
		return 1;
	}

	public function update( $table, $data, $where, $f = null, $wf = null ) {
		$set = array();
		foreach ( $data as $col => $value ) {
			$set[] = '`' . $col . '` = ' . ( null === $value ? 'NULL' : "'" . $this->db->real_escape_string( (string) $value ) . "'" );
		}
		$cond = array();
		foreach ( $where as $col => $value ) {
			$cond[] = '`' . $col . "` = '" . $this->db->real_escape_string( (string) $value ) . "'";
		}
		return $this->query( "UPDATE {$table} SET " . implode( ',', $set ) . ' WHERE ' . implode( ' AND ', $cond ) );
	}

	public function delete( $table, $where, $f = null ) {
		$cond = array();
		foreach ( $where as $col => $value ) {
			$cond[] = '`' . $col . "` = '" . $this->db->real_escape_string( (string) $value ) . "'";
		}
		return $this->query( "DELETE FROM {$table} WHERE " . implode( ' AND ', $cond ) );
	}
}
