<?php
/**
 * Shared $wpdb double for the wp_options-backed primitives (Support\RateLimit).
 *
 * The only behaviour that matters is the one the plugin relies on: option_name is
 * UNIQUE, so inserting a slot row that already exists FAILS rather than
 * overwriting. That constraint — not any counter — is what caps attempts and
 * quotas, so a double that quietly overwrote would test nothing.
 *
 * Used by both plugins' smoke tests; the real thing is exercised against a live
 * MySQL/MariaDB in tests/db/.
 *
 * @package RaplsPasskey
 */

// phpcs:disable

class WPDB_Options {

	public $options       = 'wp_options';
	public $prefix        = 'wp_';
	public $store         = array();
	public $rows_affected = 0;
	public $last_error    = '';
	/** Fail only the next statement (a transient blip). */
	public $fail_next     = false;
	/** Fail every statement (the database is down). */
	public $fail_all      = false;

	public function esc_like( $s ) {
		return $s;
	}

	public function prepare( $q, ...$a ) {
		foreach ( $a as $x ) {
			$rep = is_int( $x ) ? (string) $x : "'" . str_replace( "'", "''", (string) $x ) . "'";
			$q   = preg_replace( '/%[dsf]/', $rep, $q, 1 );
		}
		return $q;
	}

	public function query( $q ) {
		$this->rows_affected = 0;
		$this->last_error    = '';
		if ( $this->fail_next || $this->fail_all ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return false;
		}

		// Claim one slot: a plain INSERT that the unique index must reject when the
		// row is already there.
		if ( 0 === strpos( ltrim( $q ), 'INSERT INTO' )
			&& preg_match( "/VALUES \\('([^']*)', '([^']*)', 'no'\\)/", $q, $m ) ) {
			if ( isset( $this->store[ $m[1] ] ) ) {
				$this->last_error = 'Duplicate entry';
				return false;
			}
			$this->store[ $m[1] ] = $m[2];
			$this->rows_affected  = 1;
			return 1;
		}

		// release(): token-scoped DELETE — name AND value must both match.
		if ( 0 === strpos( ltrim( $q ), 'DELETE' )
			&& preg_match( "/option_name = '([^']*)' AND option_value = '([^']*)'/", $q, $m ) ) {
			if ( ( $this->store[ $m[1] ] ?? null ) === $m[2] ) {
				unset( $this->store[ $m[1] ] );
				$this->rows_affected = 1;
				return 1;
			}
			return 0;
		}

		// clear() / gc(): DELETE ... WHERE option_name LIKE '<prefix>%' [AND window].
		if ( 0 === strpos( ltrim( $q ), 'DELETE' ) && preg_match( "/option_name LIKE '([^']*)%'/", $q, $m ) ) {
			$expired = null;
			if ( preg_match( "/AS UNSIGNED\\) <= (\\d+)/", $q, $n ) ) {
				$expired = (int) $n[1];
			}
			$gone = 0;
			foreach ( $this->store as $name => $value ) {
				if ( 0 !== strpos( $name, $m[1] ) ) {
					continue;
				}
				if ( null !== $expired && (int) explode( ':', (string) $value )[0] > $expired ) {
					continue; // still inside its window
				}
				unset( $this->store[ $name ] );
				++$gone;
			}
			$this->rows_affected = $gone;
			return $gone;
		}

		return 0;
	}

	public function get_var( $q ) {
		$this->last_error = '';
		if ( $this->fail_next || $this->fail_all ) {
			$this->fail_next  = false;
			$this->last_error = 'simulated DB error';
			return null;
		}
		if ( false !== strpos( $q, 'COUNT(*)' ) && preg_match( "/LIKE '([^']*)%'/", $q, $m ) ) {
			$n = 0;
			foreach ( $this->store as $name => $_ ) {
				if ( 0 === strpos( $name, $m[1] ) ) {
					++$n;
				}
			}
			return (string) $n;
		}
		if ( preg_match( "/option_name = '([^']*)'/", $q, $m ) ) {
			return $this->store[ $m[1] ] ?? null;
		}
		return null;
	}

	public function delete( $table, $where ) {
		unset( $this->store[ $where['option_name'] ?? '' ] );
		return 1;
	}
}
