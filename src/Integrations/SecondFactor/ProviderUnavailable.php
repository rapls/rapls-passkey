<?php
/**
 * Signals that a 2FA provider could not determine a user's second-factor state.
 *
 * @package RaplsPasskey
 */

namespace RaplsPasskey\Integrations\SecondFactor;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thrown by a Provider when the underlying 2FA plugin errors while we ask
 * whether a user has a second factor configured. It is deliberately distinct
 * from "the user has no second factor": the second-factor gate treats an
 * unavailable provider as a reason to *refuse* a weaker alternative login
 * (fail-closed), never as a reason to wave it through.
 */
final class ProviderUnavailable extends \RuntimeException {
}
