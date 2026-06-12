<?php
/**
 * Uninstall cleanup for BBH Security Insight.
 *
 * Removes all plugin options and transients from the database
 * when the plugin is deleted via the WordPress admin.
 *
 * @since      1.0.0
 * @package    BBHSecurityInsight
 */

// If uninstall is not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Ensure the user has permission.
if ( ! current_user_can( 'activate_plugins' ) ) {
    return;
}

// Delete stored audit results.
delete_option( 'bbhsecins_audit_results' );

// Delete dismissed notices tracking.
delete_option( 'bbhsecins_dismissed_notices' );

// Delete audit history.
delete_option( 'bbhsecins_audit_history' );

// Delete any remaining transients.
delete_transient( 'bbhsecins_activated' );
delete_transient( 'bbhsecins_cron_alert' );
