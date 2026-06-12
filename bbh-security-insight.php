<?php
/**
 * BBH Security Insight
 *
 * A lightweight, read-only WordPress security auditing plugin that generates
 * professional security risk reports with actionable recommendations.
 *
 * @link              https://wordpress.org/plugins/bbh-security-insight/
 * @since             1.0.0
 * @package           BBHSecurityInsight
 *
 * @wordpress-plugin
 * Plugin Name:       BBH Security Insight
 * Plugin URI:        https://wordpress.org/plugins/bbh-security-insight/
 * Description:       Perform lightweight read-only security health scans on your WordPress installation. Generate professional security risk reports with actionable recommendations.
 * Version:           1.0.0
 * Author:            Jahid Shah
 * Author URI:        https://jahidshah.com/
 * License:           GPL-2.0+
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       bbh-security-insight
 * Requires at least: 6.7
 * Requires PHP:      7.4
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
    die;
}

/**
 * Current plugin version.
 */
define( 'BBHSECINS_VERSION', '1.0.0' );

/**
 * Plugin base path.
 */
define( 'BBHSECINS_PLUGIN_PATH', plugin_dir_path( __FILE__ ) );

/**
 * Plugin base URL.
 */
define( 'BBHSECINS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Plugin base name.
 */
define( 'BBHSECINS_BASENAME', plugin_basename( __FILE__ ) );

/**
 * Minimum required capability to access plugin features.
 */
define( 'BBHSECINS_CAPABILITY', 'manage_options' );

/**
 * AJAX nonce action name.
 */
define( 'BBHSECINS_NONCE_ACTION', 'bbhsecins_audit_nonce' );

/**
 * AJAX nonce request parameter name.
 */
define( 'BBHSECINS_NONCE_NAME', 'bbhsecins_nonce' );

/**
 * Database option name for storing audit results.
 */
define( 'BBHSECINS_OPTION_KEY', 'bbhsecins_audit_results' );

/**
 * Database option name for dismissal of admin notices.
 */
define( 'BBHSECINS_NOTICE_DISMISS_KEY', 'bbhsecins_dismissed_notices' );

/**
 * WP-Cron hook name for automatic background audits.
 */
define( 'BBHSECINS_CRON_HOOK', 'bbhsecins_daily_audit' );

/**
 * Database option name for audit history.
 */
define( 'BBHSECINS_HISTORY_KEY', 'bbhsecins_audit_history' );

/**
 * The core plugin class autoloader.
 *
 * @since 1.0.0
 * @param string $class The fully-qualified class name.
 */
function bbhsecins_autoloader( $class ) {
    $prefix   = 'BBHSecurityInsight\\';
    $base_dir = BBHSECINS_PLUGIN_PATH;

    $len = strlen( $prefix );
    if ( strncmp( $prefix, $class, $len ) !== 0 ) {
        return;
    }

    $relative_class = substr( $class, $len );
    $relative_class = strtolower( $relative_class );
    $relative_class = str_replace( '_', '-', $relative_class );

    $parts = explode( '\\', $relative_class );
    $class_name = array_pop( $parts );

    $class_name = 'class-' . $class_name . '.php';

    $subdir = ! empty( $parts ) ? implode( '/', $parts ) . '/' : '';

    $file = $base_dir . $subdir . $class_name;

    if ( file_exists( $file ) ) {
        require $file;
    }
}
spl_autoload_register( 'bbhsecins_autoloader' );

/**
 * Activation hook.
 *
 * @since 1.0.0
 */
function bbhsecins_activate() {
    if ( ! current_user_can( 'activate_plugins' ) ) {
        return;
    }

    $plugin = isset( $_REQUEST['plugin'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) ) : '';
    check_admin_referer( "activate-plugin_{$plugin}" );

    set_transient( 'bbhsecins_activated', true, 30 );
    
    update_option(
        'bbhsecins_activated_at',
        time()
    );

    if ( ! wp_next_scheduled( BBHSECINS_CRON_HOOK ) ) {
        wp_schedule_event( time(), 'daily', BBHSECINS_CRON_HOOK );
    }
}
register_activation_hook( __FILE__, 'bbhsecins_activate' );

/**
 * Deactivation hook.
 *
 * @since 1.0.0
 */
function bbhsecins_deactivate() {
    if ( ! current_user_can( 'activate_plugins' ) ) {
        return;
    }

    $plugin = isset( $_REQUEST['plugin'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['plugin'] ) ) : '';
    check_admin_referer( "deactivate-plugin_{$plugin}" );

    delete_transient( 'bbhsecins_activated' );

    $timestamp = wp_next_scheduled( BBHSECINS_CRON_HOOK );
    if ( $timestamp ) {
        wp_unschedule_event( $timestamp, BBHSECINS_CRON_HOOK );
    }
}
register_deactivation_hook( __FILE__, 'bbhsecins_deactivate' );

/**
 * Begins execution of the plugin.
 *
 * @since 1.0.0
 */
function bbhsecins_init() {
    if ( is_admin() ) {
        new BBHSecurityInsight\Admin\Admin();
    }
}
add_action( 'plugins_loaded', 'bbhsecins_init' );

/**
 * Run automatic background audit via WP-Cron.
 *
 * @since 1.1.0
 */
function bbhsecins_cron_audit() {
    if ( ! function_exists( 'get_option' ) ) {
        return;
    }

    $audit   = new BBHSecurityInsight\Includes\Audit();
    $results = $audit->run_all_checks();

    $previous = get_option( BBHSECINS_OPTION_KEY, false );

    update_option( BBHSECINS_OPTION_KEY, $results, false );

    $history = get_option( BBHSECINS_HISTORY_KEY, array() );
    array_unshift( $history, array(
        'timestamp'  => $results['timestamp'],
        'score'      => $results['score'],
        'risk_level' => $results['risk_level'],
    ) );
    $history = array_slice( $history, 0, 5 );
    update_option( BBHSECINS_HISTORY_KEY, $history, false );

    if ( false === $previous ) {
        return;
    }

    $previous_risk  = isset( $previous['risk_level'] ) ? $previous['risk_level'] : '';
    $current_risk   = $results['risk_level'];
    $risk_changed   = ( $previous_risk !== $current_risk );
    $new_criticals  = array();
    $prev_by_id     = array();

    $previous_checks = isset( $previous['checks'] ) ? $previous['checks'] : array();
    foreach ( $previous_checks as $pc ) {
        if ( isset( $pc['id'] ) ) {
            $prev_by_id[ $pc['id'] ] = $pc;
        }
    }

    $current_checks = isset( $results['checks'] ) ? $results['checks'] : array();
    foreach ( $current_checks as $check ) {
        if ( ! isset( $check['id'], $check['risk'] ) || 'critical' !== $check['risk'] ) {
            continue;
        }
        $prev = isset( $prev_by_id[ $check['id'] ] ) ? $prev_by_id[ $check['id'] ] : null;
        if ( ! $prev || ( isset( $prev['risk'] ) && 'critical' !== $prev['risk'] ) ) {
            $new_criticals[] = $check['title'];
        }
    }

    if ( ! empty( $new_criticals ) || $risk_changed ) {
        set_transient(
            'bbhsecins_cron_alert',
            array(
                'new_criticals' => $new_criticals,
                'risk_changed'  => $risk_changed,
                'old_risk'      => $previous_risk,
                'new_risk'      => $current_risk,
                'score'         => $results['score'],
                'timestamp'     => $results['timestamp'],
            ),
            DAY_IN_SECONDS
        );
    }
}
add_action( BBHSECINS_CRON_HOOK, 'bbhsecins_cron_audit' );

/**
 * Show admin notice when automatic audit detects risk changes.
 *
 * @since 1.1.0
 */
function bbhsecins_cron_alert_notice() {
    if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
        return;
    }

    $alert = get_transient( 'bbhsecins_cron_alert' );
    if ( ! $alert || ! is_array( $alert ) ) {
        return;
    }

    delete_transient( 'bbhsecins_cron_alert' );

    $screen = get_current_screen();
    if ( ! $screen ) {
        return;
    }

    $dashboard_url = admin_url( 'admin.php?page=bbh-security-insight' );
    $new_criticals = isset( $alert['new_criticals'] ) ? $alert['new_criticals'] : array();
    $risk_changed  = ! empty( $alert['risk_changed'] );
    $old_risk      = isset( $alert['old_risk'] ) ? $alert['old_risk'] : '';
    $new_risk      = isset( $alert['new_risk'] ) ? $alert['new_risk'] : '';

    if ( ! empty( $new_criticals ) ) {
        ?>
        <div class="notice notice-error is-dismissible">
            <p>
                <?php
                printf(
                    wp_kses_post(
                        /* translators: %1$d: number of new critical issues, %2$s: dashboard URL */
                        _n(
                            'BBH Security Insight: <strong>%1$d new critical issue</strong> detected during automatic scan. <a href="%2$s">View report</a>',
                            'BBH Security Insight: <strong>%1$d new critical issues</strong> detected during automatic scan. <a href="%2$s">View report</a>',
                            count( $new_criticals ),
                            'bbh-security-insight'
                        )
                    ),
                    intval( count( $new_criticals ) ),
                    esc_url( $dashboard_url )
                );
                ?>
            </p>
        </div>
        <?php
    } elseif ( $risk_changed ) {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p>
                <?php
                printf(
                    wp_kses_post(
                        /* translators: %1$s: old risk level, %2$s: new risk level, %3$s: dashboard URL */
                        __(
                            'BBH Security Insight: Your site security status changed from <strong>%1$s</strong> to <strong>%2$s</strong>. <a href="%3$s">View report</a>',
                            'bbh-security-insight'
                        )
                    ),
                    esc_html( ucfirst( $old_risk ) ),
                    esc_html( ucfirst( $new_risk ) ),
                    esc_url( $dashboard_url )
                );
                ?>
            </p>
        </div>
        <?php
    }
}
add_action( 'admin_notices', 'bbhsecins_cron_alert_notice' );

/**
 * Activation transient handler — show welcome notice.
 *
 * @since 1.0.0
 */
function bbhsecins_activation_notice() {
    if ( ! get_transient( 'bbhsecins_activated' ) ) {
        return;
    }

    delete_transient( 'bbhsecins_activated' );

    if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
        return;
    }

    $admin_url = admin_url( 'admin.php?page=bbh-security-insight' );
    ?>
    <div class="notice notice-success is-dismissible">
        <p>
            <?php
            printf(
                /* translators: %s: admin dashboard URL */
                wp_kses_post( __( 'BBH Security Insight is ready! <a href="%s">Run your first security audit</a> to check your site&rsquo;s health.', 'bbh-security-insight' ) ),
                esc_url( $admin_url )
            );
            ?>
        </p>
    </div>
    <?php
}
add_action( 'admin_notices', 'bbhsecins_activation_notice' );
