<?php
/**
 * The admin-facing functionality of the plugin.
 *
 * Handles admin menu registration, dashboard page rendering,
 * AJAX audit execution, and dismissible admin notices.
 *
 * @since      1.0.0
 * @package    BBHSecurityInsight
 * @subpackage BBHSecurityInsight/Admin
 */
namespace BBHSecurityInsight\Admin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use BBHSecurityInsight\Includes\Audit;

/**
 * Admin class.
 *
 * @since 1.0.0
 */
class Admin {

    /**
     * Constructor.
     *
     * Hooks into WordPress admin actions.
     *
     * @since 1.0.0
     */
    public function __construct() {
        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );
        add_action( 'wp_ajax_bbhsecins_run_audit', array( $this, 'handle_ajax_audit' ) );
        add_action( 'wp_ajax_bbhsecins_dismiss_notice', array( $this, 'handle_ajax_dismiss_notice' ) );
        add_action( 'admin_notices', array( $this, 'render_admin_notices' ) );
    }

    /**
     * Register top-level admin menu with submenus.
     *
     * Also auto-heals the WP-Cron schedule if missing.
     *
     * @since 1.0.0
     * @return void
     */
    public function add_admin_menu() {
        if ( ! wp_next_scheduled( BBHSECINS_CRON_HOOK ) ) {
            wp_schedule_event( time(), 'daily', BBHSECINS_CRON_HOOK );
        }

        add_menu_page(
            esc_html__( 'BBH Security Insight', 'bbh-security-insight' ),
            esc_html__( 'BBH Security Insight', 'bbh-security-insight' ),
            BBHSECINS_CAPABILITY,
            'bbh-security-insight',
            array( $this, 'render_dashboard' ),
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'bbh-security-insight',
            esc_html__( 'View Results', 'bbh-security-insight' ),
            esc_html__( 'View Results', 'bbh-security-insight' ),
            BBHSECINS_CAPABILITY,
            'bbh-security-insight',
            array( $this, 'render_dashboard' )
        );

        add_submenu_page(
            'bbh-security-insight',
            esc_html__( 'Settings', 'bbh-security-insight' ),
            esc_html__( 'Settings', 'bbh-security-insight' ),
            BBHSECINS_CAPABILITY,
            'bbh-security-insight-settings',
            array( $this, 'render_settings' )
        );

        add_submenu_page(
            'bbh-security-insight',
            esc_html__( 'Documentation', 'bbh-security-insight' ),
            esc_html__( 'Documentation', 'bbh-security-insight' ),
            BBHSECINS_CAPABILITY,
            'bbh-security-insight-docs',
            array( $this, 'render_documentation' )
        );
    }

    /**
     * Enqueue admin styles and scripts.
     *
     * @since 1.0.0
     * @param string $hook The current admin page hook.
     * @return void
     */
    public function enqueue_admin_assets( $hook ) {
        $allowed_hooks = array(
            'toplevel_page_bbh-security-insight',
            'bbh-security-insight_page_bbh-security-insight-settings',
            'bbh-security-insight_page_bbh-security-insight-docs',
        );
        if ( ! in_array( $hook, $allowed_hooks, true ) ) {
            return;
        }

        wp_enqueue_style(
            'bbhsecins-admin',
            BBHSECINS_PLUGIN_URL . 'assets/css/bbhsecins-admin.css',
            array(),
            BBHSECINS_VERSION
        );

        wp_enqueue_script(
            'bbhsecins-admin',
            BBHSECINS_PLUGIN_URL . 'assets/js/bbhsecins-admin.js',
            array( 'jquery' ),
            BBHSECINS_VERSION,
            true
        );

        wp_localize_script(
            'bbhsecins-admin',
            'bbhsecinsData',
            array(
                'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
                'nonce'         => wp_create_nonce( BBHSECINS_NONCE_ACTION ),
                'nonceName'     => BBHSECINS_NONCE_NAME,
                'runningText'   => esc_html__( 'Running security audit...', 'bbh-security-insight' ),
                'errorText'     => esc_html__( 'An error occurred while running the audit. Please try again.', 'bbh-security-insight' ),
                'dismissNonce'  => wp_create_nonce( 'bbhsecins_dismiss_notice' ),
            )
        );
    }

    /**
     * Render the admin dashboard page.
     *
     * @since 1.0.0
     * @return void
     */
    public function render_dashboard() {
        if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'bbh-security-insight' ) );
        }

        $stored_results = get_option( BBHSECINS_OPTION_KEY, false );
        ?>
        <div class="bbhsecins-wrap">
            <div class="bbgsecinshead">
                <h1><?php echo esc_html( 'Security Insight' ); ?></h1>
                <p><?php esc_html_e( 'Your WordPress security overview', 'bbh-security-insight' ); ?></p>
            </div>

            <div class="bbhsecins-intro bbhsecins-audit-panel">
                <p>
                    <?php
                    esc_html_e(
                        'Run a lightweight, read-only security health scan on your WordPress installation.
                        The audit checks common security configurations, file exposures, and security best-practice indicators
                        without making any changes to your site.',
                        'bbh-security-insight'
                    );
                    ?>
                </p>
                <button type="button" id="bbhsecins-run-audit" class="button button-primary button-hero">
                    <span class="dashicons dashicons-shield runsecurityicon"></span>
                    <?php esc_html_e( 'Run Security Audit', 'bbh-security-insight' ); ?>
                </button>
                <span class="spinner" id="bbhsecins-spinner"></span>
                <p class="bbhsecins-last-run" id="bbhsecins-last-run">
                    <?php
                    if ( ! empty( $stored_results['timestamp'] ) ) {
                        printf(
                            /* translators: %s: formatted date and time of the last audit. */
                            esc_html__( 'Last audit: %s', 'bbh-security-insight' ),
                            esc_html( $this->format_timestamp( $stored_results['timestamp'] ) )
                        );
                    }
                    ?>
                </p>
            </div>

            <?php $this->render_scan_history(); ?>

            <div id="bbhsecins-results">
                <?php
                if ( ! empty( $stored_results ) ) {
                    $this->render_report( $stored_results );
                }
                ?>
            </div>

            <div class="bbhsecins-footer">
                <hr>
                <p>
                    <?php
                    printf(
                        /* translators: %s: URL to professional security services */
                        wp_kses_post(
                            /* translators: %s: Contact link URL for security services */
                            __(
                                'Need more information? <a href="%s" target="_blank" rel="noopener noreferrer">Visit the documentation</a> for WordPress security guidance and best practices.',
                                'bbh-security-insight'
                            )
                        ),
                        esc_url( 'https://jahidshah.com/plugins/bbh-security-insight/' )
                    );
                    ?>
                </p>
            </div>
        </div>
        <?php
    }

    /**
     * Render the Settings page.
     *
     * @since 1.4.0
     * @return void
     */
    public function render_settings() {
        if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'bbh-security-insight' ) );
        }
        ?>
        <div class="wrap bbhsecins-wrap">
            <h1><?php esc_html_e( 'Settings', 'bbh-security-insight' ); ?></h1>
            <div class="bbhsecins-intro">
                <p><?php esc_html_e( 'No configurable settings are available yet. The plugin runs a read-only security audit with sensible defaults. Future versions will include configurable scan options, notification preferences, and exclusion rules.', 'bbh-security-insight' ); ?></p>
            </div>
        </div>
        <?php
    }

    /**
     * Render the Documentation page.
     *
     * @since 1.4.0
     * @return void
     */
    public function render_documentation() {
        if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'bbh-security-insight' ) );
        }
        ?>
        <div class="bbhsecins-wrap">
            <div class="bbhsecins-header bbgsecinshead">
                <h1><?php esc_html_e( 'Documentation', 'bbh-security-insight' ); ?></h1>
                <p><?php esc_html_e( 'Welcome to BBH Security Insight Documentation', 'bbh-security-insight' ); ?></p>
                <p><?php esc_html_e( 'This documentation provides an overview of how BBH Security Insight works, the security checks it performs, and how to interpret your security score.', 'bbh-security-insight' ); ?></p>                    
            </div>
            <div class="bbhsecins-docs-wrap">
                <div class="bbhsecins-intro bbhsecins-check-content">
                    <div class="bbhsecins-postbox">
                        <h2><?php esc_html_e( 'How It Works', 'bbh-security-insight' ); ?></h2>
                        <p><?php esc_html_e( 'BBH Security Insight performs a lightweight read-only security audit of your WordPress installation. It checks common security configurations, file exposures, and security best-practice indicators without making any changes to your site.', 'bbh-security-insight' ); ?></p>
                    </div>

                    <div class="bbhsecins-postbox">
                        <h2><?php esc_html_e( 'Security Checks', 'bbh-security-insight' ); ?></h2>
                        <p><?php esc_html_e( 'The audit runs 15 different checks covering: WordPress version exposure, database prefix safety, XML-RPC status, file editing permissions, debug mode, directory browsing, sensitive file exposure, file permissions, user enumeration, security headers, uploads security, admin username safety, and basic malware pattern heuristics.', 'bbh-security-insight' ); ?></p>
                    </div>

                    <div class="bbhsecins-postbox">
                        <h2><?php esc_html_e( 'Score Calculation', 'bbh-security-insight' ); ?></h2>
                        <p><?php esc_html_e( 'The security score starts at 100 and is reduced for each failing check. Critical findings reduce the score more heavily than warnings. Higher scores indicate better security posture.', 'bbh-security-insight' ); ?></p>
                    </div>

                    <div class="bbhsecins-postbox">
                        <h2><?php esc_html_e( 'Auto Scan', 'bbh-security-insight' ); ?></h2>
                        <p><?php esc_html_e( 'A daily automatic scan is scheduled via WP-Cron when the plugin is activated. Results are stored in the database and visible on the Dashboard. The auto-scan also detects risk changes and alerts administrators via dashboard notices.', 'bbh-security-insight' ); ?></p>
                    </div>
                </div>
                <div class="bbhsecins-check-sidbar">
                    <div class="bbhsecins-postbox">
                        <h2 id="bbhred-title">
                            <?php esc_html_e( 'About Author', 'bbh-security-insight' ); ?>
                        </h2>
                        <div class="bbhsecins-author-box">
                            <div class="plugin-author-img"></div>
                            <p class="bbhre-postbox">
                                <?php
                                    printf(
                                        wp_kses_post(
                                                /* translators: %s: Author URL */
                                                __(
                                                    'I\'m <strong><a href="%s" target="_blank" rel="noopener noreferrer">Jahid Shah</a></strong>, a front-end developer with specialized skills in WordPress theme development and WordPress Security. I am passionate about creating error-free, secure websites and achieving 100%% client satisfaction. Solving real-world problems is my passion.',
                                                    'bbh-security-insight'
                                                )
                                            ),
                                            esc_url( 'https://jahidshah.com/' )
                                    );
                                ?>
                                
                            </p>
                            <div>
                                <p class="bbhre-postbox bbh-bmc-btn">
                                    <?php
                                        printf(
                                            wp_kses_post(
                                                /* translators: %s: Developer support URL */
                                                __(
                                                    'If you found this plugin helpful, you can support the developer via - <br><a href="%s" target="_blank" rel="noopener noreferrer">Buy Me a Coffee</a>',
                                                    'bbh-security-insight'
                                                )
                                            ),
                                            esc_url( 'https://www.buymeacoffee.com/jahidshah' )
                                        );
                                    ?>
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="bbhsecins-postbox">
                        <h2><?php esc_html_e( 'Need Help?', 'bbh-security-insight' ); ?></h2>
                        <p><?php esc_html_e( 'If you have any questions or need assistance, please contact our support team.', 'bbh-security-insight' ); ?></p>
                        <p>
                            <a href="https://jahidshah.com/contact-me/" target="_blank" rel="noopener noreferrer" class="button">
                                <?php esc_html_e( 'Contact Support', 'bbh-security-insight' ); ?>
                            </a>
                        </p>
                    </div>
                </div>
            </div>

        </div>
        <?php
    }

    /**
     * Render the scan status panel with auto-schedule info and audit history.
     *
     * @since 1.1.0
     * @return void
     */
    private function render_scan_history() {
        $history = get_option( BBHSECINS_HISTORY_KEY, array() );
        $cron_scheduled = wp_next_scheduled( BBHSECINS_CRON_HOOK );
        ?>
        <div class="bbhsecins-history-panel">
            <div class="bbhsecins-history-header">
                <h2><?php esc_html_e( 'Scan Status &amp; History', 'bbh-security-insight' ); ?></h2>
            </div>

            <div class="bbhsecins-history-grid">
                <div class="bbhsecins-history-item">
                    <span class="bbhsecins-history-label"><?php esc_html_e( 'Auto Scan', 'bbh-security-insight' ); ?></span>
                    <span class="bbhsecins-history-value">
                        <?php if ( $cron_scheduled ) : ?>
                            <span class="bbhsecins-badge bbhsecins-safe"><?php esc_html_e( 'Active', 'bbh-security-insight' ); ?></span>
                            <span class="bbhsecins-history-sub">
                                <?php
                                printf(
                                    /* translators: %s: next scheduled run time */
                                    esc_html__( 'Next: %s', 'bbh-security-insight' ),
                                    esc_html( $this->format_timestamp( $cron_scheduled ) )
                                );
                                ?>
                            </span>
                        <?php else : ?>
                            <span class="bbhsecins-badge bbhsecins-warning"><?php esc_html_e( 'Inactive', 'bbh-security-insight' ); ?></span>
                        <?php endif; ?>
                    </span>
                </div>

                <div class="bbhsecins-history-item">
                    <span class="bbhsecins-history-label"><?php esc_html_e( 'Frequency', 'bbh-security-insight' ); ?></span>
                    <span class="bbhsecins-history-value bbhsecins-history-frequency">
                        <?php esc_html_e( 'Daily', 'bbh-security-insight' ); ?>
                    </span>
                </div>

                <div class="bbhsecins-history-item">
                    <span class="bbhsecins-history-label"><?php esc_html_e( 'History', 'bbh-security-insight' ); ?></span>
                    <span class="bbhsecins-history-value bbhsecins-history-scans">
                        <?php if ( ! empty( $history ) ) : ?>
                            <?php foreach ( $history as $entry ) : ?>
                                <span class="bbhsecins-history-entry bbhsecins-entry-<?php echo esc_attr( $entry['risk_level'] ); ?>">
                                    <span class="bbhsecins-entry-score"><?php echo esc_html( $entry['score'] ); ?>/100</span>
                                    <span class="bbhsecins-entry-date"><?php echo esc_html( $this->format_timestamp( $entry['timestamp'] ) ); ?></span>
                                </span>
                            <?php endforeach; ?>
                        <?php else : ?>
                            <?php esc_html_e( 'No history yet.', 'bbh-security-insight' ); ?>
                        <?php endif; ?>
                    </span>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Render the full security report.
     *
     * @since 1.0.0
     * @param array $results The audit results from Audit::run_all_checks().
     * @return void
     */
    private function render_report( array $results ) {
        $score      = isset( $results['score'] ) ? (int) $results['score'] : 0;
        $risk_level = isset( $results['risk_level'] ) ? $results['risk_level'] : Audit::RISK_SAFE;
        $checks     = isset( $results['checks'] ) ? $results['checks'] : array();
        $timestamp  = isset( $results['timestamp'] ) ? $results['timestamp'] : 0;

        $risk_class = $this->get_risk_css_class( $risk_level );
        $risk_label = $this->get_risk_label( $risk_level );
        ?>
        <div class="bbhsecins-report">

            <div class="bbhsecins-score-card <?php echo esc_attr( $risk_class ); ?>">
                <div class="bbhsecins-score-circle">
                    <span class="bbhsecins-score-number"><?php echo esc_html( $score ); ?></span>
                    <span class="bbhsecins-score-label">/ 100</span>
                </div>
                <div class="bbhsecins-score-info">
                    <h2><?php echo esc_html( $risk_label ); ?></h2>
                    <p>
                        <?php
                        printf(
                            /* translators: %s: formatted date/time */
                            esc_html__( 'Security Risk Report &mdash; generated %s', 'bbh-security-insight' ),
                            esc_html( $this->format_timestamp( $timestamp ) )
                        );
                        ?>
                    </p>
                    <p class="bbhsecins-score-desc">
                        <?php echo esc_html( $this->get_overall_description( $risk_level, $score ) ); ?>
                    </p>
                    <p class="bbhsencins-score-note">
                        <?php esc_html_e( 'Your score reflects the results of the current security audit. Higher scores indicate a healthier security configuration.', 'bbh-security-insight' ); ?>
                    </p>
                </div>
            </div>

            <table class="wp-list-table widefat fixed striped bbhsecins-checks-table">
                <thead>
                    <tr>
                        <th scope="col" class="bbhsecins-col-status"><?php esc_html_e( 'Status', 'bbh-security-insight' ); ?></th>
                        <th scope="col" class="bbhsecins-col-check"><?php esc_html_e( 'Security Check', 'bbh-security-insight' ); ?></th>
                        <th scope="col" class="bbhsecins-col-detail"><?php esc_html_e( 'Details', 'bbh-security-insight' ); ?></th>
                        <th scope="col" class="bbhsecins-col-recommendation"><?php esc_html_e( 'Recommendation', 'bbh-security-insight' ); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $checks as $check ) : ?>
                        <?php $this->render_check_row( $check ); ?>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    /**
     * Render a single check result row.
     *
     * @since 1.0.0
     * @param array $check Single check result array.
     * @return void
     */
    private function render_check_row( array $check ) {
        $risk        = isset( $check['risk'] ) ? $check['risk'] : Audit::RISK_SAFE;
        $title       = isset( $check['title'] ) ? $check['title'] : '';
        $description = isset( $check['description'] ) ? $check['description'] : '';
        $recommend   = isset( $check['recommendation'] ) ? $check['recommendation'] : '';
        $current_val = isset( $check['current_value'] ) ? $check['current_value'] : '';
        $risk_class  = $this->get_risk_css_class( $risk );
        $risk_badge  = $this->get_risk_badge( $risk );
        $verdict          = isset( $check['verdict'] ) ? $check['verdict'] : '';
        $disclaimer       = isset( $check['disclaimer'] ) ? $check['disclaimer'] : '';
        $needs_manual_rev = ! empty( $check['needs_manual_review'] );
        ?>
        <tr class="bbhsecins-check-row bbhsecins-risk-<?php echo esc_attr( $risk ); ?>">
            <td class="bbhsecins-col-status">
                <span class="bbhsecins-badge <?php echo esc_attr( $risk_class ); ?>">
                    <?php echo esc_html( $risk_badge ); ?>
                </span>
                <?php if ( $verdict && 'clean' !== $verdict ) : ?>
                    <br><span class="bbhsecins-confidence bbhsecins-confidence-<?php echo esc_attr( $verdict ); ?>">
                        <?php echo esc_html( ucfirst( $verdict ) ); ?>
                    </span>
                <?php endif; ?>
                <?php if ( $needs_manual_rev ) : ?>
                    <br><span class="bbhsecins-review-badge">
                        <?php esc_html_e( 'Needs Manual Review', 'bbh-security-insight' ); ?>
                    </span>
                <?php endif; ?>
            </td>
            <td class="bbhsecins-col-check">
                <strong><?php echo esc_html( $title ); ?></strong>
                <?php if ( $current_val ) : ?>
                    <br><span class="bbhsecins-current-value">
                        <?php
                        /* translators: %s: current value */
                        printf( esc_html__( 'Current: %s', 'bbh-security-insight' ), wp_kses_post( $current_val ) );
                        ?>
                    </span>
                <?php endif; ?>
            </td>
            <td class="bbhsecins-col-detail">
                <?php
                    // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Output escaped in kses_evidence().
                    echo $this->kses_evidence( $description );
                ?>
                <?php if ( $disclaimer ) : ?>
                    <p class="bbhsecins-disclaimer"><?php echo wp_kses_post( $disclaimer ); ?></p>
                <?php endif; ?>
            </td>
            <td class="bbhsecins-col-recommendation">
                <?php echo wp_kses_post( $recommend ); ?>
            </td>
        </tr>
        <?php
    }

    /**
     * Render dismissible admin notices (except on the plugin page).
     *
     * @since 1.0.0
     * @return void
     */
    public function render_admin_notices() {
        $activated_at = get_option(
        'bbhsecins_activated_at'
        );

        if (
            empty( $activated_at ) ||
            ( time() - (int) $activated_at ) < WEEK_IN_SECONDS
        ) {
            return;
        }
        //Only show the notice if there's a recent audit report (indicating the plugin is being used).
        $latest_report = get_option( 'bbhsecins_audit_results' );

        if ( empty( $latest_report ) ) {
            return;
        }

        $screen = get_current_screen();

        // Only show the notice on the plugin's dashboard page, not on other admin pages.
        if ( ! $screen || 'toplevel_page_bbh-security-insight' !== $screen->id ) {
            return;
        }

        $dismissed = get_option( BBHSECINS_NOTICE_DISMISS_KEY, array() );

        if ( in_array( 'rate_notice', $dismissed, true ) ) {
            return;
        }

        ?>
        <div class="notice notice-info is-dismissible bbhsecins-notice" data-bbhsecins-notice="rate_notice">
            <p>
                <?php
                printf(
                    wp_kses_post(
                        /* translators: %s: plugin support forum URL */
                        __(
                            'Enjoying BBH Security Insight? <a href="%s" target="_blank" rel="noopener noreferrer">Please leave a review</a> to help others discover this plugin!',
                            'bbh-security-insight'
                        )
                    ),
                    esc_url( 'https://wordpress.org/support/plugin/bbh-security-insight/reviews/' )
                );
                ?>
            </p>
        </div>
        <?php
    }

    /**
     * AJAX handler for running the security audit.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_ajax_audit() {
        if ( ! isset( $_POST[ BBHSECINS_NONCE_NAME ] ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Missing nonce.', 'bbh-security-insight' ) ) );
        }

        $nonce = sanitize_text_field( wp_unslash( $_POST[ BBHSECINS_NONCE_NAME ] ) );

        if ( ! wp_verify_nonce( $nonce, BBHSECINS_NONCE_ACTION ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Invalid nonce. Please refresh the page.', 'bbh-security-insight' ) ) );
        }

        if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Insufficient permissions.', 'bbh-security-insight' ) ) );
        }

        $audit   = new Audit();
        $results = $audit->run_all_checks();

        update_option( BBHSECINS_OPTION_KEY, $results, false );

        $history = get_option( BBHSECINS_HISTORY_KEY, array() );
        array_unshift( $history, array(
            'timestamp'  => $results['timestamp'],
            'score'      => $results['score'],
            'risk_level' => $results['risk_level'],
        ) );
        $history = array_slice( $history, 0, 5 );
        update_option( BBHSECINS_HISTORY_KEY, $history, false );

        ob_start();
        $this->render_report( $results );
        $html = ob_get_clean();

        wp_send_json_success(
            array(
                'html'       => $html,
                'risk_level' => $results['risk_level'],
                'score'      => $results['score'],
            )
        );
    }

    /**
     * AJAX handler for dismissing admin notices.
     *
     * @since 1.0.0
     * @return void
     */
    public function handle_ajax_dismiss_notice() {
        if ( ! isset( $_POST['notice_key'] ) || ! isset( $_POST['_wpnonce'] ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Missing parameters.', 'bbh-security-insight' ) ) );
        }

        $nonce = sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) );

        if ( ! wp_verify_nonce( $nonce, 'bbhsecins_dismiss_notice' ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Invalid nonce.', 'bbh-security-insight' ) ) );
        }

        if ( ! current_user_can( BBHSECINS_CAPABILITY ) ) {
            wp_send_json_error( array( 'message' => esc_html__( 'Insufficient permissions.', 'bbh-security-insight' ) ) );
        }

        $notice_key = sanitize_key( wp_unslash( $_POST['notice_key'] ) );
        $dismissed  = get_option( BBHSECINS_NOTICE_DISMISS_KEY, array() );

        if ( ! in_array( $notice_key, $dismissed, true ) ) {
            $dismissed[] = $notice_key;
            update_option( BBHSECINS_NOTICE_DISMISS_KEY, $dismissed, false );
        }

        wp_send_json_success();
    }

    /**
     * Format a Unix timestamp for display.
     *
     * @since 1.0.0
     * @param int $timestamp Unix timestamp.
     * @return string Formatted date/time string.
     */
    private function format_timestamp( $timestamp ) {
        if ( ! $timestamp ) {
            return '&mdash;';
        }

        $date_format = get_option( 'date_format' );
        $time_format = get_option( 'time_format' );
        $format      = "$date_format $time_format";

        if ( function_exists( 'wp_date' ) ) {
            return wp_date( $format, $timestamp );
        }

        $gmt_offset = (float) get_option( 'gmt_offset' );
        $local_ts   = $timestamp + ( $gmt_offset * HOUR_IN_SECONDS );

        return date_i18n( $format, $local_ts, true );
    }

    /**
     * Get the CSS class for a given risk level.
     *
     * @since 1.0.0
     * @param string $risk Risk level constant.
     * @return string CSS class name.
     */
    private function get_risk_css_class( $risk ) {
        switch ( $risk ) {
            case Audit::RISK_CRITICAL:
                return 'bbhsecins-critical';
            case Audit::RISK_WARNING:
                return 'bbhsecins-warning';
            default:
                return 'bbhsecins-safe';
        }
    }

    /**
     * Get the human-readable label for a risk level.
     *
     * @since 1.0.0
     * @param string $risk Risk level constant.
     * @return string Label.
     */
    private function get_risk_label( $risk ) {
        switch ( $risk ) {
            case Audit::RISK_CRITICAL:
                return esc_html__( 'Critical Risk', 'bbh-security-insight' );
            case Audit::RISK_WARNING:
                return esc_html__( 'Warning — Action Recommended', 'bbh-security-insight' );
            default:
                return esc_html__( 'Good — Low Risk', 'bbh-security-insight' );
        }
    }

    /**
     * Get the short badge text for a risk level.
     *
     * @since 1.0.0
     * @param string $risk Risk level constant.
     * @return string Badge text.
     */
    private function get_risk_badge( $risk ) {
        switch ( $risk ) {
            case Audit::RISK_CRITICAL:
                return esc_html__( 'Critical', 'bbh-security-insight' );
            case Audit::RISK_WARNING:
                return esc_html__( 'Warning', 'bbh-security-insight' );
            default:
                return esc_html__( 'Safe', 'bbh-security-insight' );
        }
    }

    /**
     * Get an overall description of the site based on risk level and score.
     *
     * @since 1.0.0
     * @param string $risk  Risk level.
     * @param int    $score Security score.
     * @return string Description.
     */
    private function get_overall_description( $risk, $score ) {
        if ( Audit::RISK_CRITICAL === $risk ) {
            return esc_html__(
                'Your site has multiple critical security issues that require immediate attention.
                Address the Critical findings above as soon as possible to reduce the risk of compromise.',
                'bbh-security-insight'
            );
        }

        if ( Audit::RISK_WARNING === $risk ) {
            return esc_html__(
                'Your site has some security weaknesses that should be addressed.
                Review the Warning items and apply the recommended remediations to improve your security posture.',
                'bbh-security-insight'
            );
        }

        return esc_html__(
            'Your site appears to follow most security best practices.
            Continue monitoring your security posture regularly to maintain this level.',
            'bbh-security-insight'
        );
    }

    /**
     * Apply kses with additional tags needed for the evidence panel.
     *
     * @since 1.2.0
     * @param string $html Raw HTML content.
     * @return string Safe HTML.
     */
    private function kses_evidence( $html ) {
        $allowed = wp_kses_allowed_html( 'post' );

        $allowed['details'] = array(
            'class' => true,
        );
        $allowed['summary'] = array(
            'class' => true,
        );

        return wp_kses( $html, $allowed );
    }
}
