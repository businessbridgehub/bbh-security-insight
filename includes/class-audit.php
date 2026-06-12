<?php
/**
 * The security audit functionality of the plugin.
 *
 * Performs read-only security health checks and generates structured
 * audit results used by the admin dashboard.
 *
 * @since      1.0.0
 * @package    BBHSecurityInsight
 * @subpackage BBHSecurityInsight/Includes
 */

namespace BBHSecurityInsight\Includes;

/**
 * Audit class.
 *
 * Contains all individual security check methods and the orchestration
 * method that runs them in sequence.
 *
 * @since 1.0.0
 */

defined( 'ABSPATH' ) || exit;

class Audit {

    /**
     * Risk level constants.
     */
    const RISK_CRITICAL = 'critical';
    const RISK_WARNING  = 'warning';
    const RISK_SAFE     = 'safe';

    /**
     * Score weight constants per risk level.
     */
    const SCORE_CRITICAL_PENALTY = 6;
    const SCORE_WARNING_PENALTY  = 3;

    /**
     * Run all security audit checks.
     *
     * @since 1.0.0
     * @return array{
     *   checks: array,
     *   score: int,
     *   risk_level: string,
     *   timestamp: int
     * }
     */
    public function run_all_checks() {
        $checks = array();

        $checks[] = $this->check_wp_version_exposure();
        $checks[] = $this->check_db_prefix();
        $checks[] = $this->check_xmlrpc();
        $checks[] = $this->check_file_edit_disabled();
        $checks[] = $this->check_wp_debug();
        $checks[] = $this->check_directory_browsing();
        $checks[] = $this->check_readme_html();
        $checks[] = $this->check_install_php();
        $checks[] = $this->check_wp_config_permissions();
        $checks[] = $this->check_wp_content_permissions();
        $checks[] = $this->check_user_enumeration();
        $checks[] = $this->check_security_headers();
        $checks[] = $this->check_uploads_php_execution();
        $checks[] = $this->check_admin_username();

        $malware_result = $this->check_malware_heuristics();
        if ( self::RISK_SAFE !== $malware_result['risk'] ) {
            $checks[] = $malware_result;
        }

        $score      = $this->calculate_score( $checks );
        $risk_level = $this->determine_risk_level( $score );

        return array(
            'checks'     => $checks,
            'score'      => $score,
            'risk_level' => $risk_level,
            'timestamp'  => time(),
        );
    }

    /**
     * Calculate overall security score (0–100).
     *
     * @since 1.0.0
     * @param array $checks Array of check results.
     * @return int Score from 0 to 100.
     */
    private function calculate_score( array $checks ) {
        $score = 100;

        foreach ( $checks as $check ) {
            if ( self::RISK_CRITICAL === $check['risk'] ) {
                $score -= self::SCORE_CRITICAL_PENALTY;
            } elseif ( self::RISK_WARNING === $check['risk'] ) {
                $score -= self::SCORE_WARNING_PENALTY;
            }
        }

        return max( 0, min( 100, $score ) );
    }

    /**
     * Determine overall risk level based on score.
     *
     * @since 1.0.0
     * @param int $score The security score.
     * @return string Risk level.
     */
    private function determine_risk_level( $score ) {
        if ( $score <= 40 ) {
            return self::RISK_CRITICAL;
        }
        if ( $score <= 70 ) {
            return self::RISK_WARNING;
        }
        return self::RISK_SAFE;
    }

    /**
     * Build a standardized check result array.
     *
     * @since 1.0.0
     * @param string $id            Unique check identifier.
     * @param string $title         Human-readable title.
     * @param string $risk          Risk level constant.
     * @param string $description   Human-readable explanation.
     * @param string $recommendation Remediation guidance.
     * @param string $current_value Current value or status text.
     * @return array Formatted check result.
     */
    private function build_result( $id, $title, $risk, $description, $recommendation, $current_value = '' ) {
        return array(
            'id'             => $id,
            'title'          => $title,
            'risk'           => $risk,
            'description'    => $description,
            'recommendation' => $recommendation,
            'current_value'  => $current_value,
        );
    }

    /**
     * 1. Check WordPress version exposure.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_wp_version_exposure() {
        global $wp_version;

        $readme_path = ABSPATH . 'readme.html';
        $readme_exists = file_exists( $readme_path );

        $generator_tag = false;
        $has_theme = wp_get_theme();
        if ( $has_theme->exists() ) {
            $generator_tag = true;
        }

        $issues = array();
        if ( $readme_exists ) {
            $issues[] = __( 'readme.html exists and typically exposes the WordPress version.', 'bbh-security-insight' );
        }

        $current_value = $wp_version;

        if ( $readme_exists ) {
            return $this->build_result(
                'wp_version_exposure',
                __( 'WordPress Version Exposure', 'bbh-security-insight' ),
                self::RISK_WARNING,
                sprintf(
                    /* translators: %s: WordPress version number */
                    __( 'Your site is running WordPress %s. The readme.html file is present, which can reveal the WordPress version to potential attackers. This information helps attackers target known vulnerabilities for your specific version.', 'bbh-security-insight' ),
                    $wp_version
                ),
                __( 'Delete the readme.html file from your WordPress root directory. Additionally, consider removing the WordPress generator tag from your site&rsquo;s head using a security plugin or theme function.', 'bbh-security-insight' ),
                $current_value
            );
        }

        return $this->build_result(
            'wp_version_exposure',
            __( 'WordPress Version Exposure', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'WordPress version is not easily exposed. The readme.html file is not present.', 'bbh-security-insight' ),
            __( 'No action needed. Continue to keep your WordPress version private.', 'bbh-security-insight' ),
            $current_value
        );
    }

    /**
     * 2. Check database prefix.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_db_prefix() {
        global $wpdb;

        $prefix = $wpdb->prefix;
        $is_default = ( 'wp_' === $prefix );

        if ( $is_default ) {
            return $this->build_result(
                'db_prefix',
                __( 'Database Table Prefix', 'bbh-security-insight' ),
                self::RISK_WARNING,
                sprintf(
                /* translators: %s: database prefix */
                    __( 'Your database table prefix is the default &ldquo;%s&rdquo;. This makes it easier for attackers to perform SQL injection attacks since the default table names are well-known.', 'bbh-security-insight' ),
                    $prefix
                ),
                __( 'Change your WordPress database table prefix to a custom, unique value. This can be done via a security plugin or manually by editing wp-config.php and renaming tables in phpMyAdmin.', 'bbh-security-insight' ),
                $prefix
            );
        }

        return $this->build_result(
            'db_prefix',
            __( 'Database Table Prefix', 'bbh-security-insight' ),
            self::RISK_SAFE,
            sprintf(
            /* translators: %s: database prefix */
                __( 'Your database table prefix is &ldquo;%s&rdquo;, which is not the default. This adds a layer of obscurity against automated SQL injection attacks.', 'bbh-security-insight' ),
                $prefix
            ),
            __( 'No action needed. Keep using a non-default prefix.', 'bbh-security-insight' ),
            $prefix
        );
    }

    /**
     * 3. Check XML-RPC status.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_xmlrpc() {
        $xmlrpc_file = ABSPATH . 'xmlrpc.php';
        $xmlrpc_exists = file_exists( $xmlrpc_file );

        if ( $xmlrpc_exists ) {
            // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core hook.
            $is_enabled = apply_filters( 'xmlrpc_enabled', true );

            if ( $is_enabled ) {
                return $this->build_result(
                    'xmlrpc',
                    __( 'XML-RPC Status', 'bbh-security-insight' ),
                    self::RISK_WARNING,
                    __( 'XML-RPC is enabled on your site. This protocol can be used for brute-force attacks, pingback attacks, and DDoS amplification. If you do not need XML-RPC (e.g., for the WordPress mobile app or Jetpack), it should be disabled.', 'bbh-security-insight' ),
                    __( 'Disable XML-RPC by adding <code>add_filter(&#39;xmlrpc_enabled&#39;, &#39;__return_false&#39;);</code> to your theme&rsquo;s functions.php file or use a security plugin to block XML-RPC requests.', 'bbh-security-insight' ),
                    __( 'Enabled', 'bbh-security-insight' )
                );
            }

            return $this->build_result(
                'xmlrpc',
                __( 'XML-RPC Status', 'bbh-security-insight' ),
                self::RISK_SAFE,
                __( 'XML-RPC is disabled, preventing attacks that exploit this protocol.', 'bbh-security-insight' ),
                __( 'No action needed.', 'bbh-security-insight' ),
                __( 'Disabled', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'xmlrpc',
            __( 'XML-RPC Status', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'XML-RPC file not found. This protocol is not available for exploitation.', 'bbh-security-insight' ),
            __( 'No action needed.', 'bbh-security-insight' ),
            __( 'Not present', 'bbh-security-insight' )
        );
    }

    /**
     * 4. Check if DISALLOW_FILE_EDIT is defined and true.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_file_edit_disabled() {
        if ( defined( 'DISALLOW_FILE_EDIT' ) && true === DISALLOW_FILE_EDIT ) {
            return $this->build_result(
                'file_edit_disabled',
                __( 'File Editor Disabled (DISALLOW_FILE_EDIT)', 'bbh-security-insight' ),
                self::RISK_SAFE,
                __( 'The WordPress built-in file editor is disabled. This prevents authenticated administrators from editing plugin and theme files directly from the admin dashboard, reducing the risk of code injection through compromised accounts.', 'bbh-security-insight' ),
                __( 'No action needed. This is the recommended security configuration.', 'bbh-security-insight' ),
                __( 'Defined and enabled', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'file_edit_disabled',
            __( 'File Editor Disabled (DISALLOW_FILE_EDIT)', 'bbh-security-insight' ),
            self::RISK_WARNING,
            __( 'The WordPress built-in file editor is enabled. Administrators can edit plugin and theme files directly from the admin dashboard. If an admin account is compromised, an attacker could inject malicious code.', 'bbh-security-insight' ),
            __( 'Add <code>define(&#39;DISALLOW_FILE_EDIT&#39;, true);</code> to your wp-config.php file, placing it before the &ldquo;That&rsquo;s all, stop editing&rdquo; comment.', 'bbh-security-insight' ),
            __( 'Not defined or disabled', 'bbh-security-insight' )
        );
    }

    /**
     * 5. Check WP_DEBUG status.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_wp_debug() {
        $wp_debug = defined( 'WP_DEBUG' ) && true === WP_DEBUG;
        $wp_debug_display = defined( 'WP_DEBUG_DISPLAY' ) && true === WP_DEBUG_DISPLAY;

        if ( $wp_debug && $wp_debug_display ) {
            return $this->build_result(
                'wp_debug',
                __( 'WP_DEBUG Status', 'bbh-security-insight' ),
                self::RISK_WARNING,
                __( 'WordPress debugging mode is enabled with display of errors turned on. This can expose sensitive information like database connection details, file paths, and stack traces to site visitors.', 'bbh-security-insight' ),
                __( 'On production sites, set WP_DEBUG to false in wp-config.php, or at minimum set WP_DEBUG_DISPLAY to false and WP_DEBUG_LOG to true so errors are logged to a file rather than displayed.', 'bbh-security-insight' ),
                __( 'Enabled & displayed', 'bbh-security-insight' )
            );
        }

        if ( $wp_debug && ! $wp_debug_display ) {
            return $this->build_result(
                'wp_debug',
                __( 'WP_DEBUG Status', 'bbh-security-insight' ),
                self::RISK_SAFE,
                __( 'WordPress debugging is enabled but errors are not displayed to visitors. Errors are logged internally, which is a safer configuration for staging environments.', 'bbh-security-insight' ),
                __( 'Ensure WP_DEBUG is set to false on production sites.', 'bbh-security-insight' ),
                __( 'Enabled (logged only)', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'wp_debug',
            __( 'WP_DEBUG Status', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'WordPress debugging mode is disabled on your site, which is the recommended configuration for production environments.', 'bbh-security-insight' ),
            __( 'No action needed.', 'bbh-security-insight' ),
            __( 'Disabled', 'bbh-security-insight' )
        );
    }

    /**
     * 6. Check directory browsing protection.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_directory_browsing() {
        $htaccess_file = ABSPATH . '.htaccess';
        $protected = false;

        if ( file_exists( $htaccess_file ) && is_readable( $htaccess_file ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            $content = file_get_contents( $htaccess_file );
            if ( false !== $content && preg_match( '/Options\s+-?Indexes/i', $content ) ) {
                $protected = true;
            }
        }

        if ( $protected ) {
            return $this->build_result(
                'directory_browsing',
                __( 'Directory Browsing Protection', 'bbh-security-insight' ),
                self::RISK_SAFE,
                __( 'Directory browsing appears to be disabled via your .htaccess configuration. This prevents visitors from seeing the contents of directories that don&rsquo;t have an index file.', 'bbh-security-insight' ),
                __( 'No action needed.', 'bbh-security-insight' ),
                __( 'Protected', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'directory_browsing',
            __( 'Directory Browsing Protection', 'bbh-security-insight' ),
            self::RISK_WARNING,
            __( 'Directory browsing may be enabled. Visitors could see the contents of directories that do not have an index file, potentially exposing sensitive files.', 'bbh-security-insight' ),
            __( 'Add <code>Options -Indexes</code> to your .htaccess file in the WordPress root directory. Alternatively, ask your hosting provider to disable directory listing at the server level.', 'bbh-security-insight' ),
            __( 'Not confirmed protected', 'bbh-security-insight' )
        );
    }

    /**
     * 7. Check readme.html exposure.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_readme_html() {
        $readme_path = ABSPATH . 'readme.html';

        if ( file_exists( $readme_path ) ) {
            return $this->build_result(
                'readme_html',
                __( 'readme.html Exposure', 'bbh-security-insight' ),
                self::RISK_CRITICAL,
                __( 'The readme.html file exists in your WordPress root directory. This file typically contains your WordPress version number and installation instructions, providing attackers with valuable reconnaissance information.', 'bbh-security-insight' ),
                __( 'Immediately delete the readme.html file from your WordPress root directory using FTP or your hosting file manager.', 'bbh-security-insight' ),
                __( 'Present', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'readme_html',
            __( 'readme.html Exposure', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'The readme.html file is not present in your WordPress root directory.', 'bbh-security-insight' ),
            __( 'No action needed.', 'bbh-security-insight' ),
            __( 'Not present', 'bbh-security-insight' )
        );
    }

    /**
     * 8. Check install.php exposure.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_install_php() {
        $install_path = ABSPATH . 'wp-admin/install.php';

        if ( file_exists( $install_path ) && is_readable( $install_path ) ) {
            return $this->build_result(
                'install_php',
                __( 'install.php Exposure', 'bbh-security-insight' ),
                self::RISK_WARNING,
                __( 'The wp-admin/install.php file exists. While WordPress typically redirects to the login page if the site is already installed, its presence can still be a potential attack vector in certain configurations.', 'bbh-security-insight' ),
                __( 'Ensure your wp-config.php file has proper security constants defined. Consider restricting access to wp-admin/install.php via .htaccess rules.', 'bbh-security-insight' ),
                __( 'Present', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'install_php',
            __( 'install.php Exposure', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'The install.php file is not accessible or does not exist.', 'bbh-security-insight' ),
            __( 'No action needed.', 'bbh-security-insight' ),
            __( 'Not accessible', 'bbh-security-insight' )
        );
    }

    /**
     * 9. Check wp-config.php file permissions.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_wp_config_permissions() {
        $config_path = ABSPATH . 'wp-config.php';

        if ( ! file_exists( $config_path ) ) {
            $config_path = dirname( ABSPATH ) . '/wp-config.php';
        }

        if ( file_exists( $config_path ) ) {
            $perms = fileperms( $config_path );
            if ( false !== $perms ) {
                $perm_string = substr( sprintf( '%o', $perms ), -4 );
                $perm_int    = (int) $perm_string;

                if ( $perm_int > 644 ) {
                    return $this->build_result(
                        'wp_config_permissions',
                        __( 'wp-config.php File Permissions', 'bbh-security-insight' ),
                        self::RISK_CRITICAL,
                        sprintf(
                        /* translators: %s: current permission value */
                            __( 'Your wp-config.php file has permissions set to %s, which is more permissive than the recommended 644 or 600. This could allow other users on the server to read your database credentials and security keys.', 'bbh-security-insight' ),
                            $perm_string
                        ),
                        __( 'Change the wp-config.php file permissions to 644 or 600 using your FTP client or hosting file manager. This restricts read access to the file owner.', 'bbh-security-insight' ),
                        $perm_string
                    );
                }

                return $this->build_result(
                    'wp_config_permissions',
                    __( 'wp-config.php File Permissions', 'bbh-security-insight' ),
                    self::RISK_SAFE,
                    sprintf(
                    /* translators: %s: current permission value */
                        __( 'Your wp-config.php file has secure permissions set to %s.', 'bbh-security-insight' ),
                        $perm_string
                    ),
                    __( 'No action needed. Maintain these restrictive permissions.', 'bbh-security-insight' ),
                    $perm_string
                );
            }

            return $this->build_result(
                'wp_config_permissions',
                __( 'wp-config.php File Permissions', 'bbh-security-insight' ),
                self::RISK_WARNING,
                __( 'Unable to determine the file permissions of wp-config.php. The file exists but permissions could not be read.', 'bbh-security-insight' ),
                __( 'Manually verify that wp-config.php has permissions of 644 or less.', 'bbh-security-insight' ),
                __( 'Unknown', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'wp_config_permissions',
            __( 'wp-config.php File Permissions', 'bbh-security-insight' ),
            self::RISK_CRITICAL,
            __( 'The wp-config.php file could not be found in the expected locations.', 'bbh-security-insight' ),
            __( 'Ensure your wp-config.php file exists in the WordPress root directory with proper permissions.', 'bbh-security-insight' ),
            __( 'Not found', 'bbh-security-insight' )
        );
    }

    /**
     * 10. Check wp-content directory permissions.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_wp_content_permissions() {
        $content_dir = WP_CONTENT_DIR;

        if ( is_dir( $content_dir ) ) {
            $perms = fileperms( $content_dir );
            if ( false !== $perms ) {
                $perm_string = substr( sprintf( '%o', $perms ), -4 );
                $perm_int    = (int) $perm_string;

                if ( $perm_int > 755 ) {
                    return $this->build_result(
                        'wp_content_permissions',
                        __( 'wp-content Directory Permissions', 'bbh-security-insight' ),
                        self::RISK_WARNING,
                        sprintf(
                        /* translators: %s: current permission value */
                            __( 'Your wp-content directory has permissions set to %s, which is more permissive than the recommended 755. This could allow unauthorized users to read or modify your content.', 'bbh-security-insight' ),
                            $perm_string
                        ),
                        __( 'Change the wp-content directory permissions to 755 using your FTP client or hosting file manager.', 'bbh-security-insight' ),
                        $perm_string
                    );
                }

                return $this->build_result(
                    'wp_content_permissions',
                    __( 'wp-content Directory Permissions', 'bbh-security-insight' ),
                    self::RISK_SAFE,
                    sprintf(
                    /* translators: %s: current permission value */
                        __( 'Your wp-content directory has secure permissions set to %s.', 'bbh-security-insight' ),
                        $perm_string
                    ),
                    __( 'No action needed.', 'bbh-security-insight' ),
                    $perm_string
                );
            }

            return $this->build_result(
                'wp_content_permissions',
                __( 'wp-content Directory Permissions', 'bbh-security-insight' ),
                self::RISK_WARNING,
                __( 'Unable to determine the permissions of the wp-content directory.', 'bbh-security-insight' ),
                __( 'Manually verify that wp-content has permissions of 755 or less.', 'bbh-security-insight' ),
                __( 'Unknown', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'wp_content_permissions',
            __( 'wp-content Directory Permissions', 'bbh-security-insight' ),
            self::RISK_WARNING,
            __( 'The wp-content directory could not be found at the expected location.', 'bbh-security-insight' ),
            __( 'Ensure your WordPress installation has a valid wp-content directory.', 'bbh-security-insight' ),
            __( 'Not found', 'bbh-security-insight' )
        );
    }

    /**
     * 11. Check user enumeration exposure.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_user_enumeration() {
        $rest_url = rest_url( 'wp/v2/users/' );
        $response = wp_remote_get( $rest_url, array( 'timeout' => 5 ) );

        if ( is_wp_error( $response ) ) {
            return $this->build_result(
                'user_enumeration',
                __( 'User Enumeration Exposure', 'bbh-security-insight' ),
                self::RISK_WARNING,
                __( 'Unable to verify user enumeration protection. The REST API endpoint could not be reached for testing.', 'bbh-security-insight' ),
                __( 'Manually verify that your site restricts access to <code>/wp-json/wp/v2/users/</code>. Consider using a security plugin to block user enumeration.', 'bbh-security-insight' ),
                __( 'Unable to verify', 'bbh-security-insight' )
            );
        }

        $status_code = wp_remote_retrieve_response_code( $response );

        if ( 200 === $status_code ) {
            $body = wp_remote_retrieve_body( $response );
            $users = json_decode( $body, true );

            if ( is_array( $users ) && count( $users ) > 0 ) {
                return $this->build_result(
                    'user_enumeration',
                    __( 'User Enumeration Exposure', 'bbh-security-insight' ),
                    self::RISK_CRITICAL,
                    __( 'Your site exposes a list of users via the WordPress REST API. Attackers can enumerate registered usernames to perform targeted brute-force attacks. By default, WordPress exposes user data through <code>/wp-json/wp/v2/users/</code>.', 'bbh-security-insight' ),
                    __( 'Restrict access to the WordPress REST API users endpoint using a security plugin or by adding custom code to your theme&rsquo;s functions.php. Consider using a plugin that blocks user enumeration while preserving legitimate REST API functionality.', 'bbh-security-insight' ),
                    /* translators: %d: number of exposed users */
                    sprintf( __( 'Exposed (%d users)', 'bbh-security-insight' ), count( $users ) )
                );
            }
        }

        return $this->build_result(
            'user_enumeration',
            __( 'User Enumeration Exposure', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'Your site appears to protect against user enumeration via the REST API. The users endpoint does not publicly expose user data.', 'bbh-security-insight' ),
            __( 'No action needed.', 'bbh-security-insight' ),
            __( 'Protected', 'bbh-security-insight' )
        );
    }

    /**
     * 12. Check security headers.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_security_headers() {
        $home_url = home_url( '/' );
        $response = wp_remote_get( $home_url, array( 'timeout' => 5 ) );

        if ( is_wp_error( $response ) ) {
            return $this->build_result(
                'security_headers',
                __( 'Security Headers', 'bbh-security-insight' ),
                self::RISK_WARNING,
                __( 'Unable to check security headers. The home page could not be reached.', 'bbh-security-insight' ),
                __( 'Ensure your site is accessible and try again.', 'bbh-security-insight' ),
                __( 'Unable to check', 'bbh-security-insight' )
            );
        }

        $headers = wp_remote_retrieve_headers( $response );
        $headers = is_object( $headers ) ? $headers->getAll() : (array) $headers;

        $header_checks = array(
            'Content-Security-Policy' => array(
                'label' => __( 'CSP (Content Security Policy)', 'bbh-security-insight' ),
                'found' => false,
            ),
            'Strict-Transport-Security' => array(
                'label' => __( 'HSTS (HTTP Strict Transport Security)', 'bbh-security-insight' ),
                'found' => false,
            ),
            'X-Frame-Options' => array(
                'label' => __( 'X-Frame-Options', 'bbh-security-insight' ),
                'found' => false,
            ),
            'Referrer-Policy' => array(
                'label' => __( 'Referrer-Policy', 'bbh-security-insight' ),
                'found' => false,
            ),
            'Permissions-Policy' => array(
                'label' => __( 'Permissions-Policy', 'bbh-security-insight' ),
                'found' => false,
            ),
            'X-Content-Type-Options' => array(
                'label' => __( 'X-Content-Type-Options', 'bbh-security-insight' ),
                'found' => false,
            ),
        );

        $headers_lower = array_change_key_case( $headers, CASE_LOWER );

        foreach ( $header_checks as $header_name => $data ) {
            $lower_name = strtolower( $header_name );
            if ( isset( $headers_lower[ $lower_name ] ) ) {
                $header_checks[ $header_name ]['found'] = true;
            }
        }

        $found_count = 0;
        $missing = array();
        foreach ( $header_checks as $header_name => $data ) {
            if ( $data['found'] ) {
                ++$found_count;
            } else {
                $missing[] = $data['label'];
            }
        }

        $total = count( $header_checks );

        if ( $found_count === $total ) {
            return $this->build_result(
                'security_headers',
                __( 'Security Headers', 'bbh-security-insight' ),
                self::RISK_SAFE,
                __( 'All recommended security headers are present on your site. This provides protection against common web vulnerabilities including clickjacking, MIME sniffing, and XSS attacks.', 'bbh-security-insight' ),
                __( 'No action needed. Periodically review your security headers to ensure they remain properly configured.', 'bbh-security-insight' ),
                /* translators: %d: number of headers found, %d: total headers checked */
                sprintf( __( '%1$d of %2$d headers present', 'bbh-security-insight' ), $found_count, $total )
            );
        }

        if ( $found_count >= 3 ) {
            return $this->build_result(
                'security_headers',
                __( 'Security Headers', 'bbh-security-insight' ),
                self::RISK_WARNING,
                sprintf(
                    /* translators: %1$d: number of headers found, %2$d: total headers, %3$s: list of missing headers */                
                    __( 'Some security headers are missing from your site. Present: %1$d of %2$d. Missing: %3$s.', 'bbh-security-insight' ),
                    $found_count,
                    $total,
                    implode( ', ', $missing )
                ),
                __( 'Add the missing security headers via your server configuration (.htaccess, nginx.conf) or using a security plugin. These headers help protect against clickjacking, XSS, and other attacks.', 'bbh-security-insight' ),
                /* translators: %d: number of headers found, %d: total headers checked */
                sprintf( __( '%1$d of %2$d headers present', 'bbh-security-insight' ), $found_count, $total )
            );
        }

        return $this->build_result(
            'security_headers',
            __( 'Security Headers', 'bbh-security-insight' ),
            self::RISK_CRITICAL,
            sprintf(
                /* translators: %1$d: number of headers found, %2$d: total headers, %3$s: list of missing headers */
                __( 'Most security headers are missing from your site. Present: %1$d of %2$d. Missing: %3$s. This leaves your site vulnerable to clickjacking, MIME sniffing, XSS, and other common attacks.', 'bbh-security-insight' ),
                $found_count,
                $total,
                implode( ', ', $missing )
            ),
            __( 'Immediately add security headers via your server configuration or a security plugin. Prioritize X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security.', 'bbh-security-insight' ),
            /* translators: %d: number of headers found, %d: total headers checked */
            sprintf( __( '%1$d of %2$d headers present', 'bbh-security-insight' ), $found_count, $total )
        );
    }

    /**
     * 13. Check uploads directory PHP execution protection.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_uploads_php_execution() {
        $upload_dir = wp_upload_dir();
        $base_dir   = $upload_dir['basedir'];
        $htaccess   = $base_dir . '/.htaccess';

        $protected = false;

        if ( file_exists( $htaccess ) && is_readable( $htaccess ) ) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            $content = file_get_contents( $htaccess );
            if ( false !== $content && ( preg_match( '/php/ i', $content ) || preg_match( '/deny from all/i', $content ) ) ) {
                $protected = true;
            }
        }

        if ( $protected ) {
            return $this->build_result(
                'uploads_php_execution',
                __( 'Uploads Directory PHP Execution', 'bbh-security-insight' ),
                self::RISK_SAFE,
                __( 'Your uploads directory appears to have rules that prevent PHP file execution. This is an important security measure that blocks attackers from executing malicious PHP files uploaded through file uploads.', 'bbh-security-insight' ),
                __( 'No action needed.', 'bbh-security-insight' ),
                __( 'Protected', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'uploads_php_execution',
            __( 'Uploads Directory PHP Execution', 'bbh-security-insight' ),
            self::RISK_WARNING,
            __( 'Your uploads directory may allow PHP file execution. If an attacker uploads a malicious PHP file (e.g., through a file upload vulnerability), they could execute code on your server.', 'bbh-security-insight' ),
            __( 'Add an .htaccess file to your wp-content/uploads directory with rules to block PHP execution. Common approaches include <code>deny from all</code> or <code>&lt;Files *.php&gt;deny from all&lt;/Files&gt;</code>.', 'bbh-security-insight' ),
            __( 'Not confirmed protected', 'bbh-security-insight' )
        );
    }

    /**
     * 14. Check if an admin user has the username "admin".
     *
     * @since 1.0.0
     * @return array
     */
    private function check_admin_username() {
        $admin_user = get_users(
            array(
                'login'   => 'admin',
                'role'    => 'administrator',
                'number'  => 1,
            )
        );

        if ( ! empty( $admin_user ) ) {
            return $this->build_result(
                'admin_username',
                __( 'Admin Username Check', 'bbh-security-insight' ),
                self::RISK_CRITICAL,
                __( 'An administrator account exists with the username &ldquo;admin&rdquo;. This is the most commonly targeted username in brute-force attacks, as attackers will try &ldquo;admin&rdquo; first in credential stuffing attempts.', 'bbh-security-insight' ),
                __( 'Create a new administrator account with a unique username, log into it, then delete the &ldquo;admin&rdquo; account. Alternatively, use a security plugin to rename the &ldquo;admin&rdquo; username.', 'bbh-security-insight' ),
                __( 'Exists', 'bbh-security-insight' )
            );
        }

        return $this->build_result(
            'admin_username',
            __( 'Admin Username Check', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'No administrator account uses the default &ldquo;admin&rdquo; username. This reduces the risk of targeted brute-force attacks.', 'bbh-security-insight' ),
            __( 'No action needed. Ensure all user accounts use unique, non-obvious usernames.', 'bbh-security-insight' ),
            __( 'Not found', 'bbh-security-insight' )
        );
    }

    /**
     * 15. Malware heuristics scan — context-aware suspicious pattern detection.
     *
     * Uses behavioral evidence, execution chain analysis, entropy evaluation,
     * and trusted-plugin whitelisting to dramatically reduce false positives.
     * Individual functions like base64_decode or preg_replace are NOT treated
     * as standalone malware signals — they require corroborating context.
     *
     * Confidence: None (no evidence), Low (minor, likely FP),
     * Medium (needs manual review), High (strong multi-factor evidence).
     *
     * Does NOT modify any files. Only reads file contents.
     *
     * @since 1.0.0
     * @return array
     */
    private function check_malware_heuristics() {
        $patterns = $this->get_malware_patterns();
        $trusted  = $this->get_trusted_plugin_slugs();
        $scan     = $this->scan_directories_for_malware( $patterns, $trusted );

        if ( empty( $scan['findings'] ) ) {
            return $this->malware_clean_result();
        }

        $classified = $this->classify_files( $scan, $trusted );
        $verdict    = $this->resolve_overall_verdict( $classified );
        $risk       = $this->verdict_to_risk( $verdict );
        $evidence   = $this->build_evidence_panel( $classified );

        $result = $this->build_result(
            'malware_heuristics',
            __( 'Malware Heuristics Scan', 'bbh-security-insight' ),
            $risk,
            $this->build_malware_description( $verdict, $evidence ),
            $this->build_malware_recommendation( $verdict ),
            $this->build_malware_current_value( $verdict, $classified )
        );

        $result['verdict']            = $verdict;
        $result['needs_manual_review'] = ( 'suspicious' === $verdict );
        $result['evidence']           = $evidence;
        $result['disclaimer']         = __( 'Heuristic results are not a guarantee of infection. False positives and false negatives are possible. Always verify findings manually or consult a security professional.', 'bbh-security-insight' );

        return $result;
    }

    /**
     * Get the pattern library for malware detection.
     *
     * Tiers: 5=malicious chain, 3–4=suspicious, 1–2=low-severity/contextual.
     * Low-severity patterns require corroborating evidence to affect confidence.
     *
     * @since 1.2.0
     * @return array
     */
    private function get_malware_patterns() {
        return array(
            'eval_decode_chain' => array(
                'pattern' => '/eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|\\$[a-z_]+)\s*\(/i',
                'weight'  => 5,
                'tier'    => 5,
                'label'   => 'eval( decode() ) execution chain',
            ),
            'gzinflate_base64_chain' => array(
                'pattern' => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
                'weight'  => 5,
                'tier'    => 5,
                'label'   => 'gzinflate( base64_decode() ) obfuscation chain',
            ),
            'remote_include' => array(
                'pattern' => '/(?:include|require)(?:_once)?\s*\(\s*[\'\"](?:https?|ftp):\/\//i',
                'weight'  => 5,
                'tier'    => 5,
                'label'   => 'Remote file include (RFI)',
            ),
            'preg_replace_e' => array(
                'pattern' => '/preg_replace\s*\([^)]*\/[eemsU]+/i',
                'weight'  => 2,
                'tier'    => 3,
                'label'   => 'preg_replace() with /e modifier (legacy, deprecated)',
            ),
            'hidden_iframe' => array(
                'pattern' => '/<iframe[^>]*(?:height\s*=\s*["\']?[01]["\']?|width\s*=\s*["\']?[01]["\']?|style\s*=\s*["\']display\s*:\s*none)/i',
                'weight'  => 2,
                'tier'    => 3,
                'label'   => 'Hidden / zero-size iframe reference',
            ),
            'eval_variable' => array(
                'pattern' => '/\beval\s*\(\s*(?!base64_decode|gzinflate|gzuncompress|str_rot13)(?:\\$|[\'\"])/i',
                'weight'  => 4,
                'tier'    => 4,
                'label'   => 'eval() with variable or dynamic input',
            ),
            'system_exec' => array(
                'pattern' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i',
                'weight'  => 4,
                'tier'    => 4,
                'label'   => 'System command execution function',
            ),
            'assert_dynamic' => array(
                'pattern' => '/assert\s*\(\s*\\$/i',
                'weight'  => 3,
                'tier'    => 3,
                'label'   => 'assert() with variable argument',
            ),
            'create_function' => array(
                'pattern' => '/create_function\s*\(/i',
                'weight'  => 3,
                'tier'    => 3,
                'label'   => 'create_function() (deprecated, injection risk)',
            ),
            'var_var_superglobal' => array(
                'pattern' => '/\$\$\s*\{?\s*\$?(?:_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV))/i',
                'weight'  => 3,
                'tier'    => 3,
                'label'   => 'Variable variable from superglobal ($_POST/$_GET etc.)',
            ),
            'document_write_script' => array(
                'pattern' => '/document\s*\.\s*write\s*\(\s*[\'\"][^)]{0,30}<\s*script/i',
                'weight'  => 1,
                'tier'    => 2,
                'label'   => 'document.write() with inline script tag',
            ),
            'chr_concat_sequence' => array(
                'pattern' => '/chr\s*\(\s*\d{2,}\s*\)\s*\.\s*(?:chr\s*\(|\\$)/i',
                'weight'  => 2,
                'tier'    => 2,
                'label'   => 'chr() concatenation (obfuscation pattern)',
            ),
            'eval_literal' => array(
                'pattern' => '/\beval\s*\(\s*[\'\"][^\'\"]+[\'\"]\s*\)/i',
                'weight'  => 1,
                'tier'    => 1,
                'label'   => 'eval() with string literal (low risk)',
            ),
            'base64_decode' => array(
                'pattern' => '/base64_decode\s*\(/i',
                'weight'  => 2,
                'tier'    => 2,
                'label'   => 'base64_decode() usage',
            ),
            'preg_replace' => array(
                'pattern' => '/preg_replace\s*\(/i',
                'weight'  => 1,
                'tier'    => 1,
                'label'   => 'preg_replace() usage',
            ),
            'call_user_func' => array(
                'pattern' => '/call_user_func(?:_array)?\s*\(/i',
                'weight'  => 1,
                'tier'    => 1,
                'label'   => 'call_user_func*() usage',
            ),
            'str_rot13' => array(
                'pattern' => '/str_rot13\s*\(/i',
                'weight'  => 1,
                'tier'    => 1,
                'label'   => 'str_rot13() usage',
            ),
            'atob_js' => array(
                'pattern' => '/atob\s*\(/i',
                'weight'  => 1,
                'tier'    => 1,
                'label'   => 'JS atob() base64 decode',
            ),
        );
    }

    /**
     * Known-legitimate plugin slugs that receive automatic confidence reduction.
     *
     * @since 1.2.0
     * @return string[]
     */
    private function get_trusted_plugin_slugs() {
        return array(
            'bbh-custom-schema',
            'bbh-security-insight',
            'wordfence',
            'woocommerce',
            'plugin-check',
            'wordpress-importer',
            'akismet',
            'wordpress-seo',
            'jetpack',
            'elementor',
            'contact-form-7',
            'classic-editor',
            'really-simple-ssl',
            'updraftplus',
            'litespeed-cache',
            'w3-total-cache',
            'wp-super-cache',
            'wp-fastest-cache',
            'redux-framework',
            'advanced-custom-fields',
            'custom-post-type-ui',
            'sg-security',
            'all-in-one-wp-migration',
            'duplicator',
            'google-sitemap-generator',
            'mailchimp-for-wp',
            'wp-mail-smtp',
            'easy-wp-smtp',
            'better-wp-security',
            'limit-login-attempts-reloaded',
            'wp-rocket',
            'imagify',
            'shortpixel-image-optimiser',
            'webp-express',
            'regenerate-thumbnails',
            'safe-svg',
            'svg-support',
            'code-snippets',
            'query-monitor',
            'wp-crontrol',
            'fakerpress',
            'wp-multibyte-patch',
            'redis-cache',
            'nginx-helper',
            'ewww-image-optimizer',
            'autoptimize',
            'wp-optimize',
            'child-theme-configurator',
            'disable-comments',
            'post-types-order',
            'intuitive-custom-post-order',
            'admin-menu-editor',
            'user-role-editor',
            'members',
            'tinymce-advanced',
            'block-manager',
            'favicon-by-realfavicongenerator',
            'pdf-embedder',
            'download-manager',
        );
    }

    /**
     * Get directories to scan, excluding this plugin itself.
     *
     * @since 1.0.0
     * @return string[]
     */
    private function get_scan_directories() {
        $dirs        = array();
        $plugin_base = BBHSECINS_PLUGIN_PATH;

        $active_plugins = get_option( 'active_plugins', array() );
        foreach ( $active_plugins as $plugin_path ) {
            $parts = explode( '/', $plugin_path );
            if ( ! empty( $parts[0] ) ) {
                $plugin_dir = WP_PLUGIN_DIR . '/' . $parts[0];
                if ( is_dir( $plugin_dir ) ) {
                    $normalized_plugin = wp_normalize_path( $plugin_dir );
                    $normalized_base   = wp_normalize_path( rtrim( $plugin_base, '/' ) );
                    if ( $normalized_plugin !== $normalized_base ) {
                        $dirs[ $plugin_dir ] = true;
                    }
                }
            }
        }

        if ( function_exists( 'wp_get_theme' ) ) {
            $theme = wp_get_theme();
            $theme_dir = $theme->get_stylesheet_directory();
            if ( is_dir( $theme_dir ) ) {
                $dirs[ $theme_dir ] = true;
            }

            $parent_theme = $theme->parent();
            if ( $parent_theme ) {
                $parent_dir = $parent_theme->get_stylesheet_directory();
                if ( is_dir( $parent_dir ) ) {
                    $dirs[ $parent_dir ] = true;
                }
            }
        }

        return array_keys( $dirs );
    }

    /**
     * Check if a file path should be excluded from scanning.
     *
     * @since 1.1.0
     * @param string $file_path Absolute file path.
     * @return bool
     */
    private function is_excluded_file( $file_path ) {
        $excluded = array( '/vendor/', '/node_modules/', '/bower_components/', '/composer/' );
        foreach ( $excluded as $pattern ) {
            if ( false !== strpos( $file_path, $pattern ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if a file is minified and should be skipped.
     *
     * @since 1.1.0
     * @param string $file_path Absolute file path.
     * @return bool
     */
    private function is_minified_file( $file_path ) {
        return false !== strpos( $file_path, '.min.' );
    }

    /**
     * Extract the plugin slug from an absolute directory path.
     *
     * @since 1.2.0
     * @param string $dir_path Absolute directory path (e.g. /wp-content/plugins/woocommerce).
     * @return string The directory basename.
     */
    private function get_dir_slug( $dir_path ) {
        return basename( rtrim( $dir_path, '/' ) );
    }

    /**
     * Scan all eligible directories for suspicious code patterns.
     *
     * @since 1.2.0
     * @param array $patterns Pattern definitions.
     * @param array $trusted  Trusted plugin slug list.
     * @return array{findings: array, total_raw_weight: int, total_adjusted_weight: int, has_high_severity_chains: bool, needs_review: bool, trusted_found: array}
     */
    private function scan_directories_for_malware( array $patterns, array $trusted ) {
        $directories = $this->get_scan_directories();
        $findings    = array();
        $raw_weight  = 0;
        $has_high    = false;
        $trusted_found = array();
        $max_files   = apply_filters( 'bbhsecins_max_scan_files', 100 );

        foreach ( $directories as $dir ) {
            if ( ! is_dir( $dir ) ) {
                continue;
            }

            $slug        = $this->get_dir_slug( $dir );
            $is_trusted  = in_array( $slug, $trusted, true );
            $file_count  = 0;

            try {
                $iterator = new \RecursiveIteratorIterator(
                    new \RecursiveDirectoryIterator( $dir, \RecursiveDirectoryIterator::SKIP_DOTS ),
                    \RecursiveIteratorIterator::SELF_FIRST
                );
            } catch ( \Exception $e ) {
                continue;
            }

            foreach ( $iterator as $file ) {
                if ( $file_count >= $max_files ) {
                    break;
                }
                if ( ! $file->isFile() ) {
                    continue;
                }
                if ( 'php' !== strtolower( $file->getExtension() ) ) {
                    continue;
                }
                if ( $file->getSize() > 500000 ) {
                    continue;
                }

                $real = $file->getRealPath();
                if ( $this->is_excluded_file( $real ) || $this->is_minified_file( $real ) ) {
                    continue;
                }

                ++$file_count;

                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
                if ( ! is_readable( $real ) ) {
                    continue;
                }

                $content = file_get_contents( $real );

                if ( false === $content || '' === trim( $content ) ) {
                    continue;
                }

                $result = $this->analyze_single_file( $content, $patterns );

                if ( $result['raw_weight'] > 0 ) {
                    $relative = ltrim(
                        str_replace(
                            wp_normalize_path( trailingslashit( WP_CONTENT_DIR ) ),
                            '',
                            wp_normalize_path( $real )
                        ),
                        '/'
                    );
                    $file_entry   = array_merge(
                        array(
                            'file'       => $relative,
                            'slug'       => $slug,
                            'is_trusted' => $is_trusted,
                        ),
                        $result
                    );
                    $findings[]   = $file_entry;
                    $raw_weight  += $result['raw_weight'];

                    if ( $result['has_tier5'] ) {
                        $has_high = true;
                    }
                }

                if ( $is_trusted ) {
                    $trusted_found[ $slug ] = true;
                }

                unset( $content );
            }
        }

        return array(
            'findings'           => $findings,
            'total_raw_weight'   => $raw_weight,
            'total_adjusted_weight' => $raw_weight,
            'has_high_severity_chains' => $has_high,
            'needs_review'       => false,
            'trusted_found'      => array_keys( $trusted_found ),
        );
    }

    /**
     * Analyze a single file's content against the pattern library.
     *
     * Returns raw matches without trusted-plugin or context adjustments,
     * plus context observations used for downstream scoring.
     *
     * @since 1.2.0
     * @param string $content  File source code.
     * @param array  $patterns Pattern definitions.
     * @return array{raw_weight: int, has_tier5: bool, matches: array, context: array}
     */
    private function analyze_single_file( $content, array $patterns ) {
        $total_lines = substr_count( $content, "\n" ) + 1;
        $total_bytes = strlen( $content );
        $raw_weight  = 0;
        $has_tier5   = false;
        $matches     = array();
        $dang_lines  = array();

        foreach ( $patterns as $key => $info ) {
            $count = preg_match_all( $info['pattern'], $content, $preg_matches, PREG_OFFSET_CAPTURE );

            if ( $count > 0 ) {
                $weight     = $info['weight'];
                $raw_weight += $weight * min( $count, 3 );
                $matches[ $info['label'] ] = $count;

                if ( 5 === $info['tier'] ) {
                    $has_tier5 = true;
                }

                foreach ( $preg_matches[0] as $pm ) {
                    $line_num = substr_count( substr( $content, 0, $pm[1] ), "\n" ) + 1;
                    $dang_lines[] = $line_num;
                }
            }
        }

        $context = $this->analyze_file_context( $content, $dang_lines, $total_lines, $total_bytes );

        return array(
            'raw_weight'  => $raw_weight,
            'has_tier5'   => $has_tier5,
            'matches'     => $matches,
            'context'     => $context,
            'dang_lines'  => $dang_lines,
        );
    }

    /**
     * Analyze file context around dangerous-line positions.
     *
     * @since 1.2.0
     * @param string $content     File source.
     * @param int[]  $dang_lines  Line numbers with pattern matches.
     * @param int    $total_lines Total lines in file.
     * @param int    $total_bytes Total bytes in file.
     * @return array{try_catch_wrapped: bool, has_superglobal_input: bool, proximity_count: int, has_encoded_payload: bool, entropy_score: float, notes: string[]}
     */
    private function analyze_file_context( $content, array $dang_lines, $total_lines, $total_bytes ) {
        $notes = array();
        $lines = explode( "\n", $content );

        $try_wrapped    = false;
        $superglobal_in = false;
        $prox_count     = 0;

        if ( ! empty( $dang_lines ) ) {
            foreach ( $dang_lines as $ln ) {
                $idx = $ln - 1;
                if ( isset( $lines[ $idx ] ) ) {
                    $line = $lines[ $idx ];

                    if ( preg_match( '/\$(?:_(?:POST|GET|REQUEST|COOKIE|SERVER|FILES|ENV)|wpdb|wp_query)/i', $line ) ) {
                        $superglobal_in = true;
                    }

                    for ( $check = max( 0, $idx - 4 ); $check < $idx; $check++ ) {
                        if ( isset( $lines[ $check ] ) && false !== strpos( $lines[ $check ], 'try' ) ) {
                            $try_wrapped = true;
                            break;
                        }
                    }
                }
            }

            if ( count( $dang_lines ) >= 2 ) {
                $sorted = array_unique( $dang_lines );
                sort( $sorted );
                for ( $i = 1; $i < count( $sorted ); $i++ ) {
                    if ( ( $sorted[ $i ] - $sorted[ $i - 1 ] ) <= 8 ) {
                        ++$prox_count;
                    }
                }
            }
        }

        $long_encoded = preg_match_all( '/[\'"][A-Za-z0-9+\/=]{80,}[\'"]/', $content, $enc_matches );
        $has_encoded  = $long_encoded > 0;

        $entropy = $this->calculate_entropy( $content );

        if ( $has_encoded ) {
            $ratio = ( $long_encoded * 80 ) / max( $total_bytes, 1 );
            if ( $ratio > 0.15 ) {
                $notes[] = __( 'High-density encoded string payload', 'bbh-security-insight' );
            }
        }

        if ( $try_wrapped ) {
            $notes[] = __( 'Dangerous call inside try block', 'bbh-security-insight' );
        }
        if ( $superglobal_in ) {
            $notes[] = __( 'Superglobal input used nearby', 'bbh-security-insight' );
        }
        if ( $prox_count > 0 ) {
            $notes[] = __( 'Multiple dangerous calls in close proximity', 'bbh-security-insight' );
        }

        return array(
            'try_catch_wrapped'  => $try_wrapped,
            'has_superglobal_input' => $superglobal_in,
            'proximity_count'    => $prox_count,
            'has_encoded_payload' => $has_encoded,
            'entropy_score'      => $entropy,
            'notes'              => $notes,
        );
    }

    /**
     * Calculate the Shannon entropy of a string as an obfuscation indicator.
     *
     * @since 1.2.0
     * @param string $data Input text.
     * @return float Entropy score (typically 0–8 for text).
     */
    private function calculate_entropy( $data ) {
        $len   = strlen( $data );
        if ( 0 === $len ) {
            return 0.0;
        }

        $freq  = array();
        for ( $i = 0; $i < $len; $i++ ) {
            $byte = $data[ $i ];
            if ( ! isset( $freq[ $byte ] ) ) {
                $freq[ $byte ] = 0;
            }
            ++$freq[ $byte ];
        }

        $entropy = 0.0;
        foreach ( $freq as $count ) {
            $p = $count / $len;
            $entropy -= $p * log( $p, 2 );
        }

        return $entropy;
    }

    /**
     * Apply trusted-plugin multipliers and context-aware score reductions.
     *
     * @since 1.2.0
     * @param array $scan    Raw scan result from scan_directories_for_malware().
     * @param array $trusted List of trusted plugin slugs.
     * @return array Adjusted scan result with reductions and explanations.
     */
    /**
     * Classify each file independently using strict evidence-based rules.
     *
     * No global aggregation — risk is computed per file. Tier-1/2 patterns
     * (base64_decode, preg_replace, call_user_func, etc.) NEVER trigger
     * a finding on their own. Only execution chains, obfuscation density,
     * hidden injections, or multi-factor tier-3+ evidence can produce
     * a Suspicious or High Risk verdict.
     *
     * @since 1.3.0
     * @param array $scan    Raw scan result from scan_directories_for_malware().
     * @param array $trusted List of trusted plugin slugs.
     * @return array{findings: array, verdict_counts: array, overall_verdict: string}
     */
    private function classify_files( array $scan, array $trusted ) {
        $classified      = array();
        $verdict_counts  = array( 'benign' => 0, 'suspicious' => 0, 'high_risk' => 0 );

        foreach ( $scan['findings'] as $entry ) {
            $verdict           = $this->classify_single_file( $entry );
            $entry['verdict']  = $verdict;
            $entry['benign_reason'] = '';
            $entry['reductions']    = array();

            if ( 'benign' === $verdict ) {
                $entry['benign_reason'] = $this->get_benign_reason( $entry );
                $entry['reductions'][]  = $entry['benign_reason'];
            }

            $classified[] = $entry;

            if ( isset( $verdict_counts[ $verdict ] ) ) {
                ++$verdict_counts[ $verdict ];
            }
        }

        $overall = 'benign';
        if ( $verdict_counts['high_risk'] > 0 ) {
            $overall = 'high_risk';
        } elseif ( $verdict_counts['suspicious'] > 0 ) {
            $overall = 'suspicious';
        }

        return array(
            'findings'       => $classified,
            'verdict_counts' => $verdict_counts,
            'overall_verdict' => $overall,
        );
    }

    /**
     * Classify a single file using strict evidence-based behavioral analysis.
     *
     * No individual function (preg_replace, base64_decode, DOMDocument, etc.)
     * is ever classified as malware on its own. Confirmed Malware requires
     * execution intent + obfuscation indicators. Suspicious requires a
     * corroborated pattern in non-trusted code without a safe explanation.
     *
     * Rules:
     *   - Tier-5 chains (eval(decode), gzinflate(base64_decode), RFI) → Confirmed Malware
     *   - Tier 4 (eval, system, exec) + obfuscation (encoded payload / high entropy) → Confirmed Malware
     *   - Tier 4 in non-trusted without obfuscation → Suspicious (needs review)
     *   - Tier 3 in non-trusted without safe context → Suspicious
     *   - Tier 1–2 only → ALWAYS Clean (individual safe functions are never malware)
     *   - preg_replace /e modifier → legacy warning only, not malware
     *   - Proximity-only / count-based aggregation → NEVER used for classification
     *
     * @since 1.3.0
     * @param array $entry Single file finding from analyze_single_file().
     * @return string 'benign', 'suspicious', or 'high_risk'.
     */
    private function classify_single_file( array $entry ) {
        $max_tier  = $this->get_file_max_tier( $entry['matches'] );
        $has_tier5 = $entry['has_tier5'];
        $ctx       = $entry['context'];
        $trusted   = $entry['is_trusted'];

        // === CONFIRMED MALWARE: undeniable execution chains ===
        // Tier-5 patterns = execution + obfuscation combined (eval(decode), RFI)
        if ( $has_tier5 && ! $trusted ) {
            return 'high_risk';
        }

        // === CONFIRMED MALWARE: execution intent + obfuscation evidence ===
        // system/exec/eval + encoded payload or high entropy = probable RCE
        if ( $max_tier >= 4 ) {
            $has_obfuscation = $ctx['has_encoded_payload'] || $ctx['entropy_score'] > 5.0;
            if ( $has_obfuscation && ! $trusted ) {
                return 'high_risk';
            }

            // system/exec in non-trusted without obfuscation = needs review
            if ( ! $trusted ) {
                return 'suspicious';
            }
        }

        // === SUSPICIOUS: tier-3 without safe context in non-trusted code ===
        if ( $max_tier >= 3 && ! $trusted && ! $ctx['try_catch_wrapped'] && ! $this->has_benign_intent( $entry ) ) {
            return 'suspicious';
        }

        // === CLEAN: everything below this line is safe ===
        return 'benign';
    }

    /**
     * Determine the highest pattern tier present in a file's matches.
     *
     * @since 1.3.0
     * @param array $matches Associative array of label => count.
     * @return int 0–5 highest tier found.
     */
    private function get_file_max_tier( array $matches ) {
        static $tier_map = null;
        if ( null === $tier_map ) {
            $tier_map = array();
            $patterns = $this->get_malware_patterns();
            foreach ( $patterns as $info ) {
                $tier_map[ $info['label'] ] = $info['tier'];
            }
        }

        $max = 0;
        foreach ( $matches as $label => $count ) {
            if ( isset( $tier_map[ $label ] ) && $tier_map[ $label ] > $max ) {
                $max = $tier_map[ $label ];
            }
        }
        return $max;
    }

    /**
     * Check whether a file exhibits benign developer intent patterns.
     *
     * Recognises schema generators, XML/HTML parsers, JSON formatters,
     * regex utilities, admin/debug tooling, and similar legitimate code.
     *
     * @since 1.3.0
     * @param array $entry File finding data.
     * @return bool True if the code appears to have legitimate intent.
     */
    private function has_benign_intent( array $entry ) {
        $file = $entry['file'];
        $ctx  = $entry['context'];

        if ( $ctx['try_catch_wrapped'] ) {
            return true;
        }

        $patterns = array(
            '/schema|json-ld|structured.data|microdata/i',
            '/xml|html|parser|dom|rss|feed|sitemap|atom/i',
            '/format|utility|helper|template|minif|compress/i',
            '/regex|pattern|validate|sanitize|filter/i',
            '/admin.?bar|debug|query.?monitor|admin.?tool/i',
            '/export|import|csv|tsv|serialize|unserialize/i',
            '/cache|transient|optimize|cleanup/i',
            '/seo|meta.?box|shortcode|widget/i',
            '/rest.?api|endpoint|route|middleware/i',
            '/oauth|auth|token|jwt|signature/i',
            '/cron|schedule|background|async/i',
            '/markdown|bbcode|textile|wysiwyg/i',
            '/color|palette|gradient|typography/i',
            '/animation|transition|keyframe|parallax/i',
        );

        foreach ( $patterns as $re ) {
            if ( preg_match( $re, $file ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return a human-readable explanation for a benign classification.
     *
     * @since 1.3.0
     * @param array $entry File finding data.
     * @return string Explanation text.
     */
    private function get_benign_reason( array $entry ) {
        $max_tier = $this->get_file_max_tier( $entry['matches'] );

        if ( $max_tier <= 2 ) {
            return __( 'Only low-severity patterns (safe functions like base64_decode, preg_replace) — these are common in legitimate WordPress code.', 'bbh-security-insight' );
        }

        if ( $entry['is_trusted'] ) {
            /* translators: %s: plugin slug */
            return sprintf( __( 'Trusted plugin (%s) — known-legitimate source.', 'bbh-security-insight' ), $entry['slug'] );
        }

        if ( $entry['context']['try_catch_wrapped'] ) {
            return __( 'Dangerous calls are try-catch wrapped (intentional error handling).', 'bbh-security-insight' );
        }

        return __( 'Code matches known benign developer patterns (schema, XML, formatting, utilities).', 'bbh-security-insight' );
    }

    /**
     * Find the pattern key in the pattern library by its label string.
     *
     * @since 1.2.0
     * @param string $label The match label to look up.
     * @return string|null The pattern key or null.
     */
    private function find_pattern_key_by_label( $label ) {
        static $map = null;
        if ( null === $map ) {
            $map = array();
            $patterns = $this->get_malware_patterns();
            foreach ( $patterns as $key => $info ) {
                $map[ $info['label'] ] = $key;
            }
        }
        foreach ( $map as $known_label => $key ) {
            if ( $known_label === $label ) {
                return $key;
            }
        }
        return null;
    }

    /**
     * Resolve the overall verdict from per-file classifications.
     *
     * No global weight aggregation — the highest individual file verdict
     * determines the result.
     *
     * @since 1.3.0
     * @param array $classified Output of classify_files().
     * @return string 'clean', 'suspicious', or 'high_risk'.
     */
    private function resolve_overall_verdict( array $classified ) {
        $counts = $classified['verdict_counts'];

        if ( $counts['high_risk'] > 0 ) {
            return 'high_risk';
        }
        if ( $counts['suspicious'] > 0 ) {
            return 'suspicious';
        }
        return 'clean';
    }

    /**
     * Map overall verdict to a risk level constant.
     *
     * @since 1.3.0
     * @param string $verdict 'clean', 'suspicious', or 'high_risk'.
     * @return string Risk level constant.
     */
    private function verdict_to_risk( $verdict ) {
        if ( 'high_risk' === $verdict ) {
            return self::RISK_CRITICAL;
        }
        if ( 'suspicious' === $verdict ) {
            return self::RISK_WARNING;
        }
        return self::RISK_SAFE;
    }

    /**
     * Build the explainable evidence panel from classified findings.
     *
     * Each file shows its verdict, matched rules, context,
     * and the reason for the benign/suspicious/high-risk classification.
     *
     * @since 1.2.0
     * @param array $classified Output of classify_files().
     * @return array
     */
    private function build_evidence_panel( array $classified ) {
        $panel = array();

        foreach ( $classified['findings'] as $entry ) {
            $verdict     = $entry['verdict'];
            $verdict_tag = $this->get_verdict_badge( $verdict );

            $rules_html = '<ul>';
            foreach ( $entry['matches'] as $label => $count ) {
                $rules_html .= sprintf( '<li>%s — matched %d time(s)</li>', esc_html( $label ), $count );
            }
            $rules_html .= '</ul>';

            $context_html = '';
            if ( ! empty( $entry['context']['notes'] ) ) {
                $context_html = '<p><strong>' . esc_html__( 'Context:', 'bbh-security-insight' ) . '</strong></p><ul>';
                foreach ( $entry['context']['notes'] as $note ) {
                    $context_html .= '<li>' . esc_html( $note ) . '</li>';
                }
                $context_html .= '</ul>';
            }

            $reason_html = '';
            if ( 'benign' === $verdict && ! empty( $entry['benign_reason'] ) ) {
                $reason_html = '<p><strong>' . esc_html__( 'Clean classification reason:', 'bbh-security-insight' ) . '</strong> ' . esc_html( $entry['benign_reason'] ) . '</p>';
            }

            $trusted_tag = '';
            if ( $entry['is_trusted'] ) {
                $trusted_tag = ' <span class="bbhsecins-badge bbhsecins-safe">' . esc_html__( 'Trusted Plugin', 'bbh-security-insight' ) . '</span>';
            }

            $panel[] = array(
                'file'       => $entry['file'],
                'slug'       => $entry['slug'],
                'is_trusted' => $entry['is_trusted'],
                'verdict'    => $verdict,
                'rules'      => array_keys( $entry['matches'] ),
                'html'       => sprintf(
                    '<details class="bbhsecins-evidence-details"><summary><strong>%s</strong>%s %s</summary>%s%s%s</details>',
                    esc_html( $entry['file'] ),
                    $trusted_tag,
                    $verdict_tag,
                    $rules_html,
                    $context_html,
                    $reason_html
                ),
            );
        }

        return $panel;
    }

    /**
     * Build an HTML verdict badge for the evidence panel.
     *
     * @since 1.3.0
     * @param string $verdict 'benign', 'suspicious', or 'high_risk'.
     * @return string HTML span.
     */
    private function get_verdict_badge( $verdict ) {
        if ( 'high_risk' === $verdict ) {
            return '<span class="bbhsecins-badge bbhsecins-critical">' . esc_html__( 'Confirmed Malware', 'bbh-security-insight' ) . '</span>';
        }
        if ( 'suspicious' === $verdict ) {
            return '<span class="bbhsecins-badge bbhsecins-warning">' . esc_html__( 'Suspicious', 'bbh-security-insight' ) . '</span>';
        }
        return '<span class="bbhsecins-badge bbhsecins-safe">' . esc_html__( 'Clean', 'bbh-security-insight' ) . '</span>';
    }

    /**
     * Build the human-readable description including inline evidence.
     *
     * @since 1.2.0
     * @param string $verdict  Overall verdict.
     * @param array  $evidence Evidence panel entries.
     * @return string HTML description with embedded evidence panel.
     */
    private function build_malware_description( $verdict, array $evidence ) {
        $file_count = count( $evidence );

        if ( empty( $evidence ) ) {
            return esc_html__( 'No suspicious code patterns were detected in active plugin and theme PHP files. This is a positive sign, though not a guarantee of absolute security.', 'bbh-security-insight' );
        }

        if ( 'high_risk' === $verdict ) {
            $desc = sprintf(
                /* translators: %d: number of files flagged */
                _n(
                    'Confirmed Malware — %d file has execution chains with obfuscation indicators. Probable malicious code detected.',
                    'Confirmed Malware — %d files have execution chains with obfuscation indicators. Probable malicious code detected.',
                    $file_count,
                    'bbh-security-insight'
                ),
                $file_count
            );
        } elseif ( 'suspicious' === $verdict ) {
            $desc = sprintf(
                /* translators: %d: number of files */
                _n(
                    'Suspicious — %d file has execution-adjacent patterns in non-trusted code that warrant manual review. Not conclusive on its own.',
                    'Suspicious — %d files have execution-adjacent patterns in non-trusted code that warrant manual review. Not conclusive on their own.',
                    $file_count,
                    'bbh-security-insight'
                ),
                $file_count
            );
        } else {
            $desc = sprintf(
                /* translators: %d: number of files */
                _n(
                    'Clean — %d file was flagged with low-severity patterns (safe functions) and automatically cleared.',
                    'Clean — %d files were flagged with low-severity patterns (safe functions) and automatically cleared.',
                    $file_count,
                    'bbh-security-insight'
                ),
                $file_count
            );
        }

        $desc .= '<div class="bbhsecins-evidence-container">';
        foreach ( $evidence as $entry ) {
            $desc .= $entry['html'];
        }
        $desc .= '</div>';

        return $desc;
    }

    /**
     * Build the recommendation text based on verdict.
     *
     * @since 1.2.0
     * @param string $verdict Overall verdict.
     * @return string
     */
    private function build_malware_recommendation( $verdict ) {
        $disclaimer = __( 'Heuristic results are not a guarantee of infection. False positives and false negatives are possible. Always verify findings manually or consult a security professional.', 'bbh-security-insight' );

        if ( 'high_risk' === $verdict ) {
            return __( 'Immediately review the flagged files in the evidence panel. These files contain execution chains (eval, system, exec) combined with obfuscation (encoded payloads, high entropy) — strong indicators of malicious code. Compare against the official plugin/theme source from the WordPress repository.', 'bbh-security-insight' ) . ' ' . $disclaimer;
        }

        if ( 'suspicious' === $verdict ) {
            return __( 'Review the evidence panel below. These files contain execution-adjacent patterns (system calls, deprecated functions) in non-trusted code. Not conclusive on their own, but warrant manual inspection. Compare flagged files against a fresh installation from the official source.', 'bbh-security-insight' ) . ' ' . $disclaimer;
        }

        return __( 'No signs of malicious code detected. Flagged files use common development patterns (caching, serialization, schema generation, XML parsing, regex, etc.) with no execution-obfuscation chain. No action required.', 'bbh-security-insight' ) . ' ' . $disclaimer;
    }

    /**
     * Build the current-value display string using verdict.
     *
     * @since 1.2.0
     * @param string $verdict    Overall verdict.
     * @param array  $classified Classified scan data.
     * @return string
     */
    private function build_malware_current_value( $verdict, array $classified ) {
        $counts = $classified['verdict_counts'];

        if ( 'high_risk' === $verdict ) {
            /* translators: %d: number of high-risk files */
            return sprintf( __( 'Confirmed Malware — %d file(s) with execution-obfuscation chains', 'bbh-security-insight' ), $counts['high_risk'] );
        }
        if ( 'suspicious' === $verdict ) {
            /* translators: %d: number of suspicious files */
            return sprintf( __( 'Suspicious — %d file(s) require manual review', 'bbh-security-insight' ), $counts['suspicious'] );
        }
        if ( $counts['benign'] > 0 ) {
            /* translators: %d: number of clean files */
            return sprintf( __( 'Clean — %d file(s) with low-severity patterns only', 'bbh-security-insight' ), $counts['benign'] );
        }
        return __( 'Clean', 'bbh-security-insight' );
    }

    /**
     * Return a "clean" result when no patterns are found.
     *
     * @since 1.2.0
     * @return array
     */
    private function malware_clean_result() {
        $result = $this->build_result(
            'malware_heuristics',
            __( 'Malware Heuristics Scan', 'bbh-security-insight' ),
            self::RISK_SAFE,
            __( 'No suspicious code patterns were detected in active plugin and theme PHP files. This is a positive sign, though not a guarantee of absolute security.', 'bbh-security-insight' ),
            __( 'Continue running regular audits and keep your plugins and themes updated from official sources.', 'bbh-security-insight' ),
            __( 'Clean', 'bbh-security-insight' )
        );
        $result['verdict']            = 'clean';
        $result['needs_manual_review'] = false;
        $result['evidence']           = array();
        $result['disclaimer']         = __( 'Heuristic results are not a guarantee of infection. False positives and false negatives are possible. Always verify findings manually or consult a security professional.', 'bbh-security-insight' );
        return $result;
    }
}
