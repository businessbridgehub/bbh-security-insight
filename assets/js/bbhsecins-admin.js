/**
 * Admin JavaScript for BBH Security Insight.
 *
 * Handles AJAX audit execution and notice dismissal.
 *
 * @since 1.0.0
 * @package BBHSecurityInsight
 */

(function ($) {
    'use strict';

    var bbhsecins = {

        /**
         * Initialize the module.
         *
         * @since 1.0.0
         */
        init: function () {
            this.bindEvents();
        },

        /**
         * Bind event listeners.
         *
         * @since 1.0.0
         */
        bindEvents: function () {
            $('#bbhsecins-run-audit').on('click', $.proxy(this.runAudit, this));

            $(document).on('click', '.bbhsecins-notice .notice-dismiss', $.proxy(this.dismissNotice, this));
        },

        /**
         * Run the security audit via AJAX.
         *
         * @since 1.0.0
         * @param {Event} e Click event.
         */
        runAudit: function (e) {
            var $button  = $(e.currentTarget),
                $spinner = $('#bbhsecins-spinner'),
                $results = $('#bbhsecins-results'),
                $lastRun = $('#bbhsecins-last-run');

            $button.prop('disabled', true);
            $spinner.addClass('is-active');
            $results.html('<div class="bbhsecins-loading"><p>' + bbhsecinsData.runningText + '</p></div>');

            $.ajax({
                url: bbhsecinsData.ajaxUrl,
                type: 'POST',
                data: {
                    action: 'bbhsecins_run_audit',
                    bbhsecins_nonce: bbhsecinsData.nonce
                },
                dataType: 'json',
                success: function (response) {
                    if (response.success && response.data && response.data.html) {
                        location.reload();
                    } else {
                        $results.html(
                            '<div class="notice notice-error"><p>' + bbhsecinsData.errorText + '</p></div>'
                        );
                    }
                },
                error: function () {
                    $results.html(
                        '<div class="notice notice-error"><p>' + bbhsecinsData.errorText + '</p></div>'
                    );
                },
                complete: function () {
                    $button.prop('disabled', false);
                    $spinner.removeClass('is-active');
                }
            });
        },

        /**
         * Dismiss an admin notice via AJAX.
         *
         * @since 1.0.0
         * @param {Event} e Click event on dismiss button.
         */
        dismissNotice: function (e) {
            var $notice   = $(e.currentTarget).closest('.bbhsecins-notice'),
                noticeKey = $notice.data('bbhsecins-notice');

            if (!noticeKey) {
                return;
            }

            $.ajax({
                url: bbhsecinsData.ajaxUrl,
                type: 'POST',
                data: {
                    action:     'bbhsecins_dismiss_notice',
                    notice_key: noticeKey,
                    _wpnonce:   bbhsecinsData.dismissNonce
                },
                dataType: 'json'
            });
        }
    };

    $(document).ready(function () {
        bbhsecins.init();
    });

})(jQuery);
