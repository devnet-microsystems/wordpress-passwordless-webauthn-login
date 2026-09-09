<?php
/**
 * Sovereign Auth — Uninstall Logic
 */

defined( 'ABSPATH' ) || exit;

class SovAuth_Uninstall {

    public static function cleanup(): void {
        if ( is_multisite() ) {
            $siteIds = get_sites( [ 'fields' => 'ids' ] );
            foreach ( $siteIds as $siteId ) {
                switch_to_blog( (int) $siteId );
                self::wipe_site();
                restore_current_blog();
            }
        } else {
            self::wipe_site();
        }

        // Usermeta is network-global — wipe it once, outside the per-site loop.
        self::wipe_usermeta();
    }

    /**
     * Drop the credentials table and clear all plugin transients/options
     * for the CURRENT site (i.e. the current $wpdb->prefix).
     */
    private static function wipe_site(): void {
        global $wpdb;

        // ── Custom table ──
        $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sovauth_credentials" );
        $wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}sovauth_activity_log" );

        // ── Transients (stored as a pair of rows in wp_options) ──
        $likeTransient        = $wpdb->esc_like( '_transient_sovauth_' ) . '%';
        $likeTransientTimeout = $wpdb->esc_like( '_transient_timeout_sovauth_' ) . '%';

        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}options WHERE option_name LIKE %s OR option_name LIKE %s",
            $likeTransient,
            $likeTransientTimeout
        ) );

        // ── Plain options ──
        delete_option( 'sovauth_db_ver' );
        delete_option( 'sovauth_license_key' );
        delete_option( 'sovauth_license_status' );
        delete_option( 'sovauth_tor_mode' );
        delete_option( 'sovauth_gemini_api_key' );
        delete_option( 'sovauth_ai_gateway_url' );
        delete_option( 'sovauth_ai_gateway_secret' );
        delete_option( 'sovauth_ai_denied_ips' );
        delete_option( 'sovauth_ai_logs' );
        delete_option( 'sovauth_sentinel_prompt' );
        delete_option( 'sovauth_agent_marketing' );
        delete_option( 'sovauth_agent_marketing_history' );
        delete_option( 'sovauth_agent_sales' );
        delete_option( 'sovauth_agent_sales_history' );
        delete_option( 'sovauth_agent_support' );
        delete_option( 'sovauth_agent_support_history' );
        delete_option( 'sovauth_webhook_token' );
    }

    /**
     * Remove every _sovauth_* usermeta key for every user on the network.
     */
    private static function wipe_usermeta(): void {
        $keys = [
            '_sovauth_recovery_lookup_hash',
            '_sovauth_recovery_verify_hash',
            '_sovauth_recovery_attempts',
        ];

        foreach ( $keys as $key ) {
            delete_metadata( 'user', 0, $key, '', true );
        }
    }
}
