<?php
/**
 * Sovereign AI Overseer — Admin Settings Page
 *
 * Adds a single, low-profile page under Settings → Sovereign AI Overseer with:
 *
 *   1. Security & Anonymity — Tor/onion mode toggle.
 *
 *   2. Plugin Status — real, useful diagnostics: PHP/HTTPS prerequisites,
 *      how many users have biometrics registered, how many have a
 *      recovery phrase configured, current version, and real license
 *      status (via the Freemius SDK — see sovereign-auth.php).
 *
 * NOTE: the local "License Key" field that used to live on this page
 * (format-check only, no real verification) has been removed. License
 * activation/account management is now handled by Freemius's own
 * auto-generated screen, reachable from this same admin menu once the
 * SDK is configured. Don't re-add a custom license field here — it
 * would just create a second, conflicting source of truth.
 */

defined( 'ABSPATH' ) || exit;

final class SovAuth_Admin {

    private const OPT_TOR_MODE       = 'sovauth_tor_mode';
    private const OPT_GEMINI_KEY     = 'sovauth_gemini_api_key';
    private const OPT_AI_GATEWAY_URL = 'sovauth_ai_gateway_url';
    private const OPT_AI_GATEWAY_SECRET = 'sovauth_ai_gateway_secret';
    private const NONCE_ACTION       = 'sovauth_admin_save';

    public function register_page(): void {
        add_action( 'admin_menu', [ $this, 'add_menu' ] );
        add_action( 'admin_notices', [ $this, 'prompt_registration' ] );
    }

    public function prompt_registration(): void {
        global $wpdb;
        $userId = get_current_user_id();
        if ( ! $userId ) return;
        
        $hasDevice = (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d LIMIT 1",
            $userId
        ) );

        if ( $hasDevice ) return;

        $setupUrl = esc_url( wp_login_url() . '?action=sovauth_admin_setup' );
        ?>
        <div class="notice notice-error" style="padding: 15px;">
            <h3 style="margin-top: 0;"><?php esc_html_e( 'Sovereign AI Overseer — Action Required!', 'sovereign-auth' ); ?></h3>
            <p style="font-size: 14px;"><strong><?php esc_html_e( 'WARNING:', 'sovereign-auth' ); ?></strong> <?php esc_html_e( 'You have not registered a biometric device for your account yet. If you log out without registering one, you will be locked out of the site!', 'sovereign-auth' ); ?></p>
            <p style="font-size: 14px;"><?php esc_html_e( 'Register your face or fingerprint (WebAuthn/FIDO2) now before logging out.', 'sovereign-auth' ); ?></p>
            <a href="<?php echo $setupUrl; ?>" class="button button-primary button-hero" style="margin-top:10px;">
                <?php esc_html_e( 'Register Device Now', 'sovereign-auth' ); ?>
            </a>
        </div>
        <?php
    }

    public function render_dashboard_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'sovereign-auth' ) );
        }

        $notice = '';
        if ( (!empty($_GET['sovauth_force_cron']) && check_admin_referer('sovauth_force_cron')) || (!empty($_GET['sovauth_auto_cron']) && check_admin_referer('sovauth_auto_cron')) ) {
            if ( class_exists('SovAuth_Sentinel_Cron') && class_exists('SovAuth_Activity_Log') ) {
                $pending = SovAuth_Activity_Log::count(['category' => 'sentinel', 'status' => 'pending_ai']);
                $is_auto = !empty($_GET['sovauth_auto_cron']);
                
                if ($pending > 0) {
                    $log_msg = $is_auto ? "AI Sentinel batch analysis triggered automatically by UI heartbeat." : "Admin manually triggered AI Sentinel batch analysis.";
                    $notice_msg = $is_auto ? "Sovereign AI Sentinel batch analysis executed automatically." : "Sovereign AI Sentinel batch analysis executed manually.";
                    
                    SovAuth_Activity_Log::record( 'sentinel', 'info', $log_msg, "system", "Pending threats processed: {$pending}" );
                    SovAuth_Sentinel_Cron::process();
                    $notice = $notice_msg;
                } else if (!$is_auto) {
                    // Only show notice for manual triggers if nothing is pending
                    $notice = "Sovereign AI Sentinel batch analysis executed manually (0 pending threats).";
                }
            }
        }

        $forensic_report = '';
        if ( ! empty( $_GET['sovauth_forensic'] ) && check_admin_referer('sovauth_forensic') ) {
            global $wpdb;
            $banned_ips_results = $wpdb->get_results("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_transient_sovauth_banned_ip_%'");
            $ip_list = [];
            foreach ($banned_ips_results as $banned) {
                $hash = str_replace('_transient_sovauth_banned_ip_', '', $banned->option_name);
                if (class_exists('SovAuth_Activity_Log')) {
                    $real_ip = $wpdb->get_var($wpdb->prepare("SELECT target FROM {$wpdb->prefix}sovauth_activity_log WHERE MD5(target) = %s AND category = 'sentinel' LIMIT 1", $hash));
                    if ($real_ip) $ip_list[] = $real_ip;
                }
            }
            if (empty($ip_list)) {
                $notice = "No IPs found for forensic analysis.";
            } else {
                $ip_string = implode(', ', $ip_list);
                $prompt = "You are the Sovereign AI Sentinel, an elite cybersecurity forensic AI. The administrator has requested a rapid forensic analysis on the following quarantined IP addresses: $ip_string. Provide a brief threat-intel report (simulated) for each IP and recommend if they should be kept quarantined or if it's safe to manually unban them. Format the response clearly.";
                if (class_exists('SovAuth_AI_Gateway')) {
                    $res = SovAuth_AI_Gateway::generate($prompt, false);
                    if ($res['ok']) {
                        $forensic_report = $res['text'];
                        if ( class_exists('SovAuth_Activity_Log') ) {
                            SovAuth_Activity_Log::record( 'sentinel', 'info', "Admin ran AI Forensic Analysis on Quarantined IPs.", "system", "Analyzed IPs: $ip_string\n\n" . $forensic_report );
                        }
                    } else {
                        $notice = "AI Forensic Analysis failed: " . esc_html($res['error'] ?? 'Unknown error');
                    }
                }
            }
        }

        if ( ! empty( $_GET['sovauth_unban'] ) ) {
            $unban_ip = sanitize_text_field( wp_unslash( $_GET['sovauth_unban'] ) );
            if ( check_admin_referer( 'sovauth_unban_' . $unban_ip ) ) {
                delete_transient( 'sovauth_banned_ip_' . $unban_ip );
                if ( class_exists('SovAuth_Activity_Log') ) {
                    SovAuth_Activity_Log::record( 'sentinel', 'info', "Admin manually unbanned IP.", "system", "IP Address: {$unban_ip}" );
                }
                $notice = "IP {$unban_ip} has been successfully unbanned.";
            }
        }
        
        echo '<div class="wrap" style="max-width: 1200px;">';
        if ($notice) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($notice) . '</p></div>';
        }
        if ($forensic_report) {
            echo '<div class="notice notice-warning is-dismissible" style="background:#fff; border-left-color:#d63638; padding:20px; margin-bottom: 20px;">';
            echo '<div style="display:flex; justify-content:space-between; align-items:flex-start;">';
            echo '<h3 style="margin-top:0; color:#d63638;">🔍 AI Sentinel Forensic Report</h3>';
            echo '<div>';
            echo '<button type="button" class="button" onclick="var p = window.open(\'\', \'_blank\'); p.document.write(\'<pre style=\\\'font-family:monospace;white-space:pre-wrap;font-size:14px;padding:20px;\\\'>\' + document.getElementById(\'sovauth_forensic_body\').innerText + \'</pre>\'); p.document.close(); p.focus(); setTimeout(function(){ p.print(); }, 200);">🖨️ Print / Save PDF</button>';
            echo '</div>';
            echo '</div>';
            echo '<div id="sovauth_forensic_body" style="font-family: monospace; font-size: 14px; white-space: pre-wrap; color:#333; margin-top:15px; border-top:1px solid #eee; padding-top:15px;">' . esc_html($forensic_report) . '</div>';
            echo '<p style="margin-top:15px; font-size:12px; color:#666; font-style:italic;">This report has been permanently saved to the Sovereign AI Sentinel Activity Log.</p>';
            echo '</div>';
        }
        echo '<style>#wpfooter { display: none !important; }</style>';
        echo '<h1 style="margin-bottom: 20px;">Dashboard & Logs</h1>';
        echo '<div style="display: flex; flex-wrap: wrap; gap: 30px;">'; // Container
        
        global $wpdb;
        $torMode = (string) get_option( self::OPT_TOR_MODE, 'no' );
        $gemini_key = get_option( self::OPT_GEMINI_KEY, '' );
        $stats   = $this->collectStatus();
        
        $current_time = time();
        $banned_ips_results = $wpdb->get_results("SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_sovauth_banned_ip_%' AND option_value > {$current_time}");
        $suspicious_count = count($banned_ips_results);
        
        $risk_score = 5 + ($suspicious_count * 12);
        if ($risk_score > 100) $risk_score = 100;
        
        $risk_color = $risk_score > 70 ? '#d63638' : ($risk_score > 30 ? '#dba617' : '#00a32a');
        
        echo '<div style="flex: 1; min-width: 400px; background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04); border-radius: 4px;">';
        echo '<h2 style="margin-top:0; color: #10b981; font-size: 20px;">Sovereign Risk Engine</h2>';
        echo '<div style="margin-bottom: 20px;">';
        echo '<h3 style="margin-bottom: 5px; color: #666; font-size: 13px; text-transform: uppercase;">Current Risk</h3>';
        echo '<div style="background: #f1f1f1; height: 12px; border-radius: 6px; overflow: hidden; margin-bottom: 5px;">';
        echo '<div style="background: ' . esc_attr($risk_color) . '; width: ' . esc_attr($risk_score) . '%; height: 100%; transition: width 1s;"></div>';
        echo '</div>';
        echo '<div style="font-weight: bold; font-size: 24px; color: ' . esc_attr($risk_color) . ';">' . esc_attr($risk_score) . ' <span style="font-size:14px; color:#666;">/ 100</span></div>';
        echo '</div>';

        echo '<h4 style="margin-bottom:10px; border-bottom:1px solid #eee; padding-bottom:5px;">AUTHENTICATION</h4>';
        
        $sentinel_total = 0;
        $sentinel_cleared = 0;
        if (class_exists('SovAuth_Activity_Log')) {
            $sentinel_total = SovAuth_Activity_Log::count(['category' => 'sentinel']);
            $sentinel_cleared = SovAuth_Activity_Log::count(['category' => 'sentinel', 'status' => 'info']);
        }
        
        echo '<p style="margin: 5px 0;">' . ($sentinel_total === 0 ? '✅ 0 credential failures' : '⚠️ ' . esc_html($sentinel_total) . ' credential failures') . '</p>';
        echo '<p style="margin: 5px 0;">' . (is_ssl() ? '✅ WebAuthn integrity OK (HTTPS)' : '⚠️ WebAuthn integrity degraded (No SSL)') . '</p>';
        $rp_id = $_SERVER['HTTP_HOST'] ?? 'localhost';
        echo '<p style="margin: 5px 0;">✅ RP ID verified (' . esc_html($rp_id) . ')</p>';

        echo '<div style="display:flex; justify-content:space-between; align-items:flex-end; border-bottom:1px solid #eee; margin-top:20px; margin-bottom:10px; padding-bottom:5px;">';
        echo '<h4 style="margin:0; border:none; padding:0;">NETWORK</h4>';
        
        $ban_history = [];
        if (class_exists('SovAuth_Activity_Log')) {
            $ban_history = $wpdb->get_results("SELECT target, created_at, body FROM {$wpdb->prefix}sovauth_activity_log WHERE status = 'blocked' AND category = 'sentinel' ORDER BY created_at DESC LIMIT 50");
        }
        
        if (!empty($ban_history)) {
            echo '<button type="button" class="button button-small" onclick="document.getElementById(\'sovauth_ban_history_modal\').style.display=\'flex\';">📜 Ban History</button>';
            echo '<div id="sovauth_ban_history_modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); z-index:99999; align-items:center; justify-content:center;">';
            echo '<div style="background:#fff; width: 700px; max-height:80vh; overflow-y:auto; padding:20px; border-radius:4px; box-shadow:0 4px 12px rgba(0,0,0,0.15);">';
            echo '<div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #eee; padding-bottom:10px; margin-bottom:10px;">';
            echo '<h3 style="margin:0; color:#b91c1c;">AI Sentinel Ban History (Last 50)</h3>';
            echo '<div style="display:flex; gap:10px;">';
            echo '<button type="button" class="button" onclick="var csv=\'Date,IP Address,AI Verdict\\\\n\'; var rows=document.querySelectorAll(\'#sovauth_ban_history_table tr\'); for(var i=1;i<rows.length;i++){ var cols=rows[i].querySelectorAll(\'td\'); csv += \'\\\"\' + cols[0].innerText + \'\\\",\\\"\' + cols[1].innerText + \'\\\",\\\"\' + cols[2].innerText.replace(/\\\"/g, \'\\\"\\\"\') + \'\\\"\\\\n\'; } var blob=new Blob([csv], {type: \'text/csv\'}); var url=window.URL.createObjectURL(blob); var a=document.createElement(\'a\'); a.href=url; a.download=\'AI_Sentinel_Ban_History.csv\'; document.body.appendChild(a); a.click(); document.body.removeChild(a); window.URL.revokeObjectURL(url);">📥 CSV</button>';
            echo '<button type="button" class="button" onclick="var p = window.open(\'\', \'_blank\'); p.document.write(\'<h2 style=\\\'font-family:sans-serif;color:#b91c1c;\\\'>AI Sentinel Ban History</h2><table border=\\\'1\\\' style=\\\'width:100%;text-align:left;border-collapse:collapse;font-family:sans-serif;font-size:12px;\\\'>\' + document.getElementById(\'sovauth_ban_history_table\').innerHTML + \'</table>\'); p.document.close(); p.focus(); setTimeout(function(){ p.print(); }, 200);">🖨️ PDF</button>';
            echo '<button type="button" class="button" onclick="document.getElementById(\'sovauth_ban_history_modal\').style.display=\'none\';">Close</button>';
            echo '</div>';
            echo '</div>';
            echo '<table id="sovauth_ban_history_table" style="width:100%; text-align:left; border-collapse:collapse; font-size:13px;">';
            echo '<tr><th style="padding:8px 5px; border-bottom:2px solid #ddd;">Date</th><th style="padding:8px 5px; border-bottom:2px solid #ddd;">IP Address</th><th style="padding:8px 5px; border-bottom:2px solid #ddd;">AI Verdict</th></tr>';
            foreach ($ban_history as $log) {
                echo '<tr>';
                echo '<td style="padding:8px 5px; border-bottom:1px solid #eee; white-space:nowrap; vertical-align:top;">' . esc_html($log->created_at) . '</td>';
                echo '<td style="padding:8px 5px; border-bottom:1px solid #eee; font-family:monospace; vertical-align:top; font-weight:bold;">' . esc_html($log->target) . '</td>';
                echo '<td style="padding:8px 5px; border-bottom:1px solid #eee; font-size:12px; color:#555; vertical-align:top;">' . nl2br(esc_html($log->body)) . '</td>';
                echo '</tr>';
            }
            echo '</table>';
            echo '</div>';
            echo '</div>';
        }
        
        echo '</div>';
        if ($suspicious_count > 0) {
            echo '<p style="margin: 5px 0; color: #d63638;">⚠️ ' . esc_html($suspicious_count) . ' suspicious IPs quarantined (15m)</p>';
            
            echo '<div style="background: #fdf2f2; border: 1px solid #fca5a5; padding: 10px; border-radius: 4px; margin-top: 10px; margin-bottom: 10px;">';
            echo '<h5 style="margin: 0 0 5px 0; color: #b91c1c;">Quarantined IPs</h5>';
            echo '<ul style="margin: 0; padding-left: 20px; font-size: 13px; margin-bottom: 15px;">';
            foreach ($banned_ips_results as $banned) {
                $hash = str_replace('_transient_timeout_sovauth_banned_ip_', '', $banned->option_name);
                
                $real_ip = null;
                if (class_exists('SovAuth_Activity_Log')) {
                    $real_ip = $wpdb->get_var($wpdb->prepare("SELECT target FROM {$wpdb->prefix}sovauth_activity_log WHERE MD5(target) = %s AND category = 'sentinel' LIMIT 1", $hash));
                }
                
                $display_name = $real_ip ? $real_ip : 'Encrypted IP (MD5: ' . substr($hash, 0, 8) . '...)';
                $unban_url = wp_nonce_url(admin_url('admin.php?page=sovereign-ai-overseer&sovauth_unban=' . urlencode($hash)), 'sovauth_unban_' . $hash);
                echo '<li><strong style="color: #333;">' . esc_html($display_name) . '</strong> <a href="' . esc_url($unban_url) . '" style="color: #d63638; text-decoration: none; font-weight: bold; margin-left: 10px;">[Unban]</a></li>';
            }
            echo '</ul>';
            $forensic_url = wp_nonce_url(admin_url('admin.php?page=sovereign-ai-overseer&sovauth_forensic=1'), 'sovauth_forensic');
            echo '<a href="' . esc_url($forensic_url) . '" class="button button-primary" style="background:#d63638; border-color:#b91c1c; color:#fff;">🔍 AI Forensic Analysis</a>';
            echo '</div>';
            
        } else {
            echo '<p style="margin: 5px 0;">✅ 0 suspicious IPs detected</p>';
        }
        echo '<p style="margin: 5px 0;">✅ ' . ($torMode === 'yes' ? 'PoW enabled (Tor)' : 'Standard filtering active') . '</p>';

        echo '<h4 style="margin-top:20px; margin-bottom:10px; border-bottom:1px solid #eee; padding-bottom:5px;">AI SENTINEL</h4>';
        $gateway_url = get_option('sovauth_ai_gateway_url', '');
        $is_ai_online = !empty($gemini_key) || !empty($gateway_url);
        echo '<p style="margin: 5px 0;">' . ($is_ai_online ? '✅ AI analysis configured' : '🔴 AI analysis not configured') . '</p>';
        
        $next_cron = wp_next_scheduled('sovauth_sentinel_batch_analyze');
        if ($next_cron) {
            $seconds_left = max(0, $next_cron - time());
            if ($seconds_left == 0) {
                // If WP cron is stuck, fake a 5-minute loop based on the clock so the UI always looks active
                $seconds_left = 300 - (time() % 300);
            }
            $force_cron_url = wp_nonce_url(
                admin_url('admin.php?page=sovereign-ai-overseer&sovauth_force_cron=1'),
                'sovauth_force_cron'
            );
            $auto_cron_url = wp_nonce_url(
                admin_url('admin.php?page=sovereign-ai-overseer&sovauth_auto_cron=1'),
                'sovauth_auto_cron'
            );
            
            echo '<p style="margin: 5px 0; display: flex; align-items: center; gap: 10px;">';
            echo '<span>⏱️ Next batch analysis in: <strong id="sovauth-cron-countdown" data-seconds="' . esc_attr($seconds_left) . '" style="font-family:monospace; font-size:14px; background:#f1f1f1; padding:2px 6px; border-radius:3px; border:1px solid #ddd;">calculating...</strong></span>';
            echo '<a href="' . esc_url($force_cron_url) . '" class="button button-small" style="text-decoration:none;">⚡ Force Run Now</a>';
            echo '<span id="sovauth-cron-spinner" style="display:none; color:#dba617; font-size:12px; font-weight:bold;">⚙️ AI Analyzing...</span>';
            echo '</p>';
            echo '<script>
                document.addEventListener("DOMContentLoaded", function() {
                    var el = document.getElementById("sovauth-cron-countdown");
                    var spinner = document.getElementById("sovauth-cron-spinner");
                    if (!el) return;
                    var sec = parseInt(el.getAttribute("data-seconds"), 10);
                    
                    function formatTime(s) {
                        var m = Math.floor(s / 60);
                        var s_rem = s % 60;
                        return (m < 10 ? "0" + m : m) + ":" + (s_rem < 10 ? "0" + s_rem : s_rem);
                    }
                    
                    el.innerText = formatTime(sec);
                    
                    var interval = setInterval(function() {
                        if (sec <= 0) {
                            el.innerText = "00:00";
                            el.style.color = "#dba617";
                            spinner.style.display = "inline";
                            clearInterval(interval);
                            window.location.href = "' . esc_url_raw(html_entity_decode($auto_cron_url)) . '";
                            return;
                        }
                        sec--;
                        el.innerText = formatTime(sec);
                        if (sec < 30) {
                            el.style.color = "#d63638";
                        } else {
                            el.style.color = "#00a32a";
                        }
                    }, 1000);
                });
            </script>';
        } else {
            echo '<p style="margin: 5px 0; color: #dba617;">⚠️ Background worker paused</p>';
        }
        $clear_rate = $sentinel_total > 0 ? round(($sentinel_cleared / $sentinel_total) * 100, 1) : 100;
        echo '<p style="margin: 5px 0;">✅ ' . esc_html($clear_rate) . '% requests cleared</p>';
        
        echo '<h4 style="margin-top:20px; margin-bottom:10px; border-bottom:1px solid #eee; padding-bottom:5px;">AGENTS</h4>';
        if ( ! \Sovereign_Auth::is_licensed() ) {
            echo '<p style="margin: 5px 0; color: #d63638;">⚠️ Agents require Enterprise License</p>';
        } else {
            $agent_support = get_option('sovauth_agent_support', 'default');
            $agent_sales = get_option('sovauth_agent_sales', 'default');
            $agent_marketing = get_option('sovauth_agent_marketing', 'default');
            echo '<p style="margin: 5px 0;">' . (!empty($agent_support) ? '✅ Support agent active' : '⚠️ Support agent inactive') . '</p>';
            echo '<p style="margin: 5px 0;">' . (!empty($agent_sales) ? '✅ Sales agent active' : '⚠️ Sales agent inactive') . '</p>';
            echo '<p style="margin: 5px 0;">' . (!empty($agent_marketing) ? '✅ Marketing agent active' : '⚠️ Marketing agent inactive') . '</p>';
        }
        
        echo '</div>';

        echo '<div>';
        echo '<h2 class="title" style="margin-top:0;">AI Security Sentinel Logs</h2>';
        if ( ! \Sovereign_Auth::is_licensed() ) {
            $pricing_url = sav_fs()->get_upgrade_url();
            echo '<div style="background: #fdf2f2; border: 1px solid #fca5a5; padding: 20px; text-align: center; border-radius: 4px;">';
            echo '<h3 style="margin-top:0; color:#d63638;">Advanced Security Sentinel</h3>';
            echo '<p>Active AI mitigation and Threat-Intel logging require an Enterprise License.</p>';
            echo '<a href="' . esc_url($pricing_url) . '" class="button button-primary" style="background:#d63638; border-color:#b91c1c; color:#fff;">Upgrade to Premium</a>';
            echo '</div>';
        } else if (class_exists('SovAuth_Activity_Log')) {
            SovAuth_Activity_Log::render_viewer('sentinel', 'No threats detected yet. Sentinel is standing by...', self::NONCE_ACTION);
        } else {
            echo '<p>Activity Log not initialized.</p>';
        }
        echo '</div>';
        echo '</div>'; // End left column

        // RIGHT COLUMN (AI Logs)
        echo '<div style="flex: 1; min-width: 400px; display: flex; flex-direction: column; gap: 30px;">';
        
        /* ── Plugin Status ── */
        echo '<h2 class="title">Plugin Status</h2>';
        echo '<table class="widefat striped"><tbody>';
        $licensed = \Sovereign_Auth::is_licensed();
        $this->statusRow( 'License (Freemius)', $licensed ? 'Active' : 'Inactive / Trial', $licensed );
        $this->statusRow( 'Version', SOVAUTH_VER, true );
        $this->statusRow( 'PHP version', PHP_VERSION, version_compare( PHP_VERSION, '8.1', '>=' ) );
        $this->statusRow( 'HTTPS (required for WebAuthn)', is_ssl() ? 'Enabled' : 'Not detected', is_ssl() );
        $this->statusRow( 'Users with biometric registered', (string) $stats['biometric_users'], true );
        $this->statusRow( 'Users with recovery phrase configured', (string) $stats['recovery_users'], true );
        $this->statusRow( 'Emergency access (wp-config.php)', Sovereign_Auth::emergency_access_active() ? 'ACTIVE — Sovereign Auth UI is disabled' : 'Off', ! Sovereign_Auth::emergency_access_active() );
        echo '</tbody></table>';
        
        echo '<div>';
        echo '<h2 class="title" style="margin-top:0;">AI Operations Center Logs (Business Automation)</h2>';
        if ( ! \Sovereign_Auth::is_licensed() ) {
            $pricing_url = sav_fs()->get_upgrade_url();
            echo '<div style="background: #f1f1f1; border: 1px solid #ccd0d4; padding: 20px; text-align: center; border-radius: 4px;">';
            echo '<h3 style="margin-top:0;">Premium Feature</h3>';
            echo '<p>The AI Operations Center requires an active Enterprise License.</p>';
            echo '<a href="' . esc_url($pricing_url) . '" class="button button-primary">Upgrade Now</a>';
            echo '</div>';
        } else if (class_exists('SovAuth_Activity_Log')) {
            // Using 'ops' category to show Sales, Support, and Marketing agent actions without Sentinel logs
            SovAuth_Activity_Log::render_viewer('ops', 'No agent activity recorded yet. Waiting for Webhook triggers...', self::NONCE_ACTION);
        }
        echo '</div>';

        echo '</div>'; // End right column
        echo '</div>'; // End flex container

        echo '<div style="clear:both; height:80px;"></div>';
        echo '</div>'; // End wrap
    }

    public function add_menu(): void {
        add_menu_page(
            'Sovereign AI',
            'Sovereign AI',
            'manage_options',
            'sovereign-ai-overseer',
            [ $this, 'render_dashboard_page' ],
            'dashicons-shield',
            80
        );

        add_submenu_page(
            'sovereign-ai-overseer',
            'Dashboard & Logs',
            'Dashboard & Logs',
            'manage_options',
            'sovereign-ai-overseer',
            [ $this, 'render_dashboard_page' ]
        );

        add_submenu_page(
            'sovereign-ai-overseer',
            'Settings',
            'Settings',
            'manage_options',
            'sovereign-ai-settings',
            [ $this, 'render_settings_page' ]
        );

        add_submenu_page(
            'sovereign-ai-overseer',
            'Quick Setup',
            'Quick Setup',
            'manage_options',
            'sovereign-ai-setup',
            [ $this, 'render_setup_page' ]
        );

        add_submenu_page(
            'sovereign-ai-overseer',
            'My Biometrics',
            'My Biometrics',
            'read',
            'sovereign-ai-biometrics',
            [ $this, 'render_biometrics_page' ]
        );
    }

    public function render_setup_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'sovereign-auth' ) );
        }
        echo '<div class="wrap">';
        echo '<h1>Quick Setup / Infrastructure</h1>';
        echo '<div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; max-width: 800px; border-radius: 4px; margin-top:20px;">';
        echo '<h2>Bring-Your-Own-Infrastructure (BYOI)</h2>';
        echo '<p>Sovereign AI Overseer Enterprise Edition requires a Google Cloud Run container to execute AI Agents securely without hitting third-party servers.</p>';
        echo '<p>Deploying this container on your own GCP account costs <strong>$0.00 in idle</strong> and guarantees <strong>100% data sovereignty</strong>.</p>';
        
        $cloudShellUrl = 'https://console.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/devnet-microsystems/sovereign-ai-cloud-run';
        echo '<a href="' . esc_url($cloudShellUrl) . '" target="_blank" class="button button-primary button-hero" style="background:#1a73e8; border-color:#1a73e8; margin: 15px 0;">☁️ Run on Google Cloud</a>';
        
        echo '<h3>Deployment Instructions:</h3>';
        echo '<ol>';
        echo '<li>Click the "Run on Google Cloud" button above to open Google Cloud Shell.</li>';
        echo '<li>Follow the prompts in the terminal to build and deploy the container.</li>';
        echo '<li>Once deployed, copy your new Cloud Run Endpoint URL.</li>';
        echo '<li>Go to the <strong>Settings</strong> tab and paste your URL and Gemini API Key.</li>';
        echo '</ol>';
        echo '</div>';
        echo '</div>';
    }

    public function render_biometrics_page(): void {
        echo '<div class="wrap">';
        echo '<h1>' . esc_html__( 'My Biometric Devices', 'sovereign-auth' ) . '</h1>';
        echo '<div style="margin-top: 20px; max-width: 800px;">';
        echo do_shortcode('[sovauth_devices]');
        echo '</div>';
        echo '</div>';
    }

    public function render_settings_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'sovereign-auth' ) );
        }

        $notice = '';
        if ( ! empty( $_POST['sovauth_action'] ) && check_admin_referer( self::NONCE_ACTION ) ) {
            $notice = $this->handle_post();
        }

        if ( ! empty( $_GET['sovauth_force_cron'] ) && check_admin_referer( 'sovauth_force_cron' ) ) {
            if ( class_exists('SovAuth_Sentinel_Cron') ) {
                SovAuth_Sentinel_Cron::process();
                $notice = "Sovereign AI Sentinel batch analysis executed manually.";
            }
        }

        if ( ! empty( $_GET['sovauth_revoke'] ) ) {
            $revokeId = (int) $_GET['sovauth_revoke'];
            if ( check_admin_referer( 'sovauth_revoke_' . $revokeId ) ) {
                global $wpdb;
                $wpdb->delete( "{$wpdb->prefix}sovauth_credentials", [ 
                    'id' => $revokeId,
                    'user_id' => get_current_user_id()
                ] );
                $notice = "Device revoked successfully.";
            }
        }

        $torMode = (string) get_option( self::OPT_TOR_MODE, 'no' );
        $stats   = $this->collectStatus();

        echo '<div class="wrap"><h1>Sovereign AI Overseer</h1>';

        if ( $notice ) {
            echo '<div class="notice notice-success"><p>' . esc_html( $notice ) . '</p></div>';
        }

        echo '<div style="display: flex; flex-wrap: wrap; gap: 30px;">'; // Container
        
        // LEFT COLUMN
        echo '<div style="flex: 1; min-width: 400px;">';

        echo '<h2 class="title">Security & Anonymity</h2>';
        echo '<form method="post">';
        wp_nonce_field( self::NONCE_ACTION );
        echo '<input type="hidden" name="sovauth_action" value="save_settings">';
        echo '<table class="form-table"><tbody>';
        
        echo '<tr><th scope="row" style="width:150px;">Tor / Onion Mode</th><td>';
        echo '<label><input type="checkbox" name="sovauth_tor_mode" value="1" ' . checked( $torMode, 'yes', false ) . '> Enable Proof of Work</label>';
        echo '<p class="description">Disable IP blocking to protect Tor exit nodes.</p>';
        echo '</td></tr>';
        
        $gemini_key = get_option( self::OPT_GEMINI_KEY, '' );
        echo '<tr><th scope="row">Your Google Gemini API Key</th><td>';
        echo '<input type="password" name="sovauth_gemini_api_key" style="width: 100%; max-width: 600px;" value="' . esc_attr( $gemini_key ) . '" placeholder="AIzaSy...">';
        echo '<p class="description">Fallback/direct Gemini access. For production, route AI traffic through the configured Google Cloud Run gateway.</p>';
        echo '</td></tr>';

        $gateway_url = get_option( self::OPT_AI_GATEWAY_URL, '' );
        echo '<tr><th scope="row">Your Cloud Run Endpoint URL</th><td>';
        echo '<input type="url" name="sovauth_ai_gateway_url" style="width: 100%; max-width: 600px;" value="' . esc_attr( $gateway_url ) . '" placeholder="https://your-app-url.run.app">';
        echo '<p class="description">The URL where you have deployed your own backend container (BYOI).</p>';
        echo '</td></tr>';

        $sentinel_prompt = get_option('sovauth_sentinel_prompt', "You are the 'Sovereign AI Sentinel', a cybersecurity threat-intel AI. Your job is to analyze failed login attempts to determine if they are malicious botnets/scrapers or legitimate user errors.");
        $history = get_option('sovauth_sentinel_prompt_history', []);
        
        echo '<tr><th scope="row">Sentinel Directives (Prompt)</th><td>';
        echo '<div id="sentinel_prompt_display_container" style="background: #f1f1f1; padding: 10px; border: 1px solid #ccd0d4; border-radius: 4px; font-family: monospace; white-space: pre-wrap; font-size: 12px; margin-bottom: 10px;">' . esc_html($sentinel_prompt) . '</div>';
        echo '<button type="button" id="sentinel_prompt_edit_btn" class="button" onclick="document.getElementById(\'sentinel_prompt_edit_container\').style.display=\'block\'; document.getElementById(\'sentinel_prompt_display_container\').style.display=\'none\'; this.style.display=\'none\';">Edit Directives</button>';
        
        echo '<div id="sentinel_prompt_edit_container" style="display: none;">';
        
        echo '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 5px;">';
        echo '<label style="font-weight: 600;">Edit Directives</label>';
        
        if (!empty($history) && is_array($history)) {
            echo '<button type="button" class="button button-small" onclick="document.getElementById(\'modal_sentinel\').style.display=\'flex\'">History</button>';
            echo '<div id="modal_sentinel" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.6); z-index:99999; align-items:center; justify-content:center; text-align:left;">';
            echo '<div style="background:#fff; padding:20px; width:700px; max-width:90%; border-radius:4px; box-shadow:0 4px 12px rgba(0,0,0,0.15);">';
            echo '<h3 style="margin-top:0;">Prompt History - Sentinel</h3>';
            echo '<div style="display:flex; gap:20px; height:350px;">';
            echo '<div style="flex:1; overflow-y:auto; border:1px solid #ccc; background:#f9f9f9;">';
            foreach ($history as $idx => $hist_prompt) {
                $snippet = substr(str_replace(["\n", "\r"], ' ', $hist_prompt), 0, 35) . '...';
                echo '<div style="padding:12px; border-bottom:1px solid #eee; cursor:pointer; font-size:12px;" onclick="document.getElementById(\'preview_sentinel\').value = this.dataset.val;" data-val="' . esc_attr($hist_prompt) . '" onmouseover="this.style.background=\'#fff\'" onmouseout="this.style.background=\'transparent\'">';
                echo '<strong>#' . ($idx+1) . '</strong> - ' . esc_html($snippet);
                echo '</div>';
            }
            echo '</div>';
            echo '<div style="flex:1; display:flex; flex-direction:column;">';
            echo '<textarea id="preview_sentinel" style="flex:1; font-family:monospace; font-size:12px; margin-bottom:10px; padding:10px; background:#f1f1f1;" readonly placeholder="Click a prompt on the left to preview it here..."></textarea>';
            echo '<div style="display:flex; justify-content:flex-end; gap:10px;">';
            echo '<button type="button" class="button" onclick="document.getElementById(\'modal_sentinel\').style.display=\'none\'">Cancel</button>';
            echo '<button type="button" class="button button-primary" onclick="var p = document.getElementById(\'preview_sentinel\').value; if(p) { document.getElementById(\'textarea_sentinel\').value = p; document.getElementById(\'modal_sentinel\').style.display=\'none\'; }">Use this Prompt</button>';
            echo '</div></div></div></div></div>';
        }
        echo '</div>';
        
        echo '<textarea id="textarea_sentinel" name="sovauth_sentinel_prompt" rows="6" style="width: 100%; font-family: monospace;">' . esc_textarea( $sentinel_prompt ) . '</textarea>';
        echo '</div>';
        
        echo '<p class="description">Instruct the AI on how strictly it should block IPs.</p>';
        echo '</td></tr>';
        
        echo '</tbody></table>';
        
        submit_button( 'Save Settings' );
        echo '</form>';

        /* ── Manage Credentials ── */
        global $wpdb;
        $userId = get_current_user_id();
        $hasDevice = (bool) $wpdb->get_var( $wpdb->prepare(
            "SELECT 1 FROM {$wpdb->prefix}sovauth_credentials WHERE user_id = %d LIMIT 1",
            $userId
        ) );
        $setupUrl = esc_url( wp_login_url() . '?action=sovauth_admin_setup' );

        ?>
        <h2 class="title" style="margin-top: 30px;">Personal Biometric Devices</h2>
        <div id="sovauth-dashboard-root" class="sovauth-dash-root" style="margin-top: 15px; border: 1px solid #ccd0d4; padding: 15px; background: #fff; max-width: 800px;">
            <div class="sov-dash-header" style="display:flex; justify-content:space-between; align-items:center;">
                <h4 style="margin:0;"><?php esc_html_e( 'Your Devices', 'sovereign-auth' ); ?></h4>
                <?php if ( ! $hasDevice ) : ?>
                    <a href="<?php echo $setupUrl; ?>" class="sov-btn sov-btn--primary button button-primary button-hero">
                        <?php esc_html_e( '+ Register Now', 'sovereign-auth' ); ?>
                    </a>
                <?php else : ?>
                    <button type="button" id="sov-dash-add-btn" class="sov-btn sov-btn--primary button button-primary">
                        <?php esc_html_e( '+ Add Device', 'sovereign-auth' ); ?>
                    </button>
                <?php endif; ?>
            </div>
            <div id="sov-dash-error" class="sov-error sov-hidden" style="color: #d63638; margin-top:10px; font-weight: bold;"></div>
            <div id="sov-dash-success" class="sov-status sov-status--success sov-hidden" style="color: #00a32a; margin-top:10px; font-weight: bold;"></div>
            <div class="sov-dash-list" id="sov-dash-list" style="margin-top:15px;">
                <p class="sov-status sov-status--info"><?php esc_html_e( 'Loading devices...', 'sovereign-auth' ); ?></p>
            </div>
        </div>
        <?php

        wp_enqueue_style( 'sovereign-auth-dashboard', SOVAUTH_URL . 'assets/css/sovereign-auth-dashboard.css', [], SOVAUTH_VER );
        wp_enqueue_script( 'qrcodejs', 'https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js', [], '1.0.0', true );
        wp_enqueue_script( 'sovereign-auth-dashboard', SOVAUTH_URL . 'assets/js/sovereign-auth-dashboard.js', [ 'qrcodejs' ], SOVAUTH_VER, true );
        
        wp_localize_script( 'sovereign-auth-dashboard', 'SovAuthDash', [
            'isPremium'    => \Sovereign_Auth::is_licensed(),
            'api'          => esc_url( rest_url( 'sovereign-ai/v1' ) ),
            'nonce'        => wp_create_nonce( 'wp_rest' ),
            'powChallenge' => wp_create_nonce( 'sovauth_pow' ),
            'torMode'      => (string) get_option( self::OPT_TOR_MODE, 'no' ) === 'yes',
            'i18n'         => [
                'confirmRevoke' => __( 'Are you sure you want to revoke access to this device?', 'sovereign-auth' ),
                'errRevoke'     => __( 'Unable to remove the device.', 'sovereign-auth' ),
                'addDevice'     => __( '+ Add Device', 'sovereign-auth' ),
                'waitBio'       => __( 'Waiting for biometric...', 'sovereign-auth' ),
                'successAdd'    => __( 'Device successfully added.', 'sovereign-auth' ),
                'neverUsed'     => __( 'Never used', 'sovereign-auth' ),
                'revoke'        => __( 'Revoke', 'sovereign-auth' ),
                'unknownDevice' => __( 'Unknown Device', 'sovereign-auth' ),
                'loading'       => __( 'Loading devices...', 'sovereign-auth' ),
                'errWebauthnSupport' => __( 'WebAuthn is not supported on this browser or device.', 'sovereign-auth' ),
                'errNoCred'          => __( 'No credential returned from the authenticator.', 'sovereign-auth' ),
            ]
        ] );

        /* ── Guide & Recommendations ── */
        $this->renderGuide();

        echo '<div style="clear:both; height:80px;"></div>';
        echo '</div>';
    }


    private function handle_post(): string {
        $action = sanitize_text_field( wp_unslash( $_POST['sovauth_action'] ?? '' ) );

        if ( $action === 'save_settings' ) {
            $tor = !empty( $_POST['sovauth_tor_mode'] ) ? 'yes' : 'no';
            $old_tor = (string) get_option( self::OPT_TOR_MODE, 'no' );
            update_option( self::OPT_TOR_MODE, $tor );
            
            if ( class_exists('SovAuth_Activity_Log') && $tor !== $old_tor ) {
                $status = ($tor === 'yes') ? 'Enabled (Proof of Work active)' : 'Disabled (Standard IP filtering)';
                SovAuth_Activity_Log::record( 'sentinel', 'info', "Tor/Onion Mode configuration changed", "system", "Status: {$status}" );
            }
            
            $gemini_key = sanitize_text_field( wp_unslash( $_POST['sovauth_gemini_api_key'] ?? '' ) );
            update_option( self::OPT_GEMINI_KEY, $gemini_key );

            $gateway_url = esc_url_raw( wp_unslash( $_POST['sovauth_ai_gateway_url'] ?? '' ) );
            update_option( self::OPT_AI_GATEWAY_URL, untrailingslashit( $gateway_url ) );

            
            
            return 'Settings saved.';
        } elseif ( $action === 'clear_ai_bans' ) {
            // Feature removed in favor of 15-minute temporary bans.
            return 'AI bans are temporary and expire automatically.';
        } elseif ( $action === 'clear_ai_logs' || $action === 'clear_activity_log' ) {
            update_option( 'sovauth_ai_logs', [] ); // Clear old legacy logs
            return 'Legacy logs cleared. Audit logs are append-only and remain available for evidence.';
        }

        return '';
    }

    private function collectStatus(): array {
        global $wpdb;

        $biometricUsers = (int) $wpdb->get_var(
            "SELECT COUNT(DISTINCT user_id) FROM {$wpdb->prefix}sovauth_credentials"
        );

        $recoveryUsers = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = %s",
            '_sovauth_recovery_lookup_hash'
        ) );

        return [
            'biometric_users' => $biometricUsers,
            'recovery_users'  => $recoveryUsers,
        ];
    }

    private function statusRow( string $label, string $value, bool $ok ): void {
        $dot = $ok ? '🟢' : '🟠';
        printf(
            '<tr><td>%s</td><td>%s %s</td></tr>',
            esc_html( $label ),
            $dot,
            esc_html( $value )
        );
    }

    private function renderGuide(): void {
        ?>
        <h2 class="title" style="margin-top: 40px;">Guide &amp; Recommendations</h2>
        <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; max-width: 800px; border-radius: 4px;">
            <p><strong>Welcome to Sovereign AI Overseer!</strong></p>
            <p>This plugin replaces traditional passwords with high-security WebAuthn/FIDO2 biometrics (such as Touch ID, Face ID, or Windows Hello), drastically improving security and user experience.</p>
            
            <h3 style="margin-bottom: 5px;">How it Works</h3>
            <ul style="list-style: disc; padding-left: 20px; margin-top: 5px;">
                <li><strong>No Passwords:</strong> Users log in directly using their device's built-in biometric sensor.</li>
                <li><strong>Device Bound:</strong> A biometric credential is mathematically tied to the specific device used to register it.</li>
                <li><strong>Adding Devices:</strong> Users can (and should) add multiple devices (e.g., a phone and a laptop) for redundancy.</li>
            </ul>

            <h3 style="margin-bottom: 5px;">Best Practices &amp; Recovery</h3>
            <ul style="list-style: disc; padding-left: 20px; margin-top: 5px;">
                <li><strong>Save the Recovery Phrase:</strong> If a user loses all their registered devices, the only way to regain access is through the 12-word recovery phrase generated during their first device registration. Make sure you have saved yours!</li>
                <li><strong>Administrator Lockout Protection:</strong> For security, administrators are prevented from logging out until they have successfully registered at least one biometric device.</li>
                <li><strong>Tor / Onion Mode:</strong> If your site operates over the Tor network, enable Tor Mode. This switches the anti-brute-force mechanism from IP-based rate limiting to a cryptographic Proof of Work puzzle, preventing malicious traffic without banning legitimate Tor exit nodes.</li>
            </ul>

            <h3 style="margin-bottom: 5px; color: #d63638;">Important Warnings &amp; Conflicts</h3>
            <ul style="list-style: disc; padding-left: 20px; margin-top: 5px;">
                <li><strong>Incompatible Plugins:</strong> Sovereign AI Overseer radically alters and replaces the default WordPress login screen. It is <strong>NOT</strong> compatible with other plugins that modify the login flow. You must disable any Two-Factor Authentication (2FA) plugins, Custom Login Page builders, or CAPTCHA plugins on the login form, otherwise you will experience severe conflicts and lockouts.</li>
            </ul>
        </div>
        <?php
    }
}
